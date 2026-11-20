package ops

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/policy"
)

// Au-delà, l'inventaire en cache ne vaut plus pour décider ce qui est attendu.
const inventoryMaxAge = 24 * time.Hour

const inventoryCache = "inventaire.yaml"

type TeamEnvs interface {
	ListTeamEnvs(ctx context.Context) ([]coolify.SharedEnv, error)
}

type Scalingo interface {
	HasRegion(region string) bool
	FirewallRules(ctx context.Context, region, app string) ([]FirewallRule, error)
	Domains(ctx context.Context, region, app string) ([]Domain, error)
}

type Deps struct {
	Coolify  TeamEnvs
	Scalingo Scalingo
	Now      func() time.Time
}

// Rapport : écarts à corriger, et notes qui n'en sont pas. Cache dit que
// l'inventaire vient du cache, faute d'une réponse valide.
type Rapport struct {
	Ecarts []string
	Notes  []string
	Apps   int
	Cache  bool
}

func (r *Rapport) ecart(app, format string, a ...any) {
	r.Ecarts = append(r.Ecarts, app+" : "+fmt.Sprintf(format, a...))
}

// loadInventory lit l'inventaire et garde la dernière version valide dans le
// dossier d'état. Sans réponse valide, le cache sert pendant 24 h : au-delà, ou
// sans cache, le passage échoue.
func loadInventory(ctx context.Context, cfg Config, now time.Time, r *Rapport) (inventory.Inventory, error) {
	pol, err := policy.Load(filepath.Join(cfg.Etc, "policy"))
	if err != nil {
		return inventory.Inventory{}, err
	}
	platforms := map[string]bool{}
	for k := range pol.Origines {
		platforms[k] = true
	}
	cache := filepath.Join(cfg.State, inventoryCache)
	b, err := inventory.Read(ctx, cfg.Inventaire)
	if err == nil {
		inv, perr := inventory.Load(b, platforms)
		if perr == nil {
			if werr := writeAtomic(cache, b, 0o600); werr != nil {
				r.Notes = append(r.Notes, fmt.Sprintf("cache d'inventaire non écrit : %v", werr))
			}
			return inv, nil
		}
		err = perr
	}
	r.Notes = append(r.Notes, fmt.Sprintf("inventaire non relu, cache utilisé : %v", err))
	r.Cache = true
	st, serr := os.Stat(cache)
	if serr != nil {
		return inventory.Inventory{}, fmt.Errorf("inventaire illisible et sans cache : %v", err)
	}
	cb, cerr := os.ReadFile(cache)
	if cerr != nil {
		return inventory.Inventory{}, fmt.Errorf("cache d'inventaire illisible : %v", cerr)
	}
	inv, perr := inventory.Load(cb, platforms)
	if perr != nil {
		return inventory.Inventory{}, fmt.Errorf("cache d'inventaire invalide : %v", perr)
	}
	if now.Sub(st.ModTime()) > inventoryMaxAge {
		r.Ecarts = append(r.Ecarts, "inventaire non rafraîchi depuis 24 h")
	}
	return inv, nil
}

// writeAtomic écrit dans un fichier temporaire du même dossier, puis renomme :
// un passage interrompu ne laisse pas de fichier à moitié écrit.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var reUpstreamHost = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,62})\.(osc-[a-z0-9-]{1,32})\.scalingo\.io$`)

// scalingoTarget lit l'app et la région Scalingo dans UPSTREAM, de la forme
// https://<app>.<région>.scalingo.io : l'inventaire public ne situe pas l'origine.
func scalingoTarget(upstream string) (app, region string, err error) {
	u, err := url.Parse(strings.TrimSpace(upstream))
	// :443 explicite reste admis : le rendu du WAF l'accepte.
	if err != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", "", fmt.Errorf("https://<app>.<région>.scalingo.io attendu")
	}
	m := reUpstreamHost.FindStringSubmatch(strings.ToLower(u.Hostname()))
	if m == nil {
		return "", "", fmt.Errorf("hôte hors de *.<région>.scalingo.io")
	}
	return m[1], m[2], nil
}

type sharedValue struct {
	exists, readable bool
	value            string
}

func teamValue(m map[string]coolify.SharedEnv, key string) sharedValue {
	e, ok := m[key]
	if !ok {
		return sharedValue{}
	}
	if e.IsShownOnce || !e.Value.Set {
		return sharedValue{exists: true}
	}
	v := ""
	if !e.Value.Null {
		v = e.Value.Value
	}
	return sharedValue{exists: true, readable: true, value: v}
}

func fgpProblem(err error) string {
	var fe *FGPError
	switch {
	case errors.Is(err, ErrFGPInjoignable):
		return "FGP injoignable"
	case errors.As(err, &fe):
		return fe.Error()
	}
	return err.Error()
}

// Controle est le passage des 5 minutes (section 3.5 du design) : pour chaque
// app live des stages traités, sur Scalingo, règles du firewall égales aux IP
// des VM de son stage quand l'app est verrouillée, et chaque host rattaché à
// l'app quand le WAF lui passe le Host du visiteur. En upstream, le WAF envoie
// le nom Scalingo de l'app : un host rattaché ailleurs ne capte rien.
func Controle(ctx context.Context, cfg Config, d Deps) (Rapport, error) {
	var r Rapport
	inv, err := loadInventory(ctx, cfg, d.Now(), &r)
	if err != nil {
		return r, err
	}
	envs, err := d.Coolify.ListTeamEnvs(ctx)
	if err != nil {
		return r, fmt.Errorf("variables d'équipe Coolify : %w", err)
	}
	team := map[string]coolify.SharedEnv{}
	for _, e := range envs {
		team[e.Key] = e
	}
	ips := map[string][]string{}
	for _, v := range inv.VMs {
		ips[v.Stage] = append(ips[v.Stage], v.IP+"/32")
	}
	for _, a := range inv.Apps {
		if !cfg.Stages[a.Stage] {
			continue
		}
		if !a.Live {
			r.Notes = append(r.Notes, a.Name+" : pas en service, hors contrôle")
			continue
		}
		if a.Platform != "scalingo" {
			r.Notes = append(r.Notes, fmt.Sprintf("%s : plateforme %s, hors contrôle FGP", a.Name, a.Platform))
			continue
		}
		r.Apps++
		controleApp(ctx, d, a, team, ips[a.Stage], &r)
	}
	return r, nil
}

func controleApp(ctx context.Context, d Deps, a inventory.App, team map[string]coolify.SharedEnv, want []string, r *Rapport) {
	key := "UPSTREAM_" + a.EnvSuffix()
	up := teamValue(team, key)
	switch {
	case !up.exists:
		r.ecart(a.Name, "%s absente des variables d'équipe", key)
		return
	case !up.readable:
		r.ecart(a.Name, "%s illisible (jeton sans read:sensitive ou variable verrouillée)", key)
		return
	}
	app, region, err := scalingoTarget(up.value)
	if err != nil {
		r.ecart(a.Name, "%s : %v", key, err)
		return
	}
	if !d.Scalingo.HasRegion(region) {
		r.ecart(a.Name, "aucun blob FGP pour la région %s", region)
		return
	}
	where := app + " (" + region + ")"
	// Une valeur illisible compte comme posée : le contrôle des règles se fait.
	lock := teamValue(team, "LOCK_"+a.EnvSuffix())
	if lock.exists && (!lock.readable || strings.TrimSpace(lock.value) != "") {
		rules, err := d.Scalingo.FirewallRules(ctx, region, app)
		if err != nil {
			r.ecart(a.Name, "règles du firewall de %s : %s", where, fgpProblem(err))
			r.Notes = append(r.Notes, fmt.Sprintf("%s : détail : %v", a.Name, err))
		} else if missing, extra := diffRules(rules, want); len(missing)+len(extra) > 0 {
			var parts []string
			if len(missing) > 0 {
				parts = append(parts, "manquantes "+strings.Join(missing, " "))
			}
			if len(extra) > 0 {
				parts = append(parts, "en trop "+strings.Join(extra, " "))
			}
			r.ecart(a.Name, "règles du firewall de %s : %s", where, strings.Join(parts, ", "))
		}
	} else {
		r.Notes = append(r.Notes, a.Name+" : sans LOCK_"+a.EnvSuffix()+", règles du firewall non contrôlées")
	}
	if a.HostHeader != "visitor" {
		return
	}
	doms, err := d.Scalingo.Domains(ctx, region, app)
	if err != nil {
		r.ecart(a.Name, "domaines de %s : %s", where, fgpProblem(err))
		r.Notes = append(r.Notes, fmt.Sprintf("%s : détail : %v", a.Name, err))
		return
	}
	have := map[string]bool{}
	for _, dm := range doms {
		have[strings.TrimSuffix(strings.ToLower(dm.Name), ".")] = true
	}
	for _, h := range a.Hosts {
		if !have[h] {
			r.ecart(a.Name, "host %s non rattaché à %s", h, where)
		}
	}
}

// diffRules compare les CIDR en place aux IP des VM du stage. Une règle en
// double compte une fois : seul l'ensemble des IP autorisées importe.
func diffRules(rules []FirewallRule, want []string) (missing, extra []string) {
	have := map[string]bool{}
	for _, r := range rules {
		have[strings.TrimSpace(r.CIDR)] = true
	}
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
		if !have[w] {
			missing = append(missing, w)
		}
	}
	for h := range have {
		if !wanted[h] {
			extra = append(extra, h)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
