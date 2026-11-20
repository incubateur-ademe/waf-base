package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/certs"
	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/ghaudit"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	TacheCertificats = "certificats"
	TacheGitHub      = "github"
	TacheCloudflare  = "cloudflare"

	PeriodeCertificats = 24 * time.Hour
	delaiCertificats   = 10 * time.Minute
	delaiGitHub        = 4 * time.Minute
	delaiCloudflare    = 2 * time.Minute
)

// Remplacés par les tests : le vrai passage des certificats écrit sur Scalingo.
var (
	certsQuotidien = certs.Quotidien
	ghAudit        = ghaudit.Audit
	cfAudit        = cloudflare.Audit
)

// Optionnelles : config des tâches des lots 4 à 6. Une tâche sans aucune de
// ses variables n'est pas lancée. Une config incomplète ou invalide est gardée
// dans Erreurs : la tâche part en échec à chaque passage, le pulse le dit, et
// les autres contrôles continuent.
type Optionnelles struct {
	Certs           *certs.Config
	GitHub          *ghaudit.Config
	CloudflareToken string
	Erreurs         map[string]string
}

func chargerOptionnelles(getenv func(string) string, fgp FGP, state string) Optionnelles {
	o := Optionnelles{Erreurs: map[string]string{}}
	present := func(keys ...string) bool {
		for _, k := range keys {
			if strings.TrimSpace(getenv(k)) != "" {
				return true
			}
		}
		return false
	}
	if present(certs.EnvCleSSH, certs.EnvKnownHosts, certs.EnvVMs, certs.EnvFGPEcriture) {
		c, err := certs.LoadConfig(getenv, fgp.URL, fgp.Key, state)
		if err != nil {
			o.Erreurs[TacheCertificats] = err.Error()
		} else {
			o.Certs = &c
		}
	}
	if present(ghaudit.EnvAppID, ghaudit.EnvAppKey) {
		c, err := ghaudit.FromEnv(getenv)
		if err != nil {
			o.Erreurs[TacheGitHub] = err.Error()
		} else {
			o.GitHub = &c
		}
	}
	if t := strings.TrimSpace(getenv(cloudflare.TokenEnv)); t != "" {
		if _, err := cloudflare.New(t); err != nil {
			o.Erreurs[TacheCloudflare] = err.Error()
		} else {
			o.CloudflareToken = t
		}
	}
	return o
}

// Taches rend les tâches de la boucle : l'audit horaire, puis celles des lots
// 4 à 6 qui ont une config, valide ou non. absentes nomme les autres.
func Taches(cfg Config, d Deps) (ts []Tache, absentes []string) {
	ts = append(ts, TacheAudit(cfg, d))
	for _, t := range []struct {
		nom     string
		periode time.Duration
		delai   time.Duration
		ok      bool
		run     func(context.Context) (Rapport, error)
	}{
		{TacheCertificats, PeriodeCertificats, delaiCertificats, cfg.Opt.Certs != nil, func(ctx context.Context) (Rapport, error) { return CopieCertificats(ctx, cfg, d) }},
		{TacheGitHub, PeriodeAudit, delaiGitHub, cfg.Opt.GitHub != nil, func(ctx context.Context) (Rapport, error) { return GitHub(ctx, cfg, d) }},
		{TacheCloudflare, PeriodeAudit, delaiCloudflare, cfg.Opt.CloudflareToken != "" && d.Cloudflare != nil, func(ctx context.Context) (Rapport, error) { return Cloudflare(ctx, cfg, d) }},
	} {
		run := t.run
		if msg, ko := cfg.Opt.Erreurs[t.nom]; ko {
			run = func(context.Context) (Rapport, error) { return Rapport{}, fmt.Errorf("configuration : %s", msg) }
		} else if !t.ok {
			absentes = append(absentes, t.nom)
			continue
		}
		ts = append(ts, Tache{Nom: t.nom, Periode: t.periode, Delai: t.delai, Run: func(ctx context.Context, c map[string]time.Time) (Rapport, map[string]time.Time, error) {
			r, err := run(ctx)
			return r, nil, err
		}})
	}
	sort.Strings(absentes)
	return ts, absentes
}

// liveDesStages : les apps en service des stages traités, toutes plateformes.
func liveDesStages(inv inventory.Inventory, cfg Config) []inventory.App {
	var out []inventory.App
	for _, a := range inv.Apps {
		if cfg.Stages[a.Stage] && a.Live {
			out = append(out, a)
		}
	}
	return out
}

// CopieCertificats est le passage quotidien du lot 4 (section 3.7 du design) :
// copie d'acme.json de chaque VM de l'inventaire, puis poussée du certificat
// de chaque host sur le domaine Scalingo des apps live et Scalingo des stages
// traités. Il écrit sur Scalingo par les blobs d'écriture.
func CopieCertificats(ctx context.Context, cfg Config, d Deps) (Rapport, error) {
	var r Rapport
	if cfg.Opt.Certs == nil {
		return r, fmt.Errorf("copie des certificats non configurée")
	}
	if d.Domaines == nil {
		return r, fmt.Errorf("lecteur de domaines absent")
	}
	inv, team, err := preambule(ctx, cfg, d, &r)
	if err != nil {
		return r, err
	}
	vms := make([]certs.VM, 0, len(inv.VMs))
	for _, v := range inv.VMs {
		vms = append(vms, certs.VM{Name: v.Name, Stage: v.Stage})
	}
	var apps []certs.App
	for _, a := range perimetre(inv, cfg, &r) {
		r.Apps++
		var c Rapport
		app, region, ok := cible(a, team, d.Scalingo, &c)
		r.Notes = append(r.Notes, c.Ecarts...)
		if !ok {
			continue
		}
		apps = append(apps, certs.App{Name: a.Name, Stage: a.Stage, Hosts: a.Hosts, Scalingo: app, Region: region})
	}
	ecarts, notes, err := certsQuotidien(ctx, *cfg.Opt.Certs, vms, apps, certs.Deps{Lecteur: d.Domaines, Now: d.Now})
	r.Ecarts = append(r.Ecarts, ecarts...)
	r.Notes = append(r.Notes, notes...)
	return r, err
}

// GitHub est l'audit horaire du lot 6 sur les repos des apps live des stages
// traités. Il ne fait que lire.
func GitHub(ctx context.Context, cfg Config, d Deps) (Rapport, error) {
	var r Rapport
	if cfg.Opt.GitHub == nil {
		return r, fmt.Errorf("audit GitHub non configuré")
	}
	var pre Rapport
	inv, err := loadInventory(ctx, cfg, d.Now(), &pre)
	r.Notes = append(append(r.Notes, pre.Notes...), pre.Ecarts...)
	if err != nil {
		return r, err
	}
	apps := liveDesStages(inv, cfg)
	r.Apps = len(apps)
	ecarts, notes, err := ghAudit(ctx, *cfg.Opt.GitHub, apps)
	r.Ecarts = append(r.Ecarts, ecarts...)
	r.Notes = append(r.Notes, notes...)
	return r, err
}

// Cloudflare est l'audit horaire du lot 5 : règle waf-edge-<app> des apps
// live des stages traités, contre tout l'inventaire. Il ne fait que lire.
func Cloudflare(ctx context.Context, cfg Config, d Deps) (Rapport, error) {
	var r Rapport
	if d.Cloudflare == nil {
		return r, fmt.Errorf("audit Cloudflare non configuré")
	}
	inv, team, err := preambule(ctx, cfg, d, &r)
	if err != nil {
		return r, err
	}
	apps := liveDesStages(inv, cfg)
	r.Apps = len(apps)
	ecarts, notes, err := cfAudit(ctx, d.Cloudflare, apps, inv.Apps, team)
	r.Ecarts = append(r.Ecarts, ecarts...)
	r.Notes = append(r.Notes, notes...)
	return r, err
}
