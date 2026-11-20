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
	// Un passage avec des écarts (VM ou FGP sans réponse) est relancé sans
	// attendre un jour : il ne repousse pas un certificat déjà posé.
	relanceCertificats = time.Hour
	delaiCertificats   = 5 * time.Minute
	// EnvCertsPoussee doit valoir « oui » pour que la boucle pousse les
	// certificats sur Scalingo ; sinon le passage est à blanc.
	EnvCertsPoussee = "WAF_OPS_CERTS_POUSSEE"
	delaiGitHub     = 4 * time.Minute
	delaiCloudflare = 2 * time.Minute
)

// Remplacés par les tests : le vrai passage des certificats écrit sur Scalingo.
var (
	certsQuotidien = certs.Quotidien
	ghAudit        = ghaudit.Audit
	cfAudit        = cloudflare.Audit
)

// Optionnelles : config des tâches des lots 4 à 6. Une tâche sans aucune de
// ses variables n'est pas lancée. Une config incomplète ou invalide est gardée
// dans Erreurs : la tâche n'est pas lancée, chaque pulse le dit, et les autres
// contrôles continuent.
type Optionnelles struct {
	Certs           *certs.Config
	CertsPoussee    bool
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
	o.CertsPoussee = strings.TrimSpace(getenv(EnvCertsPoussee)) == "oui"
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
// 4 à 6 qui ont une config valide. absentes nomme celles qui n'ont aucune de
// leurs variables ; une config invalide est dans cfg.Opt.Erreurs, que chaque
// pulse reprend.
func Taches(cfg Config, d Deps) (ts []Tache, absentes []string) {
	ts = append(ts, TacheAudit(cfg, d))
	for _, t := range []struct {
		nom     string
		periode time.Duration
		relance time.Duration
		delai   time.Duration
		ok      bool
		run     func(context.Context) (Rapport, error)
	}{
		{TacheCertificats, PeriodeCertificats, relanceCertificats, delaiCertificats, cfg.Opt.Certs != nil, func(ctx context.Context) (Rapport, error) {
			return CopieCertificats(ctx, cfg, d, !cfg.Opt.CertsPoussee)
		}},
		{TacheGitHub, PeriodeAudit, 0, delaiGitHub, cfg.Opt.GitHub != nil, func(ctx context.Context) (Rapport, error) { return GitHub(ctx, cfg, d) }},
		{TacheCloudflare, PeriodeAudit, 0, delaiCloudflare, cfg.Opt.CloudflareToken != "" && d.Cloudflare != nil, func(ctx context.Context) (Rapport, error) { return Cloudflare(ctx, cfg, d) }},
	} {
		if _, ko := cfg.Opt.Erreurs[t.nom]; ko {
			continue
		}
		if !t.ok {
			absentes = append(absentes, t.nom)
			continue
		}
		run := t.run
		ts = append(ts, Tache{Nom: t.nom, Periode: t.periode, RelanceSurEcart: t.relance, Delai: t.delai, Run: func(ctx context.Context, c map[string]time.Time) (Rapport, map[string]time.Time, error) {
			r, err := run(ctx)
			// Un package qui range une coupure en écart rend nil : la tâche
			// coupée est en échec, relancée à 15 minutes.
			if err == nil && ctx.Err() != nil {
				err = ctx.Err()
			}
			return r, nil, err
		}})
	}
	sort.Strings(absentes)
	return ts, absentes
}

// erreursConfig : les tâches à la config invalide, une raison chacune, triées.
func erreursConfig(o Optionnelles) []string {
	noms := make([]string, 0, len(o.Erreurs))
	for nom := range o.Erreurs {
		noms = append(noms, nom)
	}
	sort.Strings(noms)
	out := make([]string, 0, len(noms))
	for _, nom := range noms {
		out = append(out, nom+" : configuration : "+o.Erreurs[nom])
	}
	return out
}

// liveDesStages : les apps en service des stages traités, toutes plateformes.
func liveDesStages(inv inventory.Inventory, cfg Config) []inventory.App {
	var out []inventory.App
	for _, a := range appsDesStages(inv, cfg) {
		if a.Live {
			out = append(out, a)
		}
	}
	return out
}

// appsDesStages : toutes les apps des stages traités, en service ou non.
func appsDesStages(inv inventory.Inventory, cfg Config) []inventory.App {
	var out []inventory.App
	for _, a := range inv.Apps {
		if cfg.Stages[a.Stage] {
			out = append(out, a)
		}
	}
	return out
}

// CopieCertificats est le passage quotidien du lot 4 (section 3.7 du design) :
// copie d'acme.json de chaque VM de l'inventaire, puis poussée du certificat
// de chaque host sur le domaine Scalingo des apps live et Scalingo des stages
// traités, par les blobs d'écriture. À blanc, rien n'est poussé : chaque
// poussée prévue sort en note.
func CopieCertificats(ctx context.Context, cfg Config, d Deps, aBlanc bool) (Rapport, error) {
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
	ecarts, notes, err := certsQuotidien(ctx, *cfg.Opt.Certs, vms, apps, certs.Deps{Lecteur: d.Domaines, Now: d.Now, ABlanc: aBlanc})
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
// des stages traités, contre tout l'inventaire. Les apps pas encore en
// service y sont, pour qu'une règle posée trop tôt, qui enverrait le secret à
// l'origine actuelle, sorte en écart. Il ne fait que lire.
func Cloudflare(ctx context.Context, cfg Config, d Deps) (Rapport, error) {
	var r Rapport
	if d.Cloudflare == nil {
		return r, fmt.Errorf("audit Cloudflare non configuré")
	}
	inv, team, err := preambule(ctx, cfg, d, &r)
	if err != nil {
		return r, err
	}
	apps := appsDesStages(inv, cfg)
	r.Apps = len(apps)
	ecarts, notes, err := cfAudit(ctx, d.Cloudflare, apps, inv.Apps, team)
	r.Ecarts = append(r.Ecarts, ecarts...)
	r.Notes = append(r.Notes, notes...)
	return r, err
}
