package ops

import (
	"context"
	"fmt"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

// Audit est le passage horaire (section 3.5 du design). Pour chaque app live
// et Scalingo des stages traités : Activity de l'app depuis le passage
// précédent, puis, si l'app est verrouillée, sonde de son origine. Pour chaque
// app live des stages traités : DNS de ses hosts et certificat servi par
// chaque VM de son stage. Enfin, plan de provision de chaque VM.
//
// curseurs donne, par « région/app » Scalingo, la date du dernier événement
// lu. Audit rend les curseurs à garder, même en erreur : un curseur n'avance
// que pour une app lue jusqu'au bout.
//
// Les écarts de l'inventaire et des UPSTREAM, que le contrôle des 5 minutes
// porte déjà, sont ici des notes : l'audit les garderait une heure après leur
// correction.
func Audit(ctx context.Context, cfg Config, d Deps, curseurs map[string]time.Time) (Rapport, map[string]time.Time, error) {
	var r Rapport
	now := d.Now()
	var pre Rapport
	inv, err := loadInventory(ctx, cfg, now, &pre)
	r.Notes = append(append(r.Notes, pre.Notes...), pre.Ecarts...)
	r.Cache = pre.Cache
	if err != nil {
		return r, curseurs, err
	}
	team, err := teamMap(ctx, d.Coolify)
	if err != nil {
		return r, curseurs, err
	}
	next := map[string]time.Time{}
	// Une cible illisible ce passage cache peut-être une app déjà suivie : ses
	// curseurs restent, quel que soit leur âge.
	garder := false
	apps := perimetre(inv, cfg, &r)
	for i, a := range apps {
		if err := coupe(ctx, i, len(apps)); err != nil {
			return r, fusion(next, curseurs), err
		}
		nE, nN := len(r.Ecarts), len(r.Notes)
		r.Apps++
		var c Rapport
		app, region, ok := cible(a, team, d.Scalingo, &c)
		r.Notes = append(r.Notes, c.Ecarts...)
		if !ok {
			garder = true
			continue
		}
		key := region + "/" + app
		avant, suivi := curseurs[key]
		auditApp(ctx, d, a, app, region, team, avant, suivi, now, next, &r)
		if ctx.Err() != nil {
			// Les écarts d'une app coupée en cours viennent du délai, pas d'elle.
			r.Ecarts, r.Notes = r.Ecarts[:nE], r.Notes[:nN]
			r.Apps--
			delete(next, key)
			return r, fusion(next, curseurs), coupe(ctx, i, len(apps))
		}
	}
	ips := map[string][]string{}
	for _, v := range inv.VMs {
		ips[v.Stage] = append(ips[v.Stage], v.IP)
	}
	for _, a := range inv.Apps {
		if !cfg.Stages[a.Stage] || !a.Live {
			continue
		}
		var x Rapport
		if d.DNS != nil {
			ecarts, notes := ControleDNS(ctx, d.DNS, a, ips[a.Stage])
			x.ajout(a.Name, ecarts, notes)
		}
		if d.Certs != nil {
			ecarts, notes := ControleCertificats(ctx, d.Certs, a, ips[a.Stage], now)
			x.ajout(a.Name, ecarts, notes)
		}
		if ctx.Err() != nil {
			return r, fusion(next, curseurs), fmt.Errorf("audit coupé pendant les DNS et certificats : %w", ctx.Err())
		}
		r.Ecarts = append(r.Ecarts, x.Ecarts...)
		r.Notes = append(r.Notes, x.Notes...)
	}
	switch {
	case cfg.Provision == nil:
		r.Notes = append(r.Notes, "WAF_OPS_PROVISION absente : plan de provision non contrôlé")
	case d.Provision != nil:
		ecarts, notes := ControlePlan(ctx, d.Provision, *cfg.Provision, cfg.CoolifyURL, cfg.CoolifyToken, inv, cfg.Stages)
		if ctx.Err() != nil {
			return r, fusion(next, curseurs), fmt.Errorf("audit coupé pendant le plan de provision : %w", ctx.Err())
		}
		r.Ecarts = append(r.Ecarts, ecarts...)
		r.Notes = append(r.Notes, notes...)
	}
	if garder {
		next = fusion(next, curseurs)
	}
	return r, next, nil
}

func coupe(ctx context.Context, i, n int) error {
	if ctx.Err() != nil {
		return fmt.Errorf("audit coupé après %d app(s) sur %d : %w", i, n, ctx.Err())
	}
	return nil
}

// fusion : les curseurs lus ce passage, et les autres tels qu'ils étaient.
func fusion(next, avant map[string]time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for k, v := range avant {
		out[k] = v
	}
	for k, v := range next {
		out[k] = v
	}
	return out
}

func auditApp(ctx context.Context, d Deps, a inventory.App, app, region string, team map[string]coolify.SharedEnv, avant time.Time, suivi bool, now time.Time, next map[string]time.Time, r *Rapport) {
	key := region + "/" + app
	where := app + " (" + region + ")"
	depuis := avant
	if !suivi {
		depuis = now.Add(-activiteSansCurseur)
		r.Notes = append(r.Notes, fmt.Sprintf("%s : Activity de %s sans curseur, relue depuis %s", a.Name, where, depuis.UTC().Format(time.RFC3339)))
	}
	evs, tronque, err := d.Scalingo.Events(ctx, region, app, depuis)
	if err != nil {
		if suivi {
			next[key] = avant
		}
		r.ecart(a.Name, "Activity de %s : %s", where, fgpProblem(err))
		r.Notes = append(r.Notes, fmt.Sprintf("%s : détail : %v", a.Name, err))
	} else {
		next[key] = depuis
		autres := 0
		for i := len(evs) - 1; i >= 0; i-- {
			e := evs[i]
			if e.A.After(next[key]) {
				next[key] = e.A
			}
			ecart, msg := classer(e)
			switch {
			case ecart:
				r.ecart(a.Name, "%s : %s", where, msg)
			case msg != "":
				r.Notes = append(r.Notes, fmt.Sprintf("%s : %s : %s", a.Name, where, msg))
			default:
				autres++
			}
		}
		if autres > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("%s : %d autre(s) événement(s) sur %s", a.Name, autres, where))
		}
		// Relire la même fenêtre au passage suivant retomberait sur les mêmes
		// pages : le curseur avance, et l'écart borne la fenêtre à relire à la
		// main dans l'Activity de l'app.
		if tronque && len(evs) > 0 {
			r.ecart(a.Name, "Activity de %s : plus de %d événements, fenêtre du %s au %s non lue, à relire dans le dashboard Scalingo",
				where, len(evs), depuis.UTC().Format(time.RFC3339), evs[len(evs)-1].A.UTC().Format(time.RFC3339))
		}
	}
	if !verrouillee(a, team) {
		r.Notes = append(r.Notes, a.Name+" : sans LOCK_"+a.EnvSuffix()+", origine non sondée")
		return
	}
	var hosts []string
	// En upstream, le host du visiteur n'est pas rattaché à l'app Scalingo :
	// le routeur répondrait 404, et rien ne passe par ce chemin.
	if a.HostHeader == "visitor" {
		hosts = a.Hosts
	}
	ecarts, notes := d.Origine.Sonder(ctx, app, region, hosts)
	r.ajout(a.Name, ecarts, notes)
}
