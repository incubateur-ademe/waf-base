package ops

import (
	"context"
	"fmt"
	"time"
)

// Audit est le passage horaire (section 3.5 du design). Pour chaque app live
// et Scalingo des stages traités : Activity de l'app depuis le passage
// précédent, puis, si l'app est verrouillée, sonde de son origine. Pour chaque
// app live des stages traités : DNS de ses hosts et certificat servi par
// chaque VM de son stage. Enfin, plan de provision de chaque VM. curseurs
// donne, par « région/app » Scalingo, la date du dernier événement lu ; Audit
// rend les curseurs à garder, avancés pour les seules apps lues sans erreur.
func Audit(ctx context.Context, cfg Config, d Deps, curseurs map[string]time.Time) (Rapport, map[string]time.Time, error) {
	var r Rapport
	now := d.Now()
	inv, err := loadInventory(ctx, cfg, now, &r)
	if err != nil {
		return r, curseurs, err
	}
	team, err := teamMap(ctx, d.Coolify)
	if err != nil {
		return r, curseurs, err
	}
	next := map[string]time.Time{}
	for _, a := range perimetre(inv, cfg, &r) {
		r.Apps++
		app, region, ok := cible(a, team, d.Scalingo, &r)
		if !ok {
			continue
		}
		key := region + "/" + app
		where := app + " (" + region + ")"
		depuis, vu := curseurs[key]
		if !vu {
			depuis = now.Add(-activiteSansCurseur)
			r.Notes = append(r.Notes, fmt.Sprintf("%s : Activity de %s sans curseur, relue depuis %s", a.Name, where, depuis.UTC().Format(time.RFC3339)))
		}
		next[key] = depuis
		evs, tronque, err := d.Scalingo.Events(ctx, region, app, depuis)
		if err != nil {
			r.ecart(a.Name, "Activity de %s : %s", where, fgpProblem(err))
			r.Notes = append(r.Notes, fmt.Sprintf("%s : détail : %v", a.Name, err))
		} else {
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
			if tronque {
				r.ecart(a.Name, "Activity de %s : plus de %d événements depuis %s, lecture tronquée", where, maxEventPages*100, depuis.UTC().Format(time.RFC3339))
			}
		}
		if !verrouillee(a, team) {
			r.Notes = append(r.Notes, a.Name+" : sans LOCK_"+a.EnvSuffix()+", origine non sondée")
			continue
		}
		var hosts []string
		// En upstream, le host du visiteur n'est pas rattaché à l'app Scalingo :
		// le routeur répondrait 404, et rien ne passe par ce chemin.
		if a.HostHeader == "visitor" {
			hosts = a.Hosts
		}
		ecarts, notes := d.Origine.Sonder(ctx, app, region, hosts)
		for _, e := range ecarts {
			r.ecart(a.Name, "%s", e)
		}
		for _, n := range notes {
			r.Notes = append(r.Notes, a.Name+" : "+n)
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
		if d.DNS != nil {
			ecarts, notes := ControleDNS(ctx, d.DNS, a, ips[a.Stage])
			r.ajout(a.Name, ecarts, notes)
		}
		if d.Certs != nil {
			ecarts, notes := ControleCertificats(ctx, d.Certs, a, ips[a.Stage], now)
			r.ajout(a.Name, ecarts, notes)
		}
	}
	switch {
	case cfg.Provision == nil:
		r.Notes = append(r.Notes, "WAF_OPS_PROVISION absente : plan de provision non contrôlé")
	case d.Provision != nil:
		ecarts, notes := ControlePlan(ctx, d.Provision, *cfg.Provision, cfg.CoolifyURL, cfg.CoolifyToken, inv, cfg.Stages)
		r.Ecarts = append(r.Ecarts, ecarts...)
		r.Notes = append(r.Notes, notes...)
	}
	// Une app dont UPSTREAM n'a pas été lue ce passage garde son curseur. Un
	// curseur non revu pendant curseurMaxAge est celui d'une app sortie du
	// périmètre : il est oublié.
	for k, v := range curseurs {
		if _, ok := next[k]; !ok && now.Sub(v) < curseurMaxAge {
			next[k] = v
		}
	}
	return r, next, nil
}

const curseurMaxAge = 30 * 24 * time.Hour
