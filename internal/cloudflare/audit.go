package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

// SecretKey rend la variable d'équipe Coolify qui porte le secret d'edge de l'app.
func SecretKey(app inventory.App) string { return "EDGE_SECRET_" + app.EnvSuffix() }

// Secret est EDGE_SECRET_<APP> telle que lue dans Coolify. Defaut vaut "" quand
// Value est utilisable, sinon la raison.
type Secret struct {
	Value  string
	Defaut string
}

// NotLive : note d'une app en edge cloudflare pas encore en service.
const NotLive = "règle Cloudflare posée au passage en live: true, pour que le secret ne parte pas vers l'origine actuelle"

const (
	SecretAbsente    = "absente"
	SecretVide       = "vide"
	SecretVerrouille = "illisible (variable verrouillée)"
	SecretIllisible  = "illisible (jeton sans read:sensitive)"
	SecretHorsFormat = "hors format (32 caractères au moins dans [A-Za-z0-9_-])"
)

// EdgeSecret lit EDGE_SECRET_<APP> dans les variables d'équipe.
func EdgeSecret(team map[string]coolify.SharedEnv, app inventory.App) Secret {
	e, ok := team[SecretKey(app)]
	switch {
	case !ok:
		return Secret{Defaut: SecretAbsente}
	case e.IsShownOnce:
		return Secret{Defaut: SecretVerrouille}
	case !e.Value.Set:
		return Secret{Defaut: SecretIllisible}
	case e.Value.Null || strings.TrimSpace(e.Value.Value) == "":
		return Secret{Defaut: SecretVide}
	case !ValidSecret(e.Value.Value):
		return Secret{Defaut: SecretHorsFormat}
	}
	return Secret{Value: e.Value.Value}
}

// Audit compare, pour chaque app de apps en edge cloudflare, la règle
// waf-edge-<app> de chacune de ses edge_zones à l'inventaire et au secret :
// présence, expression, en-tête. all est l'inventaire complet, tous stages :
// une règle qui touche l'en-tête sans être attendue pour une de ses apps est un
// écart. Il ne fait que lire. Un écart est une phrase courte pour le pulse, une
// note un détail pour les logs ; aucun ne cite de secret ni de valeur lue chez
// Cloudflare.
func Audit(ctx context.Context, r Reader, apps, all []inventory.App, team map[string]coolify.SharedEnv) (ecarts, notes []string, err error) {
	expected := Expected(all)
	read := map[string]bool{}
	byZone := map[string][]Want{}
	checkValue := map[string]bool{}
	for _, a := range apps {
		if a.Edge != render.EdgeCloudflare {
			continue
		}
		s := EdgeSecret(team, a)
		if s.Defaut != "" {
			ecarts = append(ecarts, fmt.Sprintf("%s : %s %s, en-tête des règles Cloudflare non vérifié", a.Name, SecretKey(a), s.Defaut))
		}
		checkValue[a.Name] = s.Defaut == ""
		if len(a.EdgeZones) == 0 {
			notes = append(notes, fmt.Sprintf("%s : règle Cloudflare hors de waf-ops, edge_zones absent de l'inventaire", a.Name))
			continue
		}
		if !a.Live {
			notes = append(notes, fmt.Sprintf("%s : %s", a.Name, NotLive))
		}
		for _, w := range Wants(a, s.Value) {
			read[w.Zone] = true
			if a.Live {
				byZone[w.Zone] = append(byZone[w.Zone], w)
			}
		}
	}
	zones := make([]string, 0, len(read))
	for z := range read {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	for _, z := range zones {
		st, err := ReadZone(ctx, r, z)
		if errors.Is(err, ErrZoneAbsente) || errors.Is(err, ErrZoneInactive) {
			etat := "absente ou hors du jeton Cloudflare"
			if errors.Is(err, ErrZoneInactive) {
				etat = "non active chez Cloudflare"
			}
			for _, w := range byZone[z] {
				ecarts = append(ecarts, fmt.Sprintf("%s : zone %s %s", w.App, z, etat))
			}
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("audit Cloudflare, zone %s : %w", z, err)
		}
		for _, w := range byZone[z] {
			cur, err := st.Managed(w.Ref())
			if err != nil {
				ecarts = append(ecarts, fmt.Sprintf("%s : %v", w.App, err))
				continue
			}
			if cur == nil {
				ecarts = append(ecarts, fmt.Sprintf("%s : règle %s absente de la zone %s", w.App, w.Ref(), z))
				continue
			}
			d := Diff(*cur, w, checkValue[w.App])
			for _, e := range d {
				ecarts = append(ecarts, fmt.Sprintf("%s : règle %s de la zone %s : %s", w.App, w.Ref(), z, e))
			}
			if len(d) == 0 {
				notes = append(notes, fmt.Sprintf("%s : règle %s de la zone %s conforme", w.App, w.Ref(), z))
			}
		}
		for _, id := range st.Foreign(expected[z]) {
			ecarts = append(ecarts, fmt.Sprintf("zone %s : règle %s sur %s hors des règles attendues, à retirer", z, id, Header))
		}
	}
	return ecarts, notes, nil
}
