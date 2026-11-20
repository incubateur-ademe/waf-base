package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	// Pages d'Activity lues au plus par app et par audit, de 100 événements.
	maxEventPages = 20
	// Sans curseur (premier audit, état perdu), l'audit relit ce passé.
	activiteSansCurseur = 2 * time.Hour
	maxDetail           = 120
	forbiddenPage       = "SCALINGO_FORBIDDEN_PAGE_URL"
)

// Evenement ne garde d'un événement Scalingo que son type, sa date et un détail
// sûr : CIDR et libellé d'une règle, hostname d'un domaine, noms des variables.
// La valeur d'une variable n'est jamais lue.
type Evenement struct {
	ID     string
	Type   string
	A      time.Time
	Detail string
	Noms   []string
}

type rawEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
	TypeData  json.RawMessage `json:"type_data"`
}

type eventsPage struct {
	Events *[]rawEvent `json:"events"`
	Meta   struct {
		Pagination struct {
			NextPage *int `json:"next_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Events rend les événements de l'app postérieurs à depuis, du plus récent au
// plus ancien. Tronque dit que la lecture s'est arrêtée à maxEventPages pages
// alors que des événements plus anciens restaient après depuis.
func (c *FGPClient) Events(ctx context.Context, region, app string, depuis time.Time) (evs []Evenement, tronque bool, err error) {
	if !reApp.MatchString(app) {
		return nil, false, fmt.Errorf("nom d'app Scalingo %q invalide", app)
	}
	for page := 1; page <= maxEventPages; page++ {
		var p eventsPage
		path := fmt.Sprintf("/v1/apps/%s/events?page=%d&per_page=100", app, page)
		if err := c.get(ctx, region, path, &p); err != nil {
			return nil, false, err
		}
		if p.Events == nil {
			return nil, false, fmt.Errorf("FGP GET /v1/apps/%s/events : champ events absent", app)
		}
		for _, r := range *p.Events {
			if !r.CreatedAt.After(depuis) {
				return evs, false, nil
			}
			evs = append(evs, evenement(r))
		}
		if p.Meta.Pagination.NextPage == nil || len(*p.Events) == 0 {
			return evs, false, nil
		}
	}
	return evs, true, nil
}

func evenement(r rawEvent) Evenement {
	e := Evenement{ID: propre(r.ID, 40), Type: propre(r.Type, 60), A: r.CreatedAt.UTC()}
	switch {
	case strings.Contains(r.Type, "firewall_rule"):
		var d struct {
			CIDR  string `json:"cidr"`
			Label string `json:"label"`
		}
		_ = json.Unmarshal(r.TypeData, &d)
		e.Detail = propre(d.CIDR, 50)
		if d.Label != "" {
			e.Detail += " (" + propre(d.Label, 50) + ")"
		}
	case strings.HasSuffix(r.Type, "_domain"):
		var d struct {
			Hostname string `json:"hostname"`
		}
		_ = json.Unmarshal(r.TypeData, &d)
		e.Detail = propre(d.Hostname, maxDetail)
	case strings.Contains(r.Type, "variable"):
		var v any
		_ = json.Unmarshal(r.TypeData, &v)
		for _, n := range nomsVariables(v, 0) {
			e.Noms = append(e.Noms, propre(n, 80))
		}
	}
	return e
}

// nomsVariables cherche les champs « name » à toute profondeur, la forme des
// événements groupés n'étant pas documentée. Les champs « value » ne sont
// jamais lus : leur contenu n'est pas copié.
func nomsVariables(v any, depth int) []string {
	if depth > 4 {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case map[string]any:
		if n, ok := t["name"].(string); ok {
			out = append(out, n)
		}
		for k, x := range t {
			if k == "value" || k == "name" {
				continue
			}
			out = append(out, nomsVariables(x, depth+1)...)
		}
	case []any:
		for _, x := range t {
			out = append(out, nomsVariables(x, depth+1)...)
		}
	}
	return out
}

// propre borne une valeur venue de Scalingo, saisie par un collaborateur de
// l'app, avant qu'elle n'entre dans les logs et le pulse.
func propre(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// classer : un ajout ou un retrait de règle ou de domaine est un écart, même
// remis depuis (section 3.5 du design). Une page 403 personnalisée casserait la
// signature des sondes : sa pose ou sa modification est un écart, son retrait
// une note. Un domaine modifié (certificat poussé, canonical) est une note.
func classer(e Evenement) (ecart bool, msg string) {
	quand := e.A.Format(time.RFC3339)
	switch {
	case e.Type == "new_app_firewall_rule":
		return true, fmt.Sprintf("règle du firewall ajoutée %s le %s", e.Detail, quand)
	case e.Type == "delete_app_firewall_rule":
		return true, fmt.Sprintf("règle du firewall retirée %s le %s", e.Detail, quand)
	case strings.Contains(e.Type, "firewall_rule"):
		return true, fmt.Sprintf("règle du firewall modifiée (%s) %s le %s", e.Type, e.Detail, quand)
	case e.Type == "new_domain":
		return true, fmt.Sprintf("domaine %s ajouté le %s", e.Detail, quand)
	case e.Type == "delete_domain":
		return true, fmt.Sprintf("domaine %s retiré le %s", e.Detail, quand)
	case strings.HasSuffix(e.Type, "_domain"):
		return false, fmt.Sprintf("domaine %s modifié (%s) le %s", e.Detail, e.Type, quand)
	case strings.Contains(e.Type, "variable"):
		for _, n := range e.Noms {
			if strings.EqualFold(strings.TrimSpace(n), forbiddenPage) {
				if strings.HasPrefix(e.Type, "delete") {
					return false, fmt.Sprintf("%s retirée le %s", forbiddenPage, quand)
				}
				return true, fmt.Sprintf("%s posée ou modifiée (%s) le %s", forbiddenPage, e.Type, quand)
			}
		}
	}
	return false, ""
}
