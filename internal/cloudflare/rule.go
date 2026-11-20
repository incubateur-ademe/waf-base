package cloudflare

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

// Header : en-tête que la règle pose, et que le WAF compare à WAF_EDGE_SECRET.
const Header = "X-Ademe-Edge"

// RefPrefix : préfixe de la référence des règles que wafgen provision gère.
const RefPrefix = "waf-edge-"

var (
	reHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)
	reApp  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	// Même contrôle que wafgen run avant de démarrer avec WAF_EDGE=cloudflare.
	reSecret = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)
)

// ValidSecret dit si wafgen run accepterait cette valeur de WAF_EDGE_SECRET.
func ValidSecret(s string) bool { return reSecret.MatchString(s) }

type Ruleset struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Rules []Rule `json:"rules"`
}

func (rs *Ruleset) check() error {
	if rs.Phase != Phase {
		return fmt.Errorf("Cloudflare : ruleset hors de la phase %s", Phase)
	}
	return nil
}

// Rule est une règle lue. Ses valeurs d'en-tête peuvent porter un secret : elle
// ne s'affiche jamais.
type Rule struct {
	ID               string          `json:"id"`
	Ref              string          `json:"ref"`
	Enabled          bool            `json:"enabled"`
	Action           string          `json:"action"`
	Expression       string          `json:"expression"`
	ActionParameters json.RawMessage `json:"action_parameters"`
}

type headerOp struct {
	Operation  string  `json:"operation"`
	Value      *string `json:"value,omitempty"`
	Expression *string `json:"expression,omitempty"`
}

// header rend les opérations de la règle sur Header, quelle que soit la casse.
func (r Rule) header() (ops []headerOp, others int, parsed bool) {
	var ap map[string]json.RawMessage
	if len(r.ActionParameters) == 0 || json.Unmarshal(r.ActionParameters, &ap) != nil {
		return nil, 0, len(r.ActionParameters) == 0
	}
	for k := range ap {
		if k != "headers" {
			others++
		}
	}
	var hs map[string]headerOp
	if raw, ok := ap["headers"]; ok && json.Unmarshal(raw, &hs) != nil {
		return nil, others, false
	}
	for name, op := range hs {
		if strings.EqualFold(name, Header) {
			ops = append(ops, op)
		} else {
			others++
		}
	}
	return ops, others, true
}

// touchesHeader dit si la règle agit sur Header. Une règle illisible compte :
// mieux vaut la signaler que la taire.
func (r Rule) touchesHeader() bool {
	ops, _, ok := r.header()
	return !ok || len(ops) > 0
}

// Want est la règle voulue pour une app dans une zone.
type Want struct {
	App    string
	Zone   string
	Hosts  []string
	Secret string
}

// Ref rend la référence de la règle de l'app, qui la retrouve dans la phase.
func Ref(app string) string { return RefPrefix + app }

func (w Want) Ref() string { return Ref(w.App) }

// Expression vise les seuls hosts de l'app dans la zone, jamais toute la zone.
func (w Want) Expression() (string, error) {
	if len(w.Hosts) == 0 {
		return "", fmt.Errorf("zone %s : aucun host de l'app", w.Zone)
	}
	hs := append([]string(nil), w.Hosts...)
	sort.Strings(hs)
	q := make([]string, len(hs))
	for i, h := range hs {
		if !reHost.MatchString(h) || !(h == w.Zone || strings.HasSuffix(h, "."+w.Zone)) {
			return "", fmt.Errorf("zone %s : host %q invalide ou hors de la zone", w.Zone, h)
		}
		q[i] = `"` + h + `"`
	}
	return "(http.host in {" + strings.Join(q, " ") + "})", nil
}

type ruleBody struct {
	Ref              string `json:"ref"`
	Description      string `json:"description"`
	Expression       string `json:"expression"`
	Action           string `json:"action"`
	ActionParameters struct {
		Headers map[string]headerOp `json:"headers"`
	} `json:"action_parameters"`
	Enabled bool `json:"enabled"`
}

func (w Want) body() (ruleBody, error) {
	var b ruleBody
	if !reApp.MatchString(w.App) || !reHost.MatchString(w.Zone) {
		return b, fmt.Errorf("app ou zone invalide")
	}
	if !ValidSecret(w.Secret) {
		return b, fmt.Errorf("%s : secret d'edge hors format, règle non posée", w.Ref())
	}
	expr, err := w.Expression()
	if err != nil {
		return b, err
	}
	secret := w.Secret
	b.Ref = w.Ref()
	b.Description = "Secret d'edge du WAF de " + w.App + " (IDR-0039), géré par wafgen provision"
	b.Expression = expr
	b.Action = "rewrite"
	b.ActionParameters.Headers = map[string]headerOp{Header: {Operation: "set", Value: &secret}}
	b.Enabled = true
	return b, nil
}

// Wants rend la règle voulue de chaque zone de l'app, triées par zone.
func Wants(app inventory.App, secret string) []Want {
	zh := app.ZoneHosts()
	zones := make([]string, 0, len(zh))
	for z := range zh {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	out := make([]Want, 0, len(zones))
	for _, z := range zones {
		out = append(out, Want{App: app.Name, Zone: z, Hosts: zh[z], Secret: secret})
	}
	return out
}

// Diff rend ce qui sépare la règle en place de la règle voulue. Il ne cite
// aucune valeur lue chez Cloudflare. Sans checkValue, la valeur de l'en-tête
// n'est pas comparée.
func Diff(cur Rule, w Want, checkValue bool) []string {
	var out []string
	if expr, err := w.Expression(); err != nil {
		out = append(out, err.Error())
	} else if strings.Join(strings.Fields(cur.Expression), " ") != expr {
		out = append(out, "expression différente de "+expr)
	}
	if cur.Action != "rewrite" {
		out = append(out, "action autre que rewrite")
	}
	if !cur.Enabled {
		out = append(out, "règle désactivée")
	}
	ops, others, ok := cur.header()
	switch {
	case !ok:
		out = append(out, "paramètres d'action illisibles")
	case len(ops) == 0:
		out = append(out, Header+" absent de la règle")
	case len(ops) > 1:
		out = append(out, Header+" présent plusieurs fois")
	case ops[0].Operation != "set" || ops[0].Expression != nil || ops[0].Value == nil:
		out = append(out, Header+" sans valeur fixe posée par set")
	case checkValue && subtle.ConstantTimeCompare([]byte(*ops[0].Value), []byte(w.Secret)) != 1:
		out = append(out, "valeur de "+Header+" différente du secret de l'app")
	}
	if ok && others > 0 {
		out = append(out, "la règle réécrit autre chose que "+Header)
	}
	return out
}

// Reader : lectures seules, ce dont l'audit a besoin.
type Reader interface {
	Zone(ctx context.Context, name string) (Zone, error)
	Entrypoint(ctx context.Context, zoneID string) (*Ruleset, error)
}

// API : lectures et écritures de provision. Aucune ne remplace la phase.
type API interface {
	Reader
	CreateEntrypoint(ctx context.Context, zoneID string, r Want) (*Ruleset, error)
	AddRule(ctx context.Context, zoneID, rulesetID string, r Want) (*Ruleset, error)
	UpdateRule(ctx context.Context, zoneID, rulesetID, ruleID string, r Want) (*Ruleset, error)
}

// ZoneState est une zone lue : son entrypoint, nil s'il n'existe pas.
type ZoneState struct {
	Zone    Zone
	Ruleset *Ruleset
}

// ReadZone lit la zone et son entrypoint.
func ReadZone(ctx context.Context, r Reader, name string) (ZoneState, error) {
	z, err := r.Zone(ctx, name)
	if err != nil {
		return ZoneState{}, err
	}
	rs, err := r.Entrypoint(ctx, z.ID)
	if err != nil {
		return ZoneState{}, err
	}
	return ZoneState{Zone: z, Ruleset: rs}, nil
}

// Managed rend la règle de référence ref, nil si elle est absente.
func (s ZoneState) Managed(ref string) (*Rule, error) {
	if s.Ruleset == nil {
		return nil, nil
	}
	var found *Rule
	for i := range s.Ruleset.Rules {
		if s.Ruleset.Rules[i].Ref != ref {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("zone %s : plusieurs règles %s", s.Zone.Name, ref)
		}
		found = &s.Ruleset.Rules[i]
	}
	return found, nil
}

// Foreign rend l'identifiant des règles de la phase qui touchent Header sans
// être gérées par provision : une copie du secret hors des deux endroits prévus,
// ou une règle qui le retire.
func (s ZoneState) Foreign() []string {
	if s.Ruleset == nil {
		return nil
	}
	var out []string
	for _, r := range s.Ruleset.Rules {
		if strings.HasPrefix(r.Ref, RefPrefix) && reApp.MatchString(strings.TrimPrefix(r.Ref, RefPrefix)) {
			continue
		}
		if r.touchesHeader() {
			out = append(out, r.ID)
		}
	}
	return out
}
