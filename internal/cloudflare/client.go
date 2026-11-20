// Package cloudflare pose et contrôle la règle qui porte le secret d'edge d'une
// app dans ses zones Cloudflare (IDR-0039), par l'API Rulesets.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL = "https://api.cloudflare.com"
	// TokenEnv : variable d'environnement du jeton, pour provision comme pour waf-ops.
	TokenEnv = "CLOUDFLARE_API_TOKEN"
	Phase    = "http_request_late_transform"
	maxBody  = 4 << 20
)

type route struct {
	method string
	path   *regexp.Regexp
}

const id = `[0-9a-f]{32}`

// Aucun PUT : celui de l'entrypoint remplacerait toutes les règles de la phase,
// y compris celles que waf-ops ne gère pas. Aucun DELETE non plus.
var routes = []route{
	{http.MethodGet, regexp.MustCompile(`^/client/v4/zones$`)},
	{http.MethodGet, regexp.MustCompile(`^/client/v4/zones/` + id + `/rulesets/phases/` + Phase + `/entrypoint$`)},
	{http.MethodPost, regexp.MustCompile(`^/client/v4/zones/` + id + `/rulesets$`)},
	{http.MethodPost, regexp.MustCompile(`^/client/v4/zones/` + id + `/rulesets/` + id + `/rules$`)},
	{http.MethodPatch, regexp.MustCompile(`^/client/v4/zones/` + id + `/rulesets/` + id + `/rules/` + id + `$`)},
}

// Allowed dit si le client accepte d'appeler cette route.
func Allowed(method, path string) bool {
	for _, r := range routes {
		if r.method == method && r.path.MatchString(path) {
			return true
		}
	}
	return false
}

// HTTPError ne garde du corps que les codes d'erreur de Cloudflare : un message
// d'erreur peut citer la règle envoyée, donc le secret.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Codes  []int
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("Cloudflare %s %s : HTTP %d", e.Method, e.Path, e.Status)
	if len(e.Codes) > 0 {
		cs := make([]string, len(e.Codes))
		for i, c := range e.Codes {
			cs[i] = strconv.Itoa(c)
		}
		msg += ", codes " + strings.Join(cs, ", ")
	}
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		msg += " : jeton refusé ou permission absente (Zone Read, Transform Rules Edit, lecture des Rulesets)"
	}
	return msg
}

// ErrZoneAbsente : aucune zone de ce nom n'est visible du jeton.
var ErrZoneAbsente = errors.New("zone absente ou hors du jeton Cloudflare")

type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New rend un client de l'API Cloudflare.
func New(token string) (*Client, error) { return NewAt(DefaultURL, token) }

// NewAt rend un client vers une autre base : https, ou http sur la boucle locale
// pour les tests, pour que le jeton ne parte jamais en clair.
func NewAt(baseURL, token string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("URL de l'API Cloudflare : http(s)://<hôte>[:port] attendu, sans chemin")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("URL de l'API Cloudflare : https attendu hors de la boucle locale")
		}
	default:
		return nil, fmt.Errorf("URL de l'API Cloudflare : http(s)://<hôte>[:port] attendu, sans chemin")
	}
	if token == "" || len(token) > 512 || strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return nil, fmt.Errorf("%s vide, trop long ou avec des blancs", TokenEnv)
	}
	return &Client{
		base:  u,
		token: token,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type envelope struct {
	Success bool            `json:"success"`
	Errors  []apiError      `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type apiError struct {
	Code int `json:"code"`
}

func codes(raw []byte) []int {
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		return nil
	}
	var out []int
	for _, e := range env.Errors {
		out = append(out, e.Code)
	}
	return out
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	if !Allowed(method, path) {
		return fmt.Errorf("Cloudflare %s %s : route hors de la liste du client", method, path)
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("Cloudflare %s %s : requête invalide", method, path)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("Cloudflare %s %s : %s", method, path, strings.ReplaceAll(err.Error(), c.token, "[jeton]"))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("Cloudflare %s %s : lecture de la réponse interrompue", method, path)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("Cloudflare %s %s : réponse de plus de %d octets", method, path, maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Codes: codes(raw)}
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("Cloudflare %s %s : réponse illisible", method, path)
	}
	if !env.Success {
		return &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Codes: codes(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("Cloudflare %s %s : résultat illisible", method, path)
	}
	return nil
}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

var reID = regexp.MustCompile(`^` + id + `$`)

// Zone rend la seule zone de ce nom visible du jeton.
func (c *Client) Zone(ctx context.Context, name string) (Zone, error) {
	if !reHost.MatchString(name) {
		return Zone{}, fmt.Errorf("zone %q invalide", name)
	}
	var list []Zone
	q := url.Values{"name": {name}, "per_page": {"50"}}
	if err := c.do(ctx, http.MethodGet, "/client/v4/zones", q, nil, &list); err != nil {
		return Zone{}, err
	}
	var found []Zone
	for _, z := range list {
		if z.Name == name {
			found = append(found, z)
		}
	}
	switch {
	case len(found) == 0:
		return Zone{}, fmt.Errorf("%s : %w", name, ErrZoneAbsente)
	case len(found) > 1:
		return Zone{}, fmt.Errorf("%s : %d zones de ce nom visibles du jeton Cloudflare", name, len(found))
	case !reID.MatchString(found[0].ID):
		return Zone{}, fmt.Errorf("%s : identifiant de zone inattendu", name)
	}
	return found[0], nil
}

func zonePath(zoneID string) (string, error) {
	if !reID.MatchString(zoneID) {
		return "", fmt.Errorf("identifiant de zone inattendu")
	}
	return "/client/v4/zones/" + zoneID, nil
}

// Entrypoint rend le ruleset de la phase de la zone, nil s'il n'existe pas.
func (c *Client) Entrypoint(ctx context.Context, zoneID string) (*Ruleset, error) {
	zp, err := zonePath(zoneID)
	if err != nil {
		return nil, err
	}
	var rs Ruleset
	err = c.do(ctx, http.MethodGet, zp+"/rulesets/phases/"+Phase+"/entrypoint", nil, nil, &rs)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := rs.check(); err != nil {
		return nil, err
	}
	return &rs, nil
}

// CreateEntrypoint crée le ruleset de la phase avec la seule règle r. Cloudflare
// le refuse si la zone en a déjà un : il ne remplace jamais les règles en place.
func (c *Client) CreateEntrypoint(ctx context.Context, zoneID string, r Want) (*Ruleset, error) {
	zp, err := zonePath(zoneID)
	if err != nil {
		return nil, err
	}
	body, err := r.body()
	if err != nil {
		return nil, err
	}
	in := map[string]any{
		"name":        "default",
		"description": "Transform Rules de requête, créé par wafgen provision",
		"kind":        "zone",
		"phase":       Phase,
		"rules":       []ruleBody{body},
	}
	var rs Ruleset
	if err := c.do(ctx, http.MethodPost, zp+"/rulesets", nil, in, &rs); err != nil {
		return nil, err
	}
	return &rs, rs.check()
}

// AddRule ajoute r à la fin du ruleset, sans toucher aux autres règles.
func (c *Client) AddRule(ctx context.Context, zoneID, rulesetID string, r Want) (*Ruleset, error) {
	zp, err := zonePath(zoneID)
	if err != nil {
		return nil, err
	}
	if !reID.MatchString(rulesetID) {
		return nil, fmt.Errorf("identifiant de ruleset inattendu")
	}
	body, err := r.body()
	if err != nil {
		return nil, err
	}
	var rs Ruleset
	if err := c.do(ctx, http.MethodPost, zp+"/rulesets/"+rulesetID+"/rules", nil, body, &rs); err != nil {
		return nil, err
	}
	return &rs, rs.check()
}

// UpdateRule remplace la seule règle ruleID par r.
func (c *Client) UpdateRule(ctx context.Context, zoneID, rulesetID, ruleID string, r Want) (*Ruleset, error) {
	zp, err := zonePath(zoneID)
	if err != nil {
		return nil, err
	}
	if !reID.MatchString(rulesetID) || !reID.MatchString(ruleID) {
		return nil, fmt.Errorf("identifiant de ruleset ou de règle inattendu")
	}
	body, err := r.body()
	if err != nil {
		return nil, err
	}
	var rs Ruleset
	if err := c.do(ctx, http.MethodPatch, zp+"/rulesets/"+rulesetID+"/rules/"+ruleID, nil, body, &rs); err != nil {
		return nil, err
	}
	return &rs, rs.check()
}
