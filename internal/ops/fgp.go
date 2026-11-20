package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Routes que le client accepte d'appeler : lecture seule, pour une app nommée.
// Le blob borne aussi chaque appel, mais une route hors liste n'est jamais tentée.
var reFGPPath = regexp.MustCompile(`^/v1/apps/[a-z0-9][a-z0-9-]{0,62}/(firewall_rules|domains|events\?page=[1-9]&per_page=100)$`)

var reApp = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const maxFGPBody = 4 << 20

// FGPError distingue un refus du proxy (blob sans le scope, clé fausse) d'une
// réponse de Scalingo, par l'en-tête X-FGP-Source.
type FGPError struct {
	Path   string
	Status int
	Source string
}

func (e *FGPError) Error() string {
	if e.Source == "proxy" {
		return fmt.Sprintf("FGP refuse %s (HTTP %d) : scope absent du blob ou clé fausse", e.Path, e.Status)
	}
	return fmt.Sprintf("Scalingo répond %d sur %s", e.Status, e.Path)
}

// ErrFGPInjoignable : FGP n'a pas répondu, réseau ou délai.
var ErrFGPInjoignable = errors.New("FGP injoignable")

type FGPClient struct {
	base  string
	key   string
	blobs map[string]string
	http  *http.Client
}

func NewFGPClient(f FGP) *FGPClient {
	return &FGPClient{
		base:  f.URL,
		key:   f.Key,
		blobs: f.API,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// HasRegion dit si un blob d'API couvre la région.
func (c *FGPClient) HasRegion(region string) bool {
	_, ok := c.blobs[region]
	return ok
}

func (c *FGPClient) get(ctx context.Context, region, path string, out any) error {
	if !reFGPPath.MatchString(path) {
		return fmt.Errorf("FGP GET %s : route hors de la liste du client", path)
	}
	blob, ok := c.blobs[region]
	if !ok {
		return fmt.Errorf("aucun blob FGP pour la région %s", region)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-FGP-Key", c.key)
	req.Header.Set("X-FGP-Blob", blob)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// L'erreur de transport cite l'URL, sans les en-têtes : ni clé ni blob.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%w : GET %s : %v", ErrFGPInjoignable, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFGPBody+1))
	if err != nil {
		return fmt.Errorf("%w : GET %s : %v", ErrFGPInjoignable, path, err)
	}
	if len(raw) > maxFGPBody {
		return fmt.Errorf("FGP GET %s : réponse de plus de %d octets", path, maxFGPBody)
	}
	if resp.StatusCode != http.StatusOK {
		// Le corps n'est pas repris : une réponse d'erreur du proxy peut citer la requête.
		return &FGPError{Path: path, Status: resp.StatusCode, Source: strings.ToLower(resp.Header.Get("X-FGP-Source"))}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("FGP GET %s : réponse illisible : %v", path, err)
	}
	return nil
}

type FirewallRule struct {
	ID    string `json:"id"`
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
}

type Domain struct {
	Name string `json:"name"`
}

func (c *FGPClient) FirewallRules(ctx context.Context, region, app string) ([]FirewallRule, error) {
	if !reApp.MatchString(app) {
		return nil, fmt.Errorf("nom d'app Scalingo %q invalide", app)
	}
	var out struct {
		Rules *[]FirewallRule `json:"firewall_rules"`
	}
	if err := c.get(ctx, region, "/v1/apps/"+app+"/firewall_rules", &out); err != nil {
		return nil, err
	}
	if out.Rules == nil {
		return nil, fmt.Errorf("FGP GET /v1/apps/%s/firewall_rules : champ firewall_rules absent", app)
	}
	return *out.Rules, nil
}

func (c *FGPClient) Domains(ctx context.Context, region, app string) ([]Domain, error) {
	if !reApp.MatchString(app) {
		return nil, fmt.Errorf("nom d'app Scalingo %q invalide", app)
	}
	var out struct {
		Domains *[]Domain `json:"domains"`
	}
	if err := c.get(ctx, region, "/v1/apps/"+app+"/domains", &out); err != nil {
		return nil, err
	}
	if out.Domains == nil {
		return nil, fmt.Errorf("FGP GET /v1/apps/%s/domains : champ domains absent", app)
	}
	return *out.Domains, nil
}
