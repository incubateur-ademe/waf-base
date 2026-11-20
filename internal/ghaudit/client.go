package ghaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
)

const (
	DefaultAPI = "https://api.github.com"
	apiVersion = "2022-11-28"
	maxBody    = 4 << 20
	perPage    = 100
	maxPages   = 10
)

const (
	reOwner = `[A-Za-z0-9][A-Za-z0-9-]{0,38}`
	reName  = `[A-Za-z0-9._-]{1,100}`
	reRef   = `(?:[A-Za-z0-9._-]|%2F){1,300}`
	reSHA   = `[0-9a-f]{40}(?:[0-9a-f]{24})?`
	reID    = `[1-9][0-9]{0,19}`
	reRepo  = `/repos/` + reOwner + `/` + reName
)

type auth int

const (
	authApp auth = iota
	authInstallation
)

type route struct {
	method string
	re     *regexp.Regexp
	auth   auth
	query  []string
}

// Seules routes appelées : un appel hors de cette liste, ou avec une autre
// authentification ou d'autres paramètres, n'est jamais tenté. La seule
// écriture est la création du jeton d'installation, bornée à la lecture.
var routes = []route{
	{http.MethodGet, regexp.MustCompile(`^/orgs/` + reOwner + `/installation$`), authApp, nil},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/installation$`), authApp, nil},
	{http.MethodPost, regexp.MustCompile(`^/app/installations/` + reID + `/access_tokens$`), authApp, nil},
	{http.MethodGet, regexp.MustCompile(`^/orgs/` + reOwner + `/teams/[a-z0-9_-]{1,100}/members$`), authInstallation, []string{"page", "per_page"}},
	{http.MethodGet, regexp.MustCompile(`^/orgs/` + reOwner + `/members$`), authInstallation, []string{"page", "per_page", "role"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `$`), authInstallation, nil},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/branches/` + reRef + `$`), authInstallation, nil},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/branches/` + reRef + `/protection$`), authInstallation, nil},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/rules/branches/` + reRef + `$`), authInstallation, []string{"page", "per_page"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/rulesets/` + reID + `$`), authInstallation, []string{"includes_parents"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/git/trees/` + reSHA + `$`), authInstallation, []string{"recursive"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/git/blobs/` + reSHA + `$`), authInstallation, nil},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/codeowners/errors$`), authInstallation, []string{"ref"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/teams$`), authInstallation, []string{"page", "per_page"}},
	{http.MethodGet, regexp.MustCompile(`^` + reRepo + `/collaborators$`), authInstallation, []string{"affiliation", "page", "per_page"}},
}

// APIError : GitHub a répondu hors 2xx. Le corps n'est jamais repris, il peut
// citer la requête.
type APIError struct {
	Method    string
	Path      string
	Status    int
	RateLimit bool
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("GitHub %s %s : HTTP %d", e.Method, e.Path, e.Status)
	if e.RateLimit {
		s += ", limite de requêtes atteinte"
	}
	return s
}

func isStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

type client struct {
	api  string
	http *http.Client
}

func newHTTPClient(base *http.Client) *http.Client {
	c := &http.Client{}
	if base != nil {
		*c = *base
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func allowed(method, path string, a auth, q url.Values) error {
	for _, r := range routes {
		if r.method != method || !r.re.MatchString(path) {
			continue
		}
		if r.auth != a {
			return fmt.Errorf("GitHub %s %s : authentification inattendue", method, path)
		}
		for k := range q {
			if !slices.Contains(r.query, k) {
				return fmt.Errorf("GitHub %s %s : paramètre %s hors de la liste du client", method, path, k)
			}
		}
		return nil
	}
	return fmt.Errorf("GitHub %s %s : route hors de la liste du client", method, path)
}

// do appelle GitHub et décode une réponse 2xx dans out. bearer est le JWT de
// l'App ou le jeton d'installation, selon a.
func (c *client) do(ctx context.Context, method, path string, q url.Values, a auth, bearer string, body, out any) error {
	if err := allowed(method, path, a, q); err != nil {
		return err
	}
	u := c.api + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("GitHub %s %s : requête invalide", method, path)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", "waf-ops-ghaudit")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("GitHub %s %s injoignable : %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("GitHub %s %s : lecture interrompue", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, RateLimit: resp.Header.Get("X-RateLimit-Remaining") == "0"}
	}
	if len(raw) > maxBody {
		return fmt.Errorf("GitHub %s %s : réponse de plus de %d octets", method, path, maxBody)
	}
	if out == nil {
		return nil
	}
	// L'erreur de décodage peut citer un morceau du corps, qui porte un jeton sur access_tokens.
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("GitHub %s %s : réponse illisible", method, path)
	}
	return nil
}

// list lit une liste paginée par page et per_page, sans suivre l'en-tête Link.
func list[T any](ctx context.Context, c *client, path string, q url.Values, token string) ([]T, error) {
	var all []T
	for page := 1; page <= maxPages; page++ {
		pq := url.Values{}
		for k, v := range q {
			pq[k] = v
		}
		pq.Set("per_page", fmt.Sprint(perPage))
		pq.Set("page", fmt.Sprint(page))
		var items []T
		if err := c.do(ctx, http.MethodGet, path, pq, authInstallation, token, nil, &items); err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < perPage {
			return all, nil
		}
	}
	return nil, fmt.Errorf("GitHub GET %s : plus de %d éléments", path, maxPages*perPage)
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

func pathEscapeRef(ref string) string {
	return url.PathEscape(ref)
}
