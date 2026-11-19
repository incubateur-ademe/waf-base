// Package coolify est un client minimal de l'API Coolify 4.7.5, limité aux
// routes dont wafgen provision a besoin.
package coolify

import (
	"bytes"
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
	"unicode/utf8"
)

type route struct {
	method string
	path   *regexp.Regexp
}

const seg = `[A-Za-z0-9_-]{1,64}`

var routes = []route{
	{http.MethodGet, regexp.MustCompile(`^/api/v1/applications$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/applications/` + seg + `$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/applications/` + seg + `/destinations$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/applications/` + seg + `/envs$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/destinations/` + seg + `$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/github-apps$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/team/envs$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/servers/` + seg + `/envs$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/applications/private-github-app$`)},
	{http.MethodPatch, regexp.MustCompile(`^/api/v1/applications/` + seg + `$`)},
	{http.MethodPatch, regexp.MustCompile(`^/api/v1/applications/` + seg + `/envs/bulk$`)},
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

type HTTPError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Coolify %s %s : HTTP %d : %s", e.Method, e.Path, e.Status, e.Body)
}

type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

const (
	maxBody   = 8 << 20
	maxErrLen = 300
)

func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Path != "" {
		return nil, fmt.Errorf("COOLIFY_URL : http(s)://<hôte>[:port] attendu, sans chemin")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("COOLIFY_TOKEN vide")
	}
	return &Client{
		base:  u,
		token: token,
		http: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "[jeton]")
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	if !Allowed(method, path) {
		return fmt.Errorf("Coolify %s %s : route hors de la liste du client", method, path)
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
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
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
		return fmt.Errorf("Coolify %s %s : %s", method, path, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("Coolify %s %s : %v", method, path, err)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("Coolify %s %s : réponse de plus de %d octets", method, path, maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Masquer avant de tronquer : une coupe au milieu du jeton laisserait
		// passer son début.
		msg := c.redact(strings.Join(strings.Fields(string(raw)), " "))
		if len(msg) > maxErrLen {
			cut := maxErrLen
			for cut > 0 && !utf8.RuneStart(msg[cut]) {
				cut--
			}
			msg = msg[:cut] + "…"
		}
		return &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("Coolify %s %s : réponse illisible : %v", method, path, err)
	}
	return nil
}

// Str est une chaîne JSON qui distingue un champ absent (Set=false), null et une valeur.
type Str struct {
	Set   bool
	Null  bool
	Value string
}

func (s *Str) UnmarshalJSON(b []byte) error {
	s.Set = true
	if string(b) == "null" {
		s.Null = true
		return nil
	}
	return json.Unmarshal(b, &s.Value)
}

type AppSummary struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// Application garde la réponse brute : provision ne compare que les champs qu'il pose.
type Application map[string]any

type Destination struct {
	UUID       string `json:"uuid"`
	Name       string `json:"name"`
	Network    string `json:"network"`
	ServerUUID string `json:"server_uuid"`
	IsPrimary  bool   `json:"is_primary"`
}

type GithubApp struct {
	ID   int64  `json:"id"`
	UUID string `json:"uuid"`
}

type Env struct {
	UUID        string `json:"uuid"`
	Key         string `json:"key"`
	Value       Str    `json:"value"`
	IsBuildtime bool   `json:"is_buildtime"`
	IsRuntime   bool   `json:"is_runtime"`
	IsPreview   bool   `json:"is_preview"`
	IsShownOnce bool   `json:"is_shown_once"`
}

// EnvWrite est une ligne du PATCH bulk. Value nil laisse la valeur en place.
type EnvWrite struct {
	Key         string  `json:"key"`
	Value       *string `json:"value,omitempty"`
	IsPreview   bool    `json:"is_preview"`
	IsBuildtime bool    `json:"is_buildtime"`
	IsRuntime   bool    `json:"is_runtime"`
}

type SharedEnv struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Value       Str    `json:"value"`
	IsShownOnce bool   `json:"is_shown_once"`
}

func (c *Client) ListApplications(ctx context.Context) ([]AppSummary, error) {
	var out []AppSummary
	return out, c.do(ctx, http.MethodGet, "/api/v1/applications", nil, &out)
}

func (c *Client) GetApplication(ctx context.Context, uuid string) (Application, error) {
	var out Application
	return out, c.do(ctx, http.MethodGet, "/api/v1/applications/"+uuid, nil, &out)
}

func (c *Client) ApplicationDestinations(ctx context.Context, uuid string) ([]Destination, error) {
	var out []Destination
	return out, c.do(ctx, http.MethodGet, "/api/v1/applications/"+uuid+"/destinations", nil, &out)
}

func (c *Client) GetDestination(ctx context.Context, uuid string) (Destination, error) {
	var out Destination
	return out, c.do(ctx, http.MethodGet, "/api/v1/destinations/"+uuid, nil, &out)
}

func (c *Client) ListGithubApps(ctx context.Context) ([]GithubApp, error) {
	var out []GithubApp
	return out, c.do(ctx, http.MethodGet, "/api/v1/github-apps", nil, &out)
}

func (c *Client) CreateApplication(ctx context.Context, body map[string]any) (string, error) {
	var out struct {
		UUID string `json:"uuid"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/applications/private-github-app", body, &out); err != nil {
		return "", err
	}
	if out.UUID == "" {
		return "", fmt.Errorf("Coolify : création sans uuid dans la réponse")
	}
	return out.UUID, nil
}

func (c *Client) UpdateApplication(ctx context.Context, uuid string, body map[string]any) error {
	return c.do(ctx, http.MethodPatch, "/api/v1/applications/"+uuid, body, nil)
}

func (c *Client) ListApplicationEnvs(ctx context.Context, uuid string) ([]Env, error) {
	var out []Env
	return out, c.do(ctx, http.MethodGet, "/api/v1/applications/"+uuid+"/envs", nil, &out)
}

func (c *Client) UpsertApplicationEnvs(ctx context.Context, uuid string, envs []EnvWrite) error {
	return c.do(ctx, http.MethodPatch, "/api/v1/applications/"+uuid+"/envs/bulk", map[string]any{"data": envs}, nil)
}

func (c *Client) ListTeamEnvs(ctx context.Context) ([]SharedEnv, error) {
	var out []SharedEnv
	return out, c.do(ctx, http.MethodGet, "/api/v1/team/envs", nil, &out)
}

func (c *Client) ListServerEnvs(ctx context.Context, uuid string) ([]SharedEnv, error) {
	var out []SharedEnv
	return out, c.do(ctx, http.MethodGet, "/api/v1/servers/"+uuid+"/envs", nil, &out)
}
