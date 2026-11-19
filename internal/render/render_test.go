package render

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/incubateur-ademe/waf-base/internal/tenant"
)

var tacctHosts = []string{"tacct.ademe.fr", "www.tacct.ademe.fr", "facili-tacct.beta.gouv.fr", "www.facili-tacct.beta.gouv.fr"}

func testInput(hosts []string, canonical, hostHeader string) *Input {
	waf := &tenant.Config{Version: 1}
	waf.RateLimits.Default = tenant.Default{Events: 40, Window: "1s"}
	return &Input{
		Etc: "/etc/waf", State: "/var/lib/waf", Tenant: "tacct",
		Hosts: hosts, Canonical: canonical, HostHeader: hostHeader,
		Platform: "scalingo", Upstream: "https://tacct.osc-fr1.scalingo.io",
		Revision: "rev", Base: "base", WAF: waf, TenantFiles: map[string]bool{},
		Now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
	}
}

func siteJSON(t *testing.T, in *Input) []byte {
	t.Helper()
	route, err := SiteRoute(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func innerRoutes(t *testing.T, in *Input) []map[string]any {
	t.Helper()
	b := siteJSON(t, in)
	var site struct {
		Handle []struct {
			Routes []struct {
				Handle []struct {
					Handler string           `json:"handler"`
					Routes  []map[string]any `json:"routes"`
				} `json:"handle"`
			} `json:"routes"`
		} `json:"handle"`
	}
	if err := json.Unmarshal(b, &site); err != nil {
		t.Fatal(err)
	}
	outer := site.Handle[0].Routes
	last := outer[len(outer)-1].Handle[0]
	if last.Handler != "subroute" {
		t.Fatalf("dernière route du site : %s, subroute attendue", last.Handler)
	}
	return last.Routes
}

func handlers(r map[string]any) []string {
	var out []string
	for _, h := range r["handle"].([]any) {
		out = append(out, h.(map[string]any)["handler"].(string))
	}
	return out
}

func TestSansCanonicalRouteInchangee(t *testing.T) {
	cases := []struct {
		nom       string
		hosts     []string
		canonical string
	}{
		{"sans canonical, 4 hosts", tacctHosts, ""},
		{"sans canonical, 1 host", tacctHosts[:1], ""},
		{"canonical seul host de l'app", tacctHosts[:1], tacctHosts[0]},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			inner := innerRoutes(t, testInput(c.hosts, c.canonical, "visitor"))
			var got [][]string
			for _, r := range inner {
				got = append(got, handlers(r))
			}
			want := [][]string{{"static_response"}, {"static_response"}, {"rate_limit"}, {"waf", "encode", "reverse_proxy"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("handlers = %v, attendu %v", got, want)
			}
		})
	}
	a := siteJSON(t, testInput(tacctHosts[:1], "", "visitor"))
	b := siteJSON(t, testInput(tacctHosts[:1], tacctHosts[0], "visitor"))
	if string(a) != string(b) {
		t.Fatal("un canonical égal au seul host change le rendu")
	}
}

func TestCanonicalRedirection(t *testing.T) {
	for _, hh := range []string{"visitor", "upstream"} {
		t.Run(hh, func(t *testing.T) {
			inner := innerRoutes(t, testInput(tacctHosts, "tacct.ademe.fr", hh))
			var got [][]string
			for _, r := range inner {
				got = append(got, handlers(r))
			}
			want := [][]string{{"static_response"}, {"static_response"}, {"rate_limit"}, {"waf"}, {"static_response"}, {"encode", "reverse_proxy"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("handlers = %v, attendu %v : redirection après le rate limit et Coraza, avant encode et reverse_proxy", got, want)
			}
			for _, i := range []int{3, 5} {
				if _, ok := inner[i]["match"]; ok {
					t.Fatalf("route %d filtrée : %v", i, inner[i]["match"])
				}
			}
			b, _ := json.Marshal(inner[4])
			var redir struct {
				Match []struct {
					Host []string `json:"host"`
					Path []string `json:"path"`
				} `json:"match"`
				Handle []struct {
					StatusCode int                 `json:"status_code"`
					Headers    map[string][]string `json:"headers"`
				} `json:"handle"`
			}
			if err := json.Unmarshal(b, &redir); err != nil {
				t.Fatal(err)
			}
			hosts := redir.Match[0].Host
			if len(redir.Match) != 1 || slices.Contains(hosts, "tacct.ademe.fr") || len(hosts) != 3 {
				t.Fatalf("hosts redirigés = %v, attendu les 3 autres hosts", hosts)
			}
			if !reflect.DeepEqual(redir.Match[0].Path, []string{"/*"}) {
				t.Fatalf("chemins redirigés = %v, attendu [/*] dans le jeu du host", redir.Match[0].Path)
			}
			h := redir.Handle[0]
			headers := map[string][]string{
				"Location":      {"https://tacct.ademe.fr{http.request.uri}"},
				"Cache-Control": {"max-age=86400"},
			}
			if h.StatusCode != 301 || !reflect.DeepEqual(h.Headers, headers) {
				t.Fatalf("redirection : %+v", h)
			}
		})
	}
}

func TestCanonicalCibleOpaque(t *testing.T) {
	inner := innerRoutes(t, testInput(tacctHosts, "tacct.ademe.fr", "visitor"))
	b, err := json.Marshal(inner[4]["match"])
	if err != nil {
		t.Fatal(err)
	}
	var sets []map[string]json.RawMessage
	if err := json.Unmarshal(b, &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || len(sets[0]) != 2 {
		t.Fatalf("matcher de la 301 : %s, attendu un seul jeu host et path", b)
	}
	var host caddyhttp.MatchHost
	var path caddyhttp.MatchPath
	if err := json.Unmarshal(sets[0]["host"], &host); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sets[0]["path"], &path); err != nil {
		t.Fatal(err)
	}
	if err := host.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := path.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cible    string
		redirige bool
	}{
		{"/", true},
		{"/a/b?x=1&y=2", true},
		{"//evil.com/", true},
		{"a:@evil.com", false},
		{"mailto:x@evil.com", false},
		{"*", false},
	}
	for _, c := range cases {
		t.Run(c.cible, func(t *testing.T) {
			r, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + c.cible + " HTTP/1.1\r\nHost: www.tacct.ademe.fr\r\n\r\n")))
			if err != nil {
				t.Fatal(err)
			}
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
			if h, err := host.MatchWithError(r); err != nil || !h {
				t.Fatalf("host www.tacct.ademe.fr non reconnu : %v", err)
			}
			p, err := path.MatchWithError(r)
			if err != nil {
				t.Fatal(err)
			}
			if p != c.redirige {
				t.Fatalf("GET %s sur www.tacct.ademe.fr : redirection %v, attendu %v", c.cible, p, c.redirige)
			}
		})
	}
}

// Les rendus de testdata datent d'avant la redirection canonique. Une app sans
// canonical garde la même conf Caddy, à l'octet près.
func TestRenduSansCanonicalInchange(t *testing.T) {
	base, err := os.ReadFile("testdata/base.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ app, waf string }{
		{"pilote", filepath.Join(t.TempDir(), "waf.yaml")},
		{"tacct", "testdata/tacct.waf.yaml"},
	}
	for _, c := range cases {
		t.Run(c.app, func(t *testing.T) {
			b, err := os.ReadFile("testdata/" + c.app + ".entree.json")
			if err != nil {
				t.Fatal(err)
			}
			var in Input
			if err := json.Unmarshal(b, &in); err != nil {
				t.Fatal(err)
			}
			if in.WAF, err = tenant.Load(c.waf, 100); err != nil {
				t.Fatal(err)
			}
			got, err := Caddy(base, &in)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("testdata/" + c.app + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				i := 0
				for i < len(got) && i < len(want) && got[i] == want[i] {
					i++
				}
				t.Fatalf("rendu différent de testdata/%s.json à l'octet %d : %q", c.app, i, got[i:min(i+120, len(got))])
			}
		})
	}
}

func TestCanonicalRefuse(t *testing.T) {
	cases := []struct {
		nom       string
		hosts     []string
		canonical string
	}{
		{"hors des hosts", tacctHosts, "autre.ademe.fr"},
		{"placeholder Caddy", []string{"a.example.org", "{env.ORIGIN_TOKEN}"}, "{env.ORIGIN_TOKEN}"},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			_, err := SiteRoute(testInput(c.hosts, c.canonical, "visitor"))
			if err == nil || !strings.Contains(err.Error(), "WAF_CANONICAL_HOST") {
				t.Fatalf("erreur = %v", err)
			}
		})
	}
}
