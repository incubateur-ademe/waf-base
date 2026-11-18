package render

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

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
			h := redir.Handle[0]
			if h.StatusCode != 301 || !reflect.DeepEqual(h.Headers["Location"], []string{"https://tacct.ademe.fr{http.request.uri}"}) {
				t.Fatalf("redirection : %+v", h)
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
