package runner

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"
	_ "github.com/mholt/caddy-ratelimit"

	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
	"github.com/incubateur-ademe/waf-base/internal/tenant"
)

const secretFactice = "secret-edge-factice-0123456789abcdef-ABCDEF"

func TestInputsEdge(t *testing.T) {
	pol, err := policy.Load("../../policy")
	if err != nil {
		t.Fatal(err)
	}
	p := Paths{Etc: t.TempDir()}
	if err := os.Mkdir(filepath.Join(p.Etc, "tenant"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		nom, edge, secret, attendu, erreur string
		absente                            bool
	}{
		{nom: "absente", absente: true},
		{nom: "vide, null côté Coolify", secret: secretFactice},
		{nom: "cloudflare", edge: "cloudflare", secret: secretFactice, attendu: "cloudflare"},
		{nom: "espaces autour de WAF_EDGE", edge: " cloudflare ", secret: secretFactice, attendu: "cloudflare"},
		{nom: "32 caractères", edge: "cloudflare", secret: strings.Repeat("aB3_-", 6) + "zz", attendu: "cloudflare"},
		{nom: "autre edge", edge: "fastly", secret: secretFactice, erreur: `WAF_EDGE "fastly" : cloudflare seule valeur admise`},
		{nom: "secret absent", edge: "cloudflare", erreur: "WAF_EDGE_SECRET manquante ou invalide"},
		{nom: "secret de 31 caractères", edge: "cloudflare", secret: secretFactice[:31], erreur: "WAF_EDGE_SECRET manquante ou invalide"},
		{nom: "secret en base64", edge: "cloudflare", secret: "c2VjcmV0LWVkZ2UtZmFjdGljZS0wMTIzNDU2Nzg5YWJj+/==", erreur: "WAF_EDGE_SECRET manquante ou invalide"},
		{nom: "secret suivi d'un saut de ligne", edge: "cloudflare", secret: secretFactice + "\n", erreur: "WAF_EDGE_SECRET manquante ou invalide"},
		{nom: "secret précédé d'une espace", edge: "cloudflare", secret: " " + secretFactice, erreur: "WAF_EDGE_SECRET manquante ou invalide"},
		{nom: "référence d'équipe non résolue", edge: "cloudflare", secret: "{{team.EDGE_SECRET_TACCT}}", erreur: "WAF_EDGE_SECRET contient encore « {{ »"},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			for k, v := range map[string]string{
				"WAF_TENANT": "tacct", "WAF_HOSTS": "tacct.ademe.fr", "UPSTREAM": "https://tacct.osc-fr1.scalingo.io",
				"WAF_PLATFORM": "scalingo", "WAF_HOST_HEADER": "upstream", "WAF_CEILINGS": "", "WAF_CRS_PLUGINS": "",
				"WAF_DETECTION_UNTIL": "", "WAF_FORCE_DETECTION": "", "WAF_UNINSPECTED_PATHS": "", "WAF_CANONICAL_HOST": "",
				"WAF_EDGE": c.edge, "WAF_EDGE_SECRET": c.secret,
			} {
				t.Setenv(k, v)
			}
			if c.absente {
				os.Unsetenv("WAF_EDGE")
				os.Unsetenv("WAF_EDGE_SECRET")
			}
			in, err := Inputs(p, pol, nil, time.Now())
			if c.erreur != "" {
				if err == nil || !strings.Contains(err.Error(), c.erreur) {
					t.Fatalf("erreur = %v, attendu %q", err, c.erreur)
				}
				if c.secret != "" && strings.Contains(err.Error(), strings.TrimSpace(c.secret)) {
					t.Fatalf("secret dans l'erreur : %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if in.Edge != c.attendu {
				t.Fatalf("Edge = %q, attendu %q", in.Edge, c.attendu)
			}
		})
	}
}

func walk(v any, f func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		f(x)
		for _, c := range x {
			walk(c, f)
		}
	case []any:
		for _, c := range x {
			walk(c, f)
		}
	}
}

// Règles Coraza du test : 418 si X-Ademe-Edge atteint Coraza, 403 si REMOTE_ADDR
// vaut une des IP annoncées dans CF-Connecting-IP.
const directivesEdge = `SecRuleEngine On
SecRequestBodyAccess Off
SecResponseBodyAccess Off
SecAuditEngine Off
SecRule &REQUEST_HEADERS:X-Ademe-Edge "@gt 0" "id:101,phase:1,deny,status:418,log"
SecRule REMOTE_ADDR "@ipMatch 198.51.100.66,2001:db8::66" "id:102,phase:1,deny,status:403,log"
`

// caddyEdge charge dans ce processus la conf rendue pour une app edge, avec ces
// seuls écarts : ports locaux, serveur :2020 retiré, directives Coraza du test,
// origine au certificat de test, rate limit appliqué aussi à la boucle locale et
// logs écrits dans des fichiers.
func caddyEdge(t *testing.T, origin string, logs string) (string, *render.Input) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	waf := &tenant.Config{Version: 1}
	waf.RateLimits.Default = tenant.Default{Events: 1000, Window: "1m"}
	waf.RateLimits.Zones = []tenant.Zone{{Name: "limite", Paths: []string{"/limite"}, Events: 2, Window: "1m"}}
	in := &render.Input{
		Etc: "/etc/waf", State: t.TempDir(), Tenant: "edge", Hosts: []string{"edge.example.org"},
		HostHeader: "visitor", Platform: "scalingo", Upstream: origin, Edge: render.EdgeCloudflare,
		WAF: waf, TenantFiles: map[string]bool{}, Now: time.Now(),
	}
	base, err := os.ReadFile("../render/testdata/base.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := render.Caddy(base, in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	delete(servers, "srv0")
	servers["srv1"].(map[string]any)["listen"] = []string{addr}
	for name, l := range cfg["logging"].(map[string]any)["logs"].(map[string]any) {
		l.(map[string]any)["writer"] = map[string]any{"output": "file", "filename": filepath.Join(logs, name+".log")}
	}
	walk(cfg, func(m map[string]any) {
		switch m["handler"] {
		case "waf":
			m["directives"] = directivesEdge
		case "reverse_proxy":
			m["transport"].(map[string]any)["tls"].(map[string]any)["insecure_skip_verify"] = true
		}
		if _, ok := m["remote_ip"]; ok {
			m["remote_ip"] = map[string]any{"ranges": []string{"192.0.2.0/24"}}
		}
	})
	b, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	return "http://" + addr, in
}

func TestEdgeDansCaddy(t *testing.T) {
	t.Setenv("WAF_EDGE_SECRET", secretFactice)
	var mu sync.Mutex
	var vus []http.Header
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/coupe" {
			panic(http.ErrAbortHandler)
		}
		mu.Lock()
		vus = append(vus, r.Header.Clone())
		mu.Unlock()
	}))
	defer origin.Close()
	logs := t.TempDir()
	base, in := caddyEdge(t, origin.URL, logs)

	const noeud = "203.0.113.50"
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	do := func(path, xff, edge, cfip string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Host = "edge.example.org"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", xff)
		if edge != "" {
			req.Header.Set("X-Ademe-Edge", edge)
		}
		if cfip != "" {
			req.Header.Set("CF-Connecting-IP", cfip)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	faux := "secret-edge-factice-0123456789abcdef-ABCDEX"

	t.Run("/__waf/ip", func(t *testing.T) {
		cases := []struct{ nom, edge, cfip, attendu string }{
			{"secret et IPv4", secretFactice, "198.51.100.7", "198.51.100.7"},
			{"secret et IPv6", secretFactice, "2001:db8::7", "2001:db8::7"},
			{"secret faux", faux, "198.51.100.7", noeud},
			{"sans secret", "", "198.51.100.7", noeud},
			{"secret et liste d'IP", secretFactice, "198.51.100.7, 192.0.2.1", noeud},
			{"secret sans CF-Connecting-IP", secretFactice, "", noeud},
		}
		for _, c := range cases {
			if st, body := do("/__waf/ip", noeud, c.edge, c.cfip); st != 200 || body != c.attendu {
				t.Errorf("%s : %d %q, attendu %q", c.nom, st, body, c.attendu)
			}
		}
	})

	t.Run("autotest de démarrage", func(t *testing.T) {
		if err := edgeCheck(base, in, secretFactice); err != nil {
			t.Fatal(err)
		}
		err := edgeCheck(base, in, faux)
		if err == nil || !strings.Contains(err.Error(), "avec le secret") || strings.Contains(err.Error(), faux) {
			t.Fatalf("secret refusé par Caddy : %v", err)
		}
	})

	t.Run("Coraza", func(t *testing.T) {
		cases := []struct {
			nom, xff, edge, cfip string
			status               int
		}{
			{"REMOTE_ADDR remplacée en IPv4", noeud, secretFactice, "198.51.100.66", 403},
			{"REMOTE_ADDR remplacée en IPv6", noeud, secretFactice, "2001:db8::66", 403},
			{"secret faux : REMOTE_ADDR du nœud", noeud, faux, "198.51.100.66", 200},
			{"la règle du test vise bien REMOTE_ADDR", "198.51.100.66", "", "", 403},
			{"X-Ademe-Edge retiré avant Coraza", noeud, secretFactice, "198.51.100.8", 200},
		}
		for _, c := range cases {
			if st, _ := do("/", c.xff, c.edge, c.cfip); st != c.status {
				t.Errorf("%s : %d, attendu %d", c.nom, st, c.status)
			}
		}
	})

	t.Run("en-têtes reçus par l'origine", func(t *testing.T) {
		mu.Lock()
		vus = nil
		mu.Unlock()
		do("/", noeud, secretFactice, "198.51.100.9")
		do("/", noeud, faux, "198.51.100.9")
		mu.Lock()
		defer mu.Unlock()
		if len(vus) != 2 {
			t.Fatalf("%d requêtes à l'origine, 2 attendues", len(vus))
		}
		for i, xff := range []string{"198.51.100.9", noeud} {
			h := vus[i]
			if got := h.Values("X-Forwarded-For"); len(got) != 1 || got[0] != xff {
				t.Errorf("requête %d : X-Forwarded-For %v, attendu %s", i, got, xff)
			}
			if h.Get("CF-Connecting-IP") != "" || h.Get("X-Ademe-Edge") != "" {
				t.Errorf("requête %d : CF-Connecting-IP ou X-Ademe-Edge transmis à l'origine : %v", i, h)
			}
		}
	})

	t.Run("rate limit par IP du visiteur", func(t *testing.T) {
		var got []int
		for _, ip := range []string{"198.51.100.20", "198.51.100.20", "198.51.100.20", "198.51.100.21"} {
			st, _ := do("/limite", noeud, secretFactice, ip)
			got = append(got, st)
		}
		for _, xff := range []string{"203.0.113.60", "203.0.113.60", "203.0.113.60"} {
			st, _ := do("/limite", xff, faux, "198.51.100.22")
			got = append(got, st)
		}
		if want := []int{200, 200, 429, 200, 200, 200, 429}; !slices.Equal(got, want) {
			t.Fatalf("statuts %v, attendu %v", got, want)
		}
	})

	t.Run("logs de Caddy", func(t *testing.T) {
		if st, _ := do("/coupe", noeud, secretFactice, "198.51.100.10"); st != 502 {
			t.Fatalf("statut %d, 502 attendu", st)
		}
		var req string
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			b, _ := os.ReadFile(filepath.Join(logs, "requetes.log"))
			if req = string(b); strings.Contains(req, `"/coupe"`) {
				break
			}
		}
		if !strings.Contains(req, `"/coupe"`) || !strings.Contains(req, `"client_ip":"198.51.100.10"`) || !strings.Contains(req, "Cf-Connecting-Ip") {
			t.Fatalf("log d'erreur du 502 absent ou incomplet :\n%s", req)
		}
		def, _ := os.ReadFile(filepath.Join(logs, "default.log"))
		for nom, s := range map[string]string{"requetes": req, "default": string(def)} {
			if strings.Contains(s, secretFactice) || strings.Contains(s, "X-Ademe-Edge") {
				t.Errorf("log %s avec X-Ademe-Edge :\n%s", nom, s)
			}
		}
		if strings.Contains(string(def), `"/coupe"`) {
			t.Errorf("log d'erreur aussi écrit dans le log par défaut :\n%s", def)
		}
	})
}
