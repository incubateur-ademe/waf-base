package render

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const secretFactice = "secret-edge-factice-0123456789abcdef-ABCDEF"

func ipValide(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

func TestEdgeIP(t *testing.T) {
	re := regexp.MustCompile(edgeIP)
	cases := map[string]bool{
		"203.0.113.7": true, "0.0.0.0": true, "255.255.255.255": true, "::": true, "::1": true, "1::": true,
		"2001:db8::1": true, "2001:DB8:0:0:0:0:0:1": true, "1:2:3:4:5:6:7::": true, "::2:3:4:5:6:7:8": true,
		"::ffff:192.0.2.1": true, "::192.0.2.1": true, "1:2:3:4:5:6:192.0.2.1": true, "1::6:192.0.2.1": true,
		"": false, " 203.0.113.7": false, "203.0.113.7 ": false, "203.0.113.7\n": false,
		"203.0.113.7,198.51.100.1": false, "203.0.113.7, 198.51.100.1": false, "256.0.0.1": false, "01.2.3.4": false,
		"1.2.3": false, "1.2.3.4.5": false, "fe80::1%eth0": false, "1:2:3:4:5:6:7:8:9": false, "1::2::3": false,
		":::": false, "12345::": false, "1:2:3:4:5:6:7:1.2.3.4": false, "[::1]": false, "::1/128": false,
		"unknown": false, "{env.WAF_EDGE_SECRET}": false,
	}
	for s, want := range cases {
		if got := re.MatchString(s); got != want || got != ipValide(s) {
			t.Errorf("%q : regexp %v, attendu %v, netip %v", s, got, want, ipValide(s))
		}
	}
	// Formes produites par netip, puis mutées : la regexp et netip.ParseAddr
	// doivent rester d'accord sur chaque chaîne.
	r := rand.New(rand.NewPCG(5737, 4291))
	const alphabet = "0123456789abcdefABCDEF:.% ,"
	mutate := func(s string) string {
		b := []byte(s)
		for range 1 + r.IntN(3) {
			i := r.IntN(len(b) + 1)
			c := alphabet[r.IntN(len(alphabet))]
			switch r.IntN(4) {
			case 0:
				b = append(b[:i], append([]byte{c}, b[i:]...)...)
			case 1:
				if i < len(b) {
					b = append(b[:i], b[i+1:]...)
				}
			case 2:
				if i < len(b) {
					b[i] = c
				}
			case 3:
				b = append(b[:i], append([]byte("::"), b[i:]...)...)
			}
		}
		return string(b)
	}
	for range 30000 {
		var raw [16]byte
		for g := 0; g < 16; g += 2 {
			if r.IntN(2) == 0 {
				raw[g], raw[g+1] = byte(r.Uint32()), byte(r.Uint32())
			}
		}
		v6 := netip.AddrFrom16(raw)
		v4 := netip.AddrFrom4([4]byte(raw[12:]))
		mapped := netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: raw[12], 13: raw[13], 14: raw[14], 15: raw[15]})
		for _, s := range []string{v4.String(), v6.String(), v6.StringExpanded(), mapped.String()} {
			if !re.MatchString(s) {
				t.Fatalf("%q valide refusée", s)
			}
			m := mutate(s)
			if re.MatchString(m) != ipValide(m) {
				t.Fatalf("%q : regexp %v, netip %v", m, re.MatchString(m), ipValide(m))
			}
		}
	}
}

func edgeInput() *Input {
	in := testInput(tacctHosts, "tacct.ademe.fr", "upstream")
	in.Edge = EdgeCloudflare
	return in
}

func outerRoutes(t *testing.T, in *Input) []json.RawMessage {
	t.Helper()
	var site struct {
		Handle []struct {
			Routes []json.RawMessage `json:"routes"`
		} `json:"handle"`
	}
	if err := json.Unmarshal(siteJSON(t, in), &site); err != nil {
		t.Fatal(err)
	}
	return site.Handle[0].Routes
}

func TestEdgeRoutes(t *testing.T) {
	edge := outerRoutes(t, edgeInput())
	sans := outerRoutes(t, testInput(tacctHosts, "tacct.ademe.fr", "upstream"))
	if len(edge) != len(sans)+1 {
		t.Fatalf("%d routes, %d attendues : la route du secret en tête", len(edge), len(sans)+1)
	}
	var first struct {
		Match []struct {
			Header       map[string][]string `json:"header"`
			HeaderRegexp map[string]struct {
				Name    string `json:"name"`
				Pattern string `json:"pattern"`
			} `json:"header_regexp"`
		} `json:"match"`
		Handle   []map[string]any `json:"handle"`
		Terminal bool             `json:"terminal"`
	}
	if err := json.Unmarshal(edge[0], &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Match) != 1 || !reflect.DeepEqual(first.Match[0].Header, map[string][]string{"X-Ademe-Edge": {"{env.WAF_EDGE_SECRET}"}}) {
		t.Fatalf("matcher du secret : %s", edge[0])
	}
	hr := first.Match[0].HeaderRegexp
	if len(hr) != 1 || hr["CF-Connecting-IP"].Name != "waf_edge" || hr["CF-Connecting-IP"].Pattern != edgeIP {
		t.Fatalf("matcher de CF-Connecting-IP : %s", edge[0])
	}
	want := []map[string]any{{"handler": "vars", "client_ip": "{http.regexp.waf_edge.0}"}}
	if !reflect.DeepEqual(first.Handle, want) || first.Terminal {
		t.Fatalf("remplacement de client_ip : %s", edge[0])
	}
	strip := `{"handle":[{"handler":"headers","request":{"delete":["X-Ademe-Edge"]}}]}`
	if string(edge[1]) != strip || string(sans[0]) != strip {
		t.Fatalf("retrait de X-Ademe-Edge avant Coraza, avec et sans edge : %s, %s", edge[1], sans[0])
	}
	rest, err := json.Marshal(edge[1:])
	if err != nil {
		t.Fatal(err)
	}
	ref, err := json.Marshal(sans)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, ref) {
		t.Fatalf("hors de la route du secret, une app edge et une app sans edge doivent avoir la même conf")
	}
	if bytes.Count(ref, []byte(`"delete":["CF-Connecting-IP","X-Ademe-Edge"]`)) != 1 {
		t.Fatalf("reverse_proxy sans retrait de CF-Connecting-IP et X-Ademe-Edge vers l'origine")
	}
	if strings.Contains(string(siteJSON(t, edgeInput())), secretFactice) {
		t.Fatal("secret dans la conf rendue")
	}
}

func TestEdgeMatchers(t *testing.T) {
	t.Setenv("WAF_EDGE_SECRET", secretFactice)
	var route struct {
		Match []map[string]json.RawMessage `json:"match"`
	}
	if err := json.Unmarshal(outerRoutes(t, edgeInput())[0], &route); err != nil {
		t.Fatal(err)
	}
	var header caddyhttp.MatchHeader
	var headerRE caddyhttp.MatchHeaderRE
	if err := json.Unmarshal(route.Match[0]["header"], &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(route.Match[0]["header_regexp"], &headerRE); err != nil {
		t.Fatal(err)
	}
	if err := headerRE.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := headerRE.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		nom     string
		edge    []string
		ip      []string
		attendu string
	}{
		{"secret et IPv4", []string{secretFactice}, []string{"203.0.113.9"}, "203.0.113.9"},
		{"secret et IPv6", []string{secretFactice}, []string{"2001:db8::9"}, "2001:db8::9"},
		{"secret parmi deux valeurs", []string{"faux", secretFactice}, []string{"203.0.113.9"}, "203.0.113.9"},
		{"IP valide après une valeur invalide", []string{secretFactice}, []string{"nimporte", "203.0.113.9"}, "203.0.113.9"},
		{"sans secret", nil, []string{"203.0.113.9"}, ""},
		{"secret faux", []string{"secret-edge-factice-0123456789abcdef-ABCDEX"}, []string{"203.0.113.9"}, ""},
		{"secret préfixe", []string{secretFactice[:40]}, []string{"203.0.113.9"}, ""},
		{"secret suivi d'un caractère", []string{secretFactice + "x"}, []string{"203.0.113.9"}, ""},
		{"secret vide", []string{""}, []string{"203.0.113.9"}, ""},
		{"secret sans IP", []string{secretFactice}, nil, ""},
		{"liste d'IP", []string{secretFactice}, []string{"203.0.113.9, 198.51.100.1"}, ""},
		{"IP avec zone", []string{secretFactice}, []string{"fe80::1%eth0"}, ""},
		{"placeholder", []string{secretFactice}, []string{"{env.WAF_EDGE_SECRET}"}, ""},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "http://tacct.ademe.fr/", nil)
			for _, v := range c.edge {
				r.Header.Add("X-Ademe-Edge", v)
			}
			for _, v := range c.ip {
				r.Header.Add("CF-Connecting-IP", v)
			}
			repl := caddy.NewReplacer()
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			h, err := header.MatchWithError(r)
			if err != nil {
				t.Fatal(err)
			}
			re, err := headerRE.MatchWithError(r)
			if err != nil {
				t.Fatal(err)
			}
			if got := h && re; got != (c.attendu != "") {
				t.Fatalf("route d'edge prise : %v (secret %v, IP %v)", got, h, re)
			}
			if c.attendu == "" {
				return
			}
			if v, _ := repl.GetString("http.regexp.waf_edge.0"); v != c.attendu {
				t.Fatalf("client_ip deviendrait %q, attendu %q", v, c.attendu)
			}
		})
	}
}

func TestEdgeLogging(t *testing.T) {
	t.Run("edge", func(t *testing.T) { edgeLoggingDe(t, edgeInput()) })
	t.Run("sans edge", func(t *testing.T) { edgeLoggingDe(t, testInput(tacctHosts, "", "visitor")) })
}

func edgeLoggingDe(t *testing.T, in *Input) {
	b, err := Caddy([]byte(`{"apps":{"http":{"servers":{"srv1":{"listen":[":8080"]}}}}}`), in)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Logging struct {
			Logs map[string]struct {
				Include []string `json:"include"`
				Exclude []string `json:"exclude"`
				Encoder struct {
					Format string                       `json:"format"`
					Wrap   map[string]string            `json:"wrap"`
					Fields map[string]map[string]string `json:"fields"`
				} `json:"encoder"`
			} `json:"logs"`
		} `json:"logging"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	names := []string{"http.log.access", "http.log.error"}
	def, req := cfg.Logging.Logs["default"], cfg.Logging.Logs["requetes"]
	if len(cfg.Logging.Logs) != 2 || !reflect.DeepEqual(def.Exclude, names) || !reflect.DeepEqual(req.Include, names) {
		t.Fatalf("logs : %+v", cfg.Logging.Logs)
	}
	e := req.Encoder
	if e.Format != "filter" || e.Wrap["format"] != "json" || !reflect.DeepEqual(e.Fields, map[string]map[string]string{"request>headers>X-Ademe-Edge": {"filter": "delete"}}) {
		t.Fatalf("encodeur : %+v", e)
	}

	_, err = Caddy([]byte(`{"logging":{"logs":{}},"apps":{"http":{"servers":{"srv1":{"listen":[":8080"]}}}}}`), in)
	if err == nil || !strings.Contains(err.Error(), "logging") {
		t.Fatalf("bloc logging de la base écrasé : %v", err)
	}
}

func TestEdgeRefuse(t *testing.T) {
	in := testInput(tacctHosts, "", "visitor")
	in.Edge = "fastly"
	if _, err := SiteRoute(in); err == nil || !strings.Contains(err.Error(), "WAF_EDGE") {
		t.Fatalf("erreur = %v", err)
	}
}
