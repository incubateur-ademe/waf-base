package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
)

const (
	testKey  = "cle-fgp-de-test-qui-ne-doit-jamais-sortir"
	testBlob = "blob-fgp-de-test-qui-ne-doit-jamais-sortir"
	ipProd   = "78.232.54.148"
	ipPP     = "78.232.51.183"
)

const testInventory = `
vms:
  "1": { stage: prod, ip: 78.232.54.148 }
  preprod: { stage: preprod, ip: 78.232.51.183 }
defaults:
  branch: main
  resources: { memory: 512M, cpu_weight: 64 }
apps:
  waf-pilote:
    repo: incubateur-ademe/waf-pilote
    platform: scalingo
    hosts: [waf-pilote.incubateur.ademe.dev]
    live: true
    stage: preprod
  tacct:
    repo: incubateur-ademe/tacct
    platform: scalingo
    hosts: [tacct.ademe.fr]
    host_header: upstream
    live: true
  brouillon:
    repo: incubateur-ademe/brouillon
    platform: scalingo
    hosts: [brouillon.example.org]
    stage: preprod
  koyo:
    repo: incubateur-ademe/koyo
    platform: koyeb
    hosts: [koyo.example.org]
    live: true
    stage: preprod
`

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func fgpJSON(regions ...string) string {
	api := map[string]string{}
	for _, r := range regions {
		api[r] = testBlob
	}
	b, _ := json.Marshal(map[string]any{"url": "https://fgp.example.org", "api": api})
	return string(b)
}

func fullEnv() map[string]string {
	return map[string]string{
		"COOLIFY_URL": "https://coolify.example.org", "COOLIFY_TOKEN": "t", "WAF_OPS_STAGES": "preprod",
		"WAF_OPS_FGP": fgpJSON("osc-fr1"), "WAF_OPS_FGP_KEY": testKey,
		"WAF_OPS_PULSE_URL": "https://pulse.example.org/p/secret-token",
	}
}

func TestConfig(t *testing.T) {
	_, err := LoadConfig(env(nil), ModeBoucle)
	if err == nil || err.Error() != "variables manquantes : COOLIFY_URL, COOLIFY_TOKEN, WAF_OPS_STAGES, WAF_OPS_FGP, WAF_OPS_FGP_KEY, WAF_OPS_PULSE_URL" {
		t.Fatalf("boucle : %v", err)
	}
	_, err = LoadConfig(env(nil), ModeControle)
	if err == nil || err.Error() != "variables manquantes : COOLIFY_URL, COOLIFY_TOKEN, WAF_OPS_STAGES, WAF_OPS_FGP, WAF_OPS_FGP_KEY" {
		t.Fatalf("controle : %v", err)
	}
	_, err = LoadConfig(env(nil), ModeScopes)
	if err == nil || err.Error() != "variables manquantes : COOLIFY_URL, COOLIFY_TOKEN, WAF_OPS_STAGES" {
		t.Fatalf("scopes : %v", err)
	}

	c, err := LoadConfig(env(fullEnv()), ModeBoucle)
	if err != nil {
		t.Fatal(err)
	}
	if c.Etc != "/etc/waf" || c.State != DefaultState || !strings.HasPrefix(c.Inventaire, "https://raw.githubusercontent.com/") {
		t.Fatalf("défauts : %+v", c)
	}
	if c.FGP.URL != "https://fgp.example.org" || c.FGP.Key != testKey || c.FGP.API["osc-fr1"] != testBlob || !c.Stages["preprod"] || c.Stages["prod"] {
		t.Fatalf("config : %+v", c)
	}

	cases := []struct{ nom, k, v, msg string }{
		{"stage inconnu", "WAF_OPS_STAGES", "preprod,recette", `stage "recette"`},
		{"FGP illisible", "WAF_OPS_FGP", `{"api":`, "JSON"},
		{"FGP champ inconnu", "WAF_OPS_FGP", `{"api":{"osc-fr1":"b"},"key":"x"}`, "JSON"},
		{"FGP sans blob", "WAF_OPS_FGP", `{"api":{}}`, "aucun blob"},
		{"FGP région", "WAF_OPS_FGP", `{"api":{"../x":"b"}}`, "région"},
		{"FGP blob à blanc", "WAF_OPS_FGP", `{"api":{"osc-fr1":"a b"}}`, "blancs"},
		{"FGP url http", "WAF_OPS_FGP", `{"url":"http://fgp.example.org","api":{"osc-fr1":"b"}}`, "https"},
		{"FGP url à chemin", "WAF_OPS_FGP", `{"url":"https://fgp.example.org/x","api":{"osc-fr1":"b"}}`, "https"},
		{"clé courte", "WAF_OPS_FGP_KEY", "courte", "WAF_OPS_FGP_KEY"},
		{"pulse http", "WAF_OPS_PULSE_URL", "http://pulse.example.org/p/secret-token", "WAF_OPS_PULSE_URL"},
	}
	for _, cs := range cases {
		t.Run(cs.nom, func(t *testing.T) {
			e := fullEnv()
			e[cs.k] = cs.v
			_, err := LoadConfig(env(e), ModeBoucle)
			if err == nil || !strings.Contains(err.Error(), cs.msg) {
				t.Fatalf("erreur = %v", err)
			}
			if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), testKey) {
				t.Fatalf("secret dans l'erreur : %v", err)
			}
		})
	}
}

func fgpServer(t *testing.T, h http.HandlerFunc) *FGPClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewFGPClient(FGP{URL: srv.URL, Key: testKey, API: map[string]string{"osc-fr1": testBlob}})
}

func TestFGPClient(t *testing.T) {
	var gotKey, gotBlob, gotPath string
	c := fgpServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotBlob, gotPath = r.Header.Get("X-FGP-Key"), r.Header.Get("X-FGP-Blob"), r.URL.Path
		switch {
		case r.Method != http.MethodGet:
			w.WriteHeader(405)
		case strings.HasSuffix(r.URL.Path, "/firewall_rules"):
			w.Header().Set("X-FGP-Source", "upstream")
			fmt.Fprint(w, `{"firewall_rules":[{"id":"afw-1","cidr":"78.232.51.183/32","label":"waf-preprod","app_id":"x"}]}`)
		case strings.HasSuffix(r.URL.Path, "/domains"):
			w.Header().Set("X-FGP-Source", "proxy")
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"scope_denied","key":"`+testKey+`"}`)
		}
	})
	rules, err := c.FirewallRules(context.Background(), "osc-fr1", "waf-pilote")
	if err != nil || len(rules) != 1 || rules[0].CIDR != ipPP+"/32" {
		t.Fatalf("règles : %+v, %v", rules, err)
	}
	if gotKey != testKey || gotBlob != testBlob || gotPath != "/v1/apps/waf-pilote/firewall_rules" {
		t.Fatalf("requête : %q %q %q", gotKey, gotBlob, gotPath)
	}
	_, err = c.Domains(context.Background(), "osc-fr1", "waf-pilote")
	var fe *FGPError
	if !errors.As(err, &fe) || fe.Source != "proxy" || fe.Status != 403 || !strings.Contains(err.Error(), "FGP refuse") {
		t.Fatalf("refus du proxy : %v", err)
	}
	if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), testBlob) {
		t.Fatalf("secret dans l'erreur : %v", err)
	}
	if _, err := c.Domains(context.Background(), "osc-secnum-fr1", "waf-pilote"); err == nil || !strings.Contains(err.Error(), "aucun blob") {
		t.Fatalf("région sans blob : %v", err)
	}
	gotPath = ""
	if _, err := c.FirewallRules(context.Background(), "osc-fr1", "../variables"); err == nil || gotPath != "" {
		t.Fatalf("nom d'app invalide appelé : %v %q", err, gotPath)
	}
	if err := c.get(context.Background(), "osc-fr1", "/v1/apps/waf-pilote/variables", &struct{}{}); err == nil || gotPath != "" {
		t.Fatalf("route hors liste appelée : %v %q", err, gotPath)
	}
}

func TestFGPInjoignable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	c := NewFGPClient(FGP{URL: u, Key: testKey, API: map[string]string{"osc-fr1": testBlob}})
	_, err := c.FirewallRules(context.Background(), "osc-fr1", "waf-pilote")
	if !errors.Is(err, ErrFGPInjoignable) || strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), testBlob) {
		t.Fatalf("erreur = %v", err)
	}
	if fgpProblem(err) != "FGP injoignable" {
		t.Fatalf("message : %q", fgpProblem(err))
	}
}

// fakeScalingo : règles et domaines par app, erreurs forcées par app.
type fakeScalingo struct {
	regions map[string]bool
	rules   map[string][]FirewallRule
	domains map[string][]Domain
	err     map[string]error
	calls   []string
}

func (f *fakeScalingo) HasRegion(r string) bool { return f.regions[r] }
func (f *fakeScalingo) FirewallRules(_ context.Context, region, app string) ([]FirewallRule, error) {
	f.calls = append(f.calls, "rules "+region+" "+app)
	if e := f.err[app]; e != nil {
		return nil, e
	}
	return f.rules[app], nil
}
func (f *fakeScalingo) Domains(_ context.Context, region, app string) ([]Domain, error) {
	f.calls = append(f.calls, "domains "+region+" "+app)
	if e := f.err[app]; e != nil {
		return nil, e
	}
	return f.domains[app], nil
}

type fakeTeam struct {
	envs []coolify.SharedEnv
	err  error
}

func (f fakeTeam) ListTeamEnvs(context.Context) ([]coolify.SharedEnv, error) { return f.envs, f.err }

// shared pose une variable d'équipe comme la renvoie Coolify : hidden pour un
// jeton sans read:sensitive (champ value absent).
func shared(t *testing.T, key, value string, hidden bool) coolify.SharedEnv {
	t.Helper()
	m := map[string]any{"id": 1, "key": key}
	if !hidden {
		m["value"] = value
	}
	b, _ := json.Marshal(m)
	var e coolify.SharedEnv
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func testCfg(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventaire.yaml")
	if err := os.WriteFile(inv, []byte(testInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Inventaire: inv, Etc: "../..", Stages: map[string]bool{"preprod": true}, State: filepath.Join(dir, "etat")}
}

func pilotDeps(t *testing.T, rules ...string) (Deps, *fakeScalingo) {
	t.Helper()
	var fr []FirewallRule
	for i, r := range rules {
		fr = append(fr, FirewallRule{ID: fmt.Sprintf("afw-%d", i), CIDR: r})
	}
	s := &fakeScalingo{
		regions: map[string]bool{"osc-fr1": true},
		rules:   map[string][]FirewallRule{"waf-pilote": fr},
		domains: map[string][]Domain{"waf-pilote": {{Name: "waf-pilote.incubateur.ademe.dev"}}},
		err:     map[string]error{},
	}
	team := fakeTeam{envs: []coolify.SharedEnv{
		shared(t, "UPSTREAM_WAF_PILOTE", "https://waf-pilote.osc-fr1.scalingo.io", false),
		shared(t, "LOCK_WAF_PILOTE", "2026-11-13T21:10:28Z", false),
		shared(t, "UPSTREAM_TACCT", "https://tacct-prod.osc-secnum-fr1.scalingo.io", false),
	}}
	return Deps{Coolify: team, Scalingo: s, Now: time.Now}, s
}

func TestControleConforme(t *testing.T) {
	d, s := pilotDeps(t, ipPP+"/32")
	r, err := Controle(context.Background(), testCfg(t), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Ecarts) != 0 || r.Apps != 1 {
		t.Fatalf("rapport : %+v", r)
	}
	if strings.Join(s.calls, ",") != "rules osc-fr1 waf-pilote,domains osc-fr1 waf-pilote" {
		t.Fatalf("appels : %v (tacct, en prod, et koyo, sur Koyeb, hors champ)", s.calls)
	}
	notes := strings.Join(r.Notes, "\n")
	if !strings.Contains(notes, "brouillon : pas en service") || !strings.Contains(notes, "koyo : plateforme koyeb") {
		t.Fatalf("notes : %v", r.Notes)
	}
	if PulseBody(r, nil) != PulseOK {
		t.Fatalf("pulse : %q", PulseBody(r, nil))
	}
}

func TestControleEcarts(t *testing.T) {
	cases := []struct {
		nom   string
		rules []string
		setup func(*testing.T, *Deps, *fakeScalingo)
		ecart string
	}{
		{"règle de waf-1 en trop", []string{ipPP + "/32", ipProd + "/32"}, nil, "waf-pilote : règles du firewall de waf-pilote (osc-fr1) : en trop " + ipProd + "/32"},
		{"règle manquante", nil, nil, "waf-pilote : règles du firewall de waf-pilote (osc-fr1) : manquantes " + ipPP + "/32"},
		{"règle tierce", []string{ipPP + "/32", "0.0.0.0/0"}, nil, "en trop 0.0.0.0/0"},
		{"host détaché", []string{ipPP + "/32"}, func(t *testing.T, d *Deps, s *fakeScalingo) {
			s.domains["waf-pilote"] = []Domain{{Name: "autre.example.org"}}
		}, "waf-pilote : host waf-pilote.incubateur.ademe.dev non rattaché à waf-pilote (osc-fr1)"},
		{"FGP injoignable", []string{ipPP + "/32"}, func(t *testing.T, d *Deps, s *fakeScalingo) {
			s.err["waf-pilote"] = fmt.Errorf("%w : GET x : timeout", ErrFGPInjoignable)
		}, "règles du firewall de waf-pilote (osc-fr1) : FGP injoignable"},
		{"région sans blob", []string{ipPP + "/32"}, func(t *testing.T, d *Deps, s *fakeScalingo) {
			s.regions = map[string]bool{}
		}, "waf-pilote : aucun blob FGP pour la région osc-fr1"},
		{"UPSTREAM absente", nil, func(t *testing.T, d *Deps, s *fakeScalingo) {
			d.Coolify = fakeTeam{}
		}, "waf-pilote : UPSTREAM_WAF_PILOTE absente des variables d'équipe"},
		{"UPSTREAM illisible", nil, func(t *testing.T, d *Deps, s *fakeScalingo) {
			d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "UPSTREAM_WAF_PILOTE", "", true)}}
		}, "UPSTREAM_WAF_PILOTE illisible"},
		{"UPSTREAM hors Scalingo", nil, func(t *testing.T, d *Deps, s *fakeScalingo) {
			d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "UPSTREAM_WAF_PILOTE", "https://evil.example.org", false)}}
		}, "UPSTREAM_WAF_PILOTE : hôte hors de *.<région>.scalingo.io"},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			d, s := pilotDeps(t, c.rules...)
			if c.setup != nil {
				c.setup(t, &d, s)
			}
			r, err := Controle(context.Background(), testCfg(t), d)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Ecarts) == 0 || !strings.Contains(strings.Join(r.Ecarts, "\n"), c.ecart) {
				t.Fatalf("écarts : %v, attendu %q", r.Ecarts, c.ecart)
			}
			if b := PulseBody(r, nil); !strings.HasPrefix(b, "waf-ops-ko: ") || strings.Contains(b, PulseOK) {
				t.Fatalf("pulse : %q", b)
			}
		})
	}
}

func TestControleSansVerrou(t *testing.T) {
	d, s := pilotDeps(t, "0.0.0.0/0")
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "UPSTREAM_WAF_PILOTE", "https://waf-pilote.osc-fr1.scalingo.io", false)}}
	r, err := Controle(context.Background(), testCfg(t), d)
	if err != nil || len(r.Ecarts) != 0 {
		t.Fatalf("écarts : %v, %v", r.Ecarts, err)
	}
	if strings.Join(s.calls, ",") != "domains osc-fr1 waf-pilote" || !strings.Contains(strings.Join(r.Notes, "\n"), "sans LOCK_WAF_PILOTE") {
		t.Fatalf("appels %v, notes %v", s.calls, r.Notes)
	}

	// Un verrou illisible compte comme posé.
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{
		shared(t, "UPSTREAM_WAF_PILOTE", "https://waf-pilote.osc-fr1.scalingo.io", false),
		shared(t, "LOCK_WAF_PILOTE", "", true),
	}}
	r, _ = Controle(context.Background(), testCfg(t), d)
	if !strings.Contains(strings.Join(r.Ecarts, "\n"), "en trop 0.0.0.0/0") {
		t.Fatalf("verrou illisible : %v", r.Ecarts)
	}
}

func TestControleStageProd(t *testing.T) {
	d, s := pilotDeps(t)
	s.regions["osc-secnum-fr1"] = true
	s.rules["tacct-prod"] = []FirewallRule{{CIDR: ipProd + "/32"}}
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{
		shared(t, "UPSTREAM_TACCT", "https://tacct-prod.osc-secnum-fr1.scalingo.io", false),
		shared(t, "LOCK_TACCT", "2026-11-19T16:59:43Z", false),
	}}
	cfg := testCfg(t)
	cfg.Stages = map[string]bool{"prod": true}
	r, err := Controle(context.Background(), cfg, d)
	if err != nil || len(r.Ecarts) != 0 || r.Apps != 1 {
		t.Fatalf("rapport : %+v, %v", r, err)
	}
	if strings.Join(s.calls, ",") != "rules osc-secnum-fr1 tacct-prod" {
		t.Fatalf("appels : %v (tacct en upstream : pas de contrôle des hosts)", s.calls)
	}
}

func TestInventaireEnCache(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32")
	if _, err := Controle(context.Background(), cfg, d); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.Inventaire); err != nil {
		t.Fatal(err)
	}
	r, err := Controle(context.Background(), cfg, d)
	if err != nil || len(r.Ecarts) != 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "cache utilisé") {
		t.Fatalf("cache frais : %+v, %v", r, err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(filepath.Join(cfg.State, inventoryCache), old, old); err != nil {
		t.Fatal(err)
	}
	r, err = Controle(context.Background(), cfg, d)
	if err != nil || !strings.Contains(strings.Join(r.Ecarts, "\n"), "inventaire non rafraîchi depuis 24 h") {
		t.Fatalf("cache périmé : %+v, %v", r, err)
	}
	if err := os.Remove(filepath.Join(cfg.State, inventoryCache)); err != nil {
		t.Fatal(err)
	}
	if _, err := Controle(context.Background(), cfg, d); err == nil || !strings.Contains(err.Error(), "sans cache") {
		t.Fatalf("sans cache : %v", err)
	}
}

func TestPulseBody(t *testing.T) {
	if b := PulseBody(Rapport{}, errors.New("inventaire illisible et sans cache")); b != "waf-ops-ko: inventaire illisible et sans cache" {
		t.Fatalf("erreur : %q", b)
	}
	long := Rapport{Ecarts: []string{strings.Repeat("é", 3000)}}
	b := PulseBody(long, nil)
	if len(b) > maxPulseBody || !utf8.ValidString(b) || !strings.HasSuffix(b, "…") {
		t.Fatalf("troncature : %d octets, valide %t", len(b), utf8.ValidString(b))
	}
}

func TestHTTPPulse(t *testing.T) {
	var got string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		got = r.Method + " " + b.String()
		w.WriteHeader(status)
	}))
	defer srv.Close()
	p := HTTPPulse{URL: srv.URL + "/p/secret-token"}
	if err := p.Send(context.Background(), PulseOK); err != nil || got != "POST "+PulseOK {
		t.Fatalf("envoi : %q, %v", got, err)
	}
	status = 500
	if err := p.Send(context.Background(), PulseOK); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("erreur : %v", err)
	}
	srv.Close()
	if err := p.Send(context.Background(), PulseOK); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("erreur réseau : %v", err)
	}
}

type fakePulse struct{ bodies []string }

func (f *fakePulse) Send(_ context.Context, b string) error {
	f.bodies = append(f.bodies, b)
	return nil
}

func TestPassage(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32", ipProd+"/32")
	p := &fakePulse{}
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	Passage(context.Background(), cfg, d, p, logf)
	if len(p.bodies) != 1 || !strings.HasPrefix(p.bodies[0], "waf-ops-ko: waf-pilote : règles") {
		t.Fatalf("pulse : %v", p.bodies)
	}
	b, err := os.ReadFile(filepath.Join(cfg.State, etatFile))
	if err != nil {
		t.Fatal(err)
	}
	var e Etat
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	if e.Controle.Apps != 1 || len(e.Controle.Ecarts) != 1 || e.Controle.Pulse != "waf-ops-ko" || e.Controle.A.IsZero() {
		t.Fatalf("état : %+v", e)
	}
	if st, _ := os.Stat(filepath.Join(cfg.State, etatFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("droits de l'état : %v", st.Mode())
	}
	if !strings.Contains(strings.Join(logs, "\n"), "contrôle : 1 app(s), 1 écart(s)") {
		t.Fatalf("logs : %v", logs)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Passage(ctx, cfg, d, p, logf)
	if len(p.bodies) != 1 {
		t.Fatalf("pulse envoyé pendant l'arrêt : %v", p.bodies)
	}
}

func TestScopes(t *testing.T) {
	cfg := testCfg(t)
	cfg.Stages = map[string]bool{"prod": true, "preprod": true}
	d, _ := pilotDeps(t)
	s, err := Scopes(context.Background(), cfg, d.Coolify)
	if err == nil || !strings.Contains(err.Error(), "brouillon : UPSTREAM_BROUILLON absente ou illisible") {
		t.Fatalf("UPSTREAM manquante : %v", err)
	}
	cfg.Stages = map[string]bool{"preprod": true}
	team := d.Coolify.(fakeTeam)
	team.envs = append(team.envs, shared(t, "UPSTREAM_BROUILLON", "https://brouillon.osc-fr1.scalingo.io", false))
	s, err = Scopes(context.Background(), cfg, team)
	if err != nil {
		t.Fatal(err)
	}
	fr1, ok := s["osc-fr1"]
	if len(s) != 1 || !ok || fr1.Target != "https://api.osc-fr1.scalingo.com" || fr1.Auth != "scalingo-exchange" || fr1.TTL != 31536000 {
		t.Fatalf("scopes : %+v", s)
	}
	want := "GET:/v1/apps/brouillon/firewall_rules,GET:/v1/apps/brouillon/domains,GET:/v1/apps/brouillon/events," +
		"GET:/v1/apps/waf-pilote/firewall_rules,GET:/v1/apps/waf-pilote/domains,GET:/v1/apps/waf-pilote/events"
	if strings.Join(fr1.Scopes, ",") != want {
		t.Fatalf("scopes : %v", fr1.Scopes)
	}
}

func TestMainUsage(t *testing.T) {
	var out, errw bytes.Buffer
	if err := Main(context.Background(), []string{"inconnue"}, env(fullEnv()), &out, &errw); err == nil || !strings.Contains(errw.String(), "wafgen ops") {
		t.Fatalf("usage : %v %q", err, errw.String())
	}
	if err := Main(context.Background(), []string{"controle", "x"}, env(fullEnv()), &out, &errw); err == nil {
		t.Fatal("argument en trop accepté")
	}
	if err := Main(context.Background(), nil, env(nil), &out, &errw); err == nil || !strings.Contains(err.Error(), "WAF_OPS_PULSE_URL") {
		t.Fatalf("boucle sans variables : %v", err)
	}
}

func TestMainScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/team/envs" || r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `[{"id":1,"key":"UPSTREAM_WAF_PILOTE","value":"https://waf-pilote.osc-fr1.scalingo.io"},{"id":2,"key":"UPSTREAM_BROUILLON","value":"https://brouillon.osc-fr1.scalingo.io"}]`)
	}))
	defer srv.Close()
	cfg := testCfg(t)
	e := map[string]string{"COOLIFY_URL": srv.URL, "COOLIFY_TOKEN": "t", "WAF_OPS_STAGES": "preprod",
		"WAF_OPS_INVENTAIRE": cfg.Inventaire, "WAF_OPS_ETC": "../..", "WAF_OPS_STATE": cfg.State}
	var out, errw bytes.Buffer
	if err := Main(context.Background(), []string{"fgp-scopes"}, env(e), &out, &errw); err != nil {
		t.Fatalf("%v\n%s", err, errw.String())
	}
	var s map[string]BlobRequest
	if err := json.Unmarshal(out.Bytes(), &s); err != nil || len(s["osc-fr1"].Scopes) != 6 {
		t.Fatalf("sortie : %v\n%s", err, out.String())
	}
}
