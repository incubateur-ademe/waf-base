package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/cloudflare/cftest"
	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	token  = "jeton-cloudflare-de-test-qui-ne-doit-jamais-sortir"
	secret = "secret-edge-factice-0123456789abcdef-ABCDEF"
	zid    = "0123456789abcdef0123456789abcdef"
	rsid   = "fedcba9876543210fedcba9876543210"
)

var ctx = context.Background()

func TestRoutes(t *testing.T) {
	ok := []struct{ m, p string }{
		{"GET", "/client/v4/zones"},
		{"GET", "/client/v4/zones/" + zid + "/rulesets/phases/http_request_late_transform/entrypoint"},
		{"POST", "/client/v4/zones/" + zid + "/rulesets"},
		{"POST", "/client/v4/zones/" + zid + "/rulesets/" + rsid + "/rules"},
		{"PATCH", "/client/v4/zones/" + zid + "/rulesets/" + rsid + "/rules/" + zid},
	}
	for _, r := range ok {
		if !cloudflare.Allowed(r.m, r.p) {
			t.Errorf("%s %s refusée", r.m, r.p)
		}
	}
	ko := []struct{ m, p string }{
		{"PUT", "/client/v4/zones/" + zid + "/rulesets/phases/http_request_late_transform/entrypoint"},
		{"PUT", "/client/v4/zones/" + zid + "/rulesets/" + rsid},
		{"DELETE", "/client/v4/zones/" + zid + "/rulesets/" + rsid + "/rules/" + zid},
		{"DELETE", "/client/v4/zones/" + zid + "/rulesets/" + rsid},
		{"PATCH", "/client/v4/zones/" + zid + "/rulesets/" + rsid},
		{"GET", "/client/v4/zones/" + zid + "/rulesets/phases/http_request_firewall_custom/entrypoint"},
		{"GET", "/client/v4/zones/" + zid + "/dns_records"},
		{"POST", "/client/v4/zones"},
		{"GET", "/client/v4/zones/../accounts"},
		{"GET", "/client/v4/zones/" + strings.ToUpper(zid) + "/rulesets/phases/http_request_late_transform/entrypoint"},
		{"GET", "/client/v4/user/tokens/verify"},
	}
	for _, r := range ko {
		if cloudflare.Allowed(r.m, r.p) {
			t.Errorf("%s %s acceptée", r.m, r.p)
		}
	}
}

func TestNewAt(t *testing.T) {
	for _, u := range []string{"https://api.cloudflare.com", "http://127.0.0.1:8080", "http://[::1]:9"} {
		if _, err := cloudflare.NewAt(u, token); err != nil {
			t.Errorf("%s refusée : %v", u, err)
		}
	}
	for _, u := range []string{"http://api.cloudflare.com", "http://localhost:80", "https://api.cloudflare.com/client/v4", "https://u:p@api.cloudflare.com", "ftp://x", "https://x?a=b", "api.cloudflare.com"} {
		if _, err := cloudflare.NewAt(u, token); err == nil {
			t.Errorf("%s acceptée", u)
		}
	}
	for _, tok := range []string{"", "a b", "a\nb", strings.Repeat("a", 513)} {
		if _, err := cloudflare.NewAt("https://api.cloudflare.com", tok); err == nil {
			t.Errorf("jeton %q accepté", tok)
		} else if tok != "" && strings.Contains(err.Error(), tok) {
			t.Errorf("jeton cité dans l'erreur : %v", err)
		}
	}
}

func client(t *testing.T, url string) *cloudflare.Client {
	t.Helper()
	c, err := cloudflare.NewAt(url, token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestJetonEnEnTeteEtErreurSansCorps(t *testing.T) {
	var auth, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, query = r.Header.Get("Authorization"), r.URL.RawQuery
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":20021,"message":"refus de ` + secret + ` pour ` + token + `"}],"result":null}`))
	}))
	defer srv.Close()
	_, err := client(t, srv.URL).Zone(ctx, "tacct.ademe.fr")
	if auth != "Bearer "+token || strings.Contains(query, token) || query != "name=tacct.ademe.fr&per_page=50" {
		t.Fatalf("Authorization %q, query %q", auth, query)
	}
	var he *cloudflare.HTTPError
	if !errors.As(err, &he) || he.Status != 400 || len(he.Codes) != 1 || he.Codes[0] != 20021 {
		t.Fatalf("erreur : %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "refus de") {
		t.Fatalf("corps repris dans l'erreur : %v", err)
	}
}

func TestSuccesFauxEtReponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"success false", `{"success":false,"errors":[{"code":9109,"message":"` + secret + `"}],"result":[]}`, 200, "codes 9109"},
		{"illisible", `<html>` + secret, 200, "réponse illisible"},
		{"redirection", ``, 302, "HTTP 302"},
		{"jeton refusé", `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`, 403, "permission absente"},
		{"trop grosse", `{"success":true,"result":[` + strings.Repeat(" ", 4<<20) + `]}`, 200, "réponse de plus de"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if tc.status == 302 {
					http.Redirect(w, r, "https://evil.example/?k="+secret, http.StatusFound)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := client(t, srv.URL).Zone(ctx, "tacct.ademe.fr")
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), secret) {
				t.Fatalf("erreur : %v", err)
			}
			if hits != 1 {
				t.Fatalf("%d requêtes, redirection suivie ?", hits)
			}
		})
	}
}

func TestZone(t *testing.T) {
	f := cftest.New(t, token)
	id := f.AddZone("tacct.ademe.fr")
	c := client(t, f.URL)
	z, err := c.Zone(ctx, "tacct.ademe.fr")
	if err != nil || z.ID != id || z.Name != "tacct.ademe.fr" {
		t.Fatalf("zone : %+v, %v", z, err)
	}
	if _, err := c.Zone(ctx, "ademe.fr"); !errors.Is(err, cloudflare.ErrZoneAbsente) {
		t.Fatalf("zone absente : %v", err)
	}
	if _, err := c.Zone(ctx, `x" or "1`); err == nil || len(f.Requests) != 2 {
		t.Fatalf("zone invalide envoyée : %v, %v", err, f.Requests)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"` + zid + `","name":"a.fr"},{"id":"` + rsid + `","name":"a.fr"},{"id":"` + zid + `","name":"b.a.fr"}]}`))
	}))
	defer srv.Close()
	if _, err := client(t, srv.URL).Zone(ctx, "a.fr"); err == nil || !strings.Contains(err.Error(), "2 zones") {
		t.Fatalf("deux zones : %v", err)
	}
}

func koyo(zones ...string) inventory.App {
	return inventory.App{Name: "koyo", Edge: "cloudflare", Live: true, Hosts: []string{"www.koyo.example.org", "koyo.example.org", "koyo.beta.gouv.fr"}, EdgeZones: zones}
}

func want() cloudflare.Want {
	return cloudflare.Wants(koyo("koyo.example.org"), secret)[0]
}

func TestExpressionEtCorps(t *testing.T) {
	w := want()
	expr, err := w.Expression()
	if err != nil || expr != `(http.host in {"koyo.example.org" "www.koyo.example.org"})` || w.Ref() != "waf-edge-koyo" {
		t.Fatalf("expression %q, ref %q, %v", expr, w.Ref(), err)
	}
	for _, bad := range [][]string{nil, {"autre.example.org"}, {`koyo.example.org" or true or "`}, {"KOYO.example.org"}} {
		w := cloudflare.Want{App: "koyo", Zone: "koyo.example.org", Hosts: bad, Secret: secret}
		if _, err := w.Expression(); err == nil {
			t.Errorf("hosts %q acceptés", bad)
		}
	}
	f := cftest.New(t, token)
	f.AddZone("koyo.example.org")
	c := client(t, f.URL)
	z, _ := c.Zone(ctx, "koyo.example.org")
	for _, s := range []string{"", "court", strings.Repeat("a", 31), secret + "$"} {
		w := want()
		w.Secret = s
		if _, err := c.CreateEntrypoint(ctx, z.ID, w); err == nil || strings.Contains(err.Error(), "court") {
			t.Errorf("secret %q accepté ou cité : %v", s, err)
		}
	}
	if n := len(f.Writes()); n != 0 {
		t.Fatalf("%d écritures avec un secret hors format", n)
	}
	rs, err := c.CreateEntrypoint(ctx, z.ID, want())
	if err != nil || len(rs.Rules) != 1 {
		t.Fatalf("création : %v", err)
	}
	r := f.Rules("koyo.example.org")[0]
	h := r["action_parameters"].(map[string]any)["headers"].(map[string]any)["X-Ademe-Edge"].(map[string]any)
	if r["ref"] != "waf-edge-koyo" || r["action"] != "rewrite" || r["enabled"] != true || h["operation"] != "set" || h["value"] != secret || len(h) != 2 {
		t.Fatalf("règle posée : %v", r)
	}
	if _, err := c.CreateEntrypoint(ctx, z.ID, want()); err == nil {
		t.Fatal("second entrypoint créé")
	}
}

func rule(ref, expr string, enabled bool, headers map[string]any) map[string]any {
	return map[string]any{"ref": ref, "expression": expr, "action": "rewrite", "enabled": enabled,
		"description": "règle manuelle " + secret, "action_parameters": map[string]any{"headers": headers}}
}

func set(v string) map[string]any { return map[string]any{"operation": "set", "value": v} }

const expr = `(http.host in {"koyo.example.org" "www.koyo.example.org"})`

func TestDiff(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    map[string]any
		want string
	}{
		{"conforme", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret)}), ""},
		{"blancs", rule("waf-edge-koyo", "(http.host in {\"koyo.example.org\"  \"www.koyo.example.org\"})\n", true, map[string]any{"x-ademe-edge": set(secret)}), ""},
		{"expression", rule("waf-edge-koyo", `(http.host contains "koyo")`, true, map[string]any{"X-Ademe-Edge": set(secret)}), "expression différente de " + expr},
		{"valeur", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set("autre-" + secret)}), "valeur de X-Ademe-Edge différente du secret de l'app"},
		{"désactivée", rule("waf-edge-koyo", expr, false, map[string]any{"X-Ademe-Edge": set(secret)}), "règle désactivée"},
		{"absent", rule("waf-edge-koyo", expr, true, map[string]any{"X-Autre": set(secret)}), "X-Ademe-Edge absent de la règle ; la règle réécrit autre chose que X-Ademe-Edge"},
		{"dynamique", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": map[string]any{"operation": "set", "expression": "cf.ray_id"}}), "X-Ademe-Edge sans valeur fixe posée par set"},
		{"add", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": map[string]any{"operation": "add", "value": secret}}), "X-Ademe-Edge sans valeur fixe posée par set"},
		{"autre en-tête", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret), "X-Autre": set("1")}), "la règle réécrit autre chose que X-Ademe-Edge"},
		{"deux casses", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret), "x-ademe-edge": set(secret)}), "X-Ademe-Edge présent plusieurs fois"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := cftest.New(t, token)
			f.AddZone("koyo.example.org")
			f.AddRule("koyo.example.org", tc.r)
			st, err := cloudflare.ReadZone(ctx, client(t, f.URL), "koyo.example.org")
			if err != nil {
				t.Fatal(err)
			}
			cur, err := st.Managed("waf-edge-koyo")
			if err != nil || cur == nil {
				t.Fatalf("règle gérée : %v, %v", cur, err)
			}
			got := strings.Join(cloudflare.Diff(*cur, want(), true), " ; ")
			if got != tc.want {
				t.Fatalf("écarts %q, attendu %q", got, tc.want)
			}
			if strings.Contains(got, secret) {
				t.Fatalf("secret dans les écarts : %s", got)
			}
		})
	}
}

func team(v *string, locked bool) map[string]coolify.SharedEnv {
	if v == nil {
		return map[string]coolify.SharedEnv{}
	}
	return map[string]coolify.SharedEnv{"EDGE_SECRET_KOYO": {Key: "EDGE_SECRET_KOYO", Value: coolify.Str{Set: !locked, Value: *v}, IsShownOnce: locked}}
}

func ptr(s string) *string { return &s }

func TestEdgeSecret(t *testing.T) {
	a := koyo()
	for _, tc := range []struct {
		team map[string]coolify.SharedEnv
		want cloudflare.Secret
	}{
		{team(ptr(secret), false), cloudflare.Secret{Value: secret}},
		{team(nil, false), cloudflare.Secret{Defaut: cloudflare.SecretAbsente}},
		{team(ptr(""), false), cloudflare.Secret{Defaut: cloudflare.SecretVide}},
		{team(ptr(secret), true), cloudflare.Secret{Defaut: cloudflare.SecretVerrouille}},
		{map[string]coolify.SharedEnv{"EDGE_SECRET_KOYO": {Key: "EDGE_SECRET_KOYO"}}, cloudflare.Secret{Defaut: cloudflare.SecretIllisible}},
		{team(ptr("openssl rand -hex 16"), false), cloudflare.Secret{Defaut: cloudflare.SecretHorsFormat}},
	} {
		if got := cloudflare.EdgeSecret(tc.team, a); got != tc.want {
			t.Errorf("%+v : %+v", tc.want, got)
		}
	}
}

func audit(t *testing.T, f *cftest.Fake, apps []inventory.App, tm map[string]coolify.SharedEnv, all ...inventory.App) (string, string) {
	t.Helper()
	if all == nil {
		all = apps
	}
	ecarts, notes, err := cloudflare.Audit(ctx, client(t, f.URL), apps, all, tm)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.Writes(); len(w) != 0 {
		t.Fatalf("l'audit a écrit : %v", w)
	}
	e, n := strings.Join(ecarts, "\n"), strings.Join(notes, "\n")
	for _, s := range []string{secret, token, "règle manuelle"} {
		if strings.Contains(e+n, s) {
			t.Fatalf("%q dans l'audit :\n%s\n%s", s, e, n)
		}
	}
	return e, n
}

func TestAudit(t *testing.T) {
	f := cftest.New(t, token)
	f.AddZone("koyo.example.org")
	f.AddZone("tacct.ademe.fr")
	pilote := inventory.App{Name: "waf-pilote", Hosts: []string{"waf-pilote.example.org"}}
	tacct := inventory.App{Name: "tacct", Edge: "cloudflare", Hosts: []string{"tacct.ademe.fr"}}
	apps := []inventory.App{koyo("koyo.example.org", "beta.gouv.fr"), pilote, tacct}
	tm := team(ptr(secret), false)
	tm["EDGE_SECRET_TACCT"] = coolify.SharedEnv{Key: "EDGE_SECRET_TACCT", Value: coolify.Str{Set: true, Value: secret}}

	e, n := audit(t, f, apps, tm)
	for _, s := range []string{
		"koyo : règle waf-edge-koyo absente de la zone koyo.example.org",
		"koyo : zone beta.gouv.fr absente ou hors du jeton Cloudflare",
	} {
		if !strings.Contains(e, s) {
			t.Fatalf("écart %q absent :\n%s", s, e)
		}
	}
	if !strings.Contains(n, "tacct : règle Cloudflare hors de waf-ops, edge_zones absent de l'inventaire") || strings.Contains(e+n, "waf-pilote") {
		t.Fatalf("notes :\n%s\nécarts :\n%s", n, e)
	}

	f.AddZone("beta.gouv.fr")
	f.AddRule("koyo.example.org", rule("manuelle", "true", true, map[string]any{"X-Ademe-Edge": set(secret)}))
	f.AddRule("koyo.example.org", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret)}))
	f.AddRule("koyo.example.org", rule("waf-edge-autre", `(http.host eq "autre.koyo.example.org")`, true, map[string]any{"X-Ademe-Edge": set("x")}))
	f.AddRule("koyo.example.org", rule("sans-rapport", "true", true, map[string]any{"X-Autre": set("1")}))
	f.AddRule("beta.gouv.fr", rule("waf-edge-koyo", `(http.host in {"koyo.beta.gouv.fr"})`, false, map[string]any{"X-Ademe-Edge": set("ancien-" + secret)}))
	manuelle := f.Rules("koyo.example.org")[0]["id"].(string)

	e, n = audit(t, f, apps, tm)
	autre := f.Rules("koyo.example.org")[2]["id"].(string)
	want := []string{
		"koyo : règle waf-edge-koyo de la zone beta.gouv.fr : règle désactivée",
		"koyo : règle waf-edge-koyo de la zone beta.gouv.fr : valeur de X-Ademe-Edge différente du secret de l'app",
		"zone koyo.example.org : règle " + manuelle + " sur X-Ademe-Edge hors des règles attendues, à retirer",
		"zone koyo.example.org : règle " + autre + " sur X-Ademe-Edge hors des règles attendues, à retirer",
	}
	if e != strings.Join(want, "\n") {
		t.Fatalf("écarts :\n%s\nattendus :\n%s", e, strings.Join(want, "\n"))
	}
	if !strings.Contains(n, "koyo : règle waf-edge-koyo de la zone koyo.example.org conforme") {
		t.Fatalf("notes :\n%s", n)
	}

	for _, tc := range []struct {
		team map[string]coolify.SharedEnv
		msg  string
	}{
		{team(nil, false), "koyo : EDGE_SECRET_KOYO absente, en-tête des règles Cloudflare non vérifié"},
		{team(ptr(secret), true), "koyo : EDGE_SECRET_KOYO illisible (variable verrouillée), en-tête des règles Cloudflare non vérifié"},
		{team(ptr("court"), false), "koyo : EDGE_SECRET_KOYO hors format"},
	} {
		e, _ := audit(t, f, apps[:1], tc.team)
		if !strings.HasPrefix(e, tc.msg) || !strings.Contains(e, "beta.gouv.fr : règle désactivée") {
			t.Fatalf("écarts :\n%s", e)
		}
		if strings.Contains(e, "valeur de X-Ademe-Edge différente") {
			t.Fatalf("valeur comparée sans secret utilisable :\n%s", e)
		}
	}
}

func TestAuditErreurDeLecture(t *testing.T) {
	f := cftest.New(t, token)
	z := f.AddZone("koyo.example.org")
	f.Fail["GET /client/v4/zones/"+z+"/rulesets/phases/http_request_late_transform/entrypoint"] = 403
	apps := []inventory.App{koyo("koyo.example.org")}
	_, _, err := cloudflare.Audit(ctx, client(t, f.URL), apps, apps, team(ptr(secret), false))
	if err == nil || !strings.Contains(err.Error(), "permission absente") || strings.Contains(err.Error(), token) {
		t.Fatalf("erreur : %v", err)
	}
}

func TestDeuxReglesDeMemeRef(t *testing.T) {
	st := cloudflare.ZoneState{Zone: cloudflare.Zone{Name: "z.fr"}, Ruleset: &cloudflare.Ruleset{Rules: []cloudflare.Rule{{ID: zid, Ref: "waf-edge-koyo"}, {ID: rsid, Ref: "waf-edge-koyo"}}}}
	if _, err := st.Managed("waf-edge-koyo"); err == nil {
		t.Fatal("deux règles de même ref acceptées")
	}
}

func TestRulesetDUneAutrePhaseRefuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"` + rsid + `","phase":"http_request_firewall_custom","rules":[]}}`))
	}))
	defer srv.Close()
	if _, err := client(t, srv.URL).Entrypoint(ctx, zid); err == nil || !strings.Contains(err.Error(), "hors de la phase") {
		t.Fatalf("erreur : %v", err)
	}
}

func TestIdentifiantHorsFormeJamaisEnvoye(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	c := client(t, srv.URL)
	w := want()
	calls := []func() error{
		func() error { _, err := c.Entrypoint(ctx, "../accounts/"+zid); return err },
		func() error { _, err := c.CreateEntrypoint(ctx, zid+"/x", w); return err },
		func() error { _, err := c.AddRule(ctx, zid, "../"+rsid, w); return err },
		func() error { _, err := c.UpdateRule(ctx, zid, rsid, "", w); return err },
		func() error { _, err := c.UpdateRule(ctx, zid, rsid, strings.ToUpper(zid), w); return err },
	}
	for i, call := range calls {
		if err := call(); err == nil || !strings.Contains(err.Error(), "route hors de la liste du client") {
			t.Errorf("appel %d : %v", i, err)
		}
	}
	if hits != 0 {
		t.Fatalf("%d requêtes envoyées", hits)
	}
}

func TestRegleIllisibleSignalee(t *testing.T) {
	st := cloudflare.ZoneState{Zone: cloudflare.Zone{Name: "z.fr"}, Ruleset: &cloudflare.Ruleset{Rules: []cloudflare.Rule{
		{ID: zid, Ref: "manuelle", ActionParameters: []byte(`"illisible"`)},
		{ID: rsid, Ref: "sans-parametres"},
	}}}
	if got := st.Foreign(nil); len(got) != 1 || got[0] != zid {
		t.Fatalf("règles étrangères : %v", got)
	}
	d := cloudflare.Diff(cloudflare.Rule{Action: "rewrite", Expression: expr, ActionParameters: []byte(`{"headers":[1]}`)}, want(), true)
	if strings.Join(d, " ; ") != "paramètres d'action illisibles" {
		t.Fatalf("écarts : %v", d)
	}
}

func TestEnabledAbsentEtZoneInactive(t *testing.T) {
	f := cftest.New(t, token)
	f.AddZone("koyo.example.org")
	f.AddRule("koyo.example.org", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret)}))
	f.OmitEnabled = true
	apps := []inventory.App{koyo("koyo.example.org")}
	e, n := audit(t, f, apps, team(ptr(secret), false))
	if e != "" || !strings.Contains(n, "conforme") {
		t.Fatalf("enabled absent lu comme désactivée :\n%s\n%s", e, n)
	}
	for _, st := range []string{"pending", "moved", ""} {
		f.Status["koyo.example.org"] = st
		e, _ = audit(t, f, apps, team(ptr(secret), false))
		if st == "" {
			if e != "" {
				t.Fatalf("statut vide lu comme actif attendu :\n%s", e)
			}
			continue
		}
		if e != "koyo : zone koyo.example.org non active chez Cloudflare" {
			t.Fatalf("statut %s : écarts :\n%s", st, e)
		}
	}
}

func TestAuditAppHorsLiveEtReglesOrphelines(t *testing.T) {
	f := cftest.New(t, token)
	f.AddZone("koyo.example.org")
	f.AddRule("koyo.example.org", rule("waf-edge-koyo", expr, true, map[string]any{"X-Ademe-Edge": set(secret)}))
	preprod := inventory.App{Name: "koyo-preprod", Live: true, Hosts: []string{"preprod.koyo.example.org"}}
	prod := inventory.App{Name: "koyo-prod", Edge: "cloudflare", Live: true, Hosts: []string{"prod.koyo.example.org"}, EdgeZones: []string{"koyo.example.org"}}
	f.AddRule("koyo.example.org", rule("waf-edge-koyo-preprod", "true", true, map[string]any{"X-Ademe-Edge": set("ancien-" + secret)}))
	f.AddRule("koyo.example.org", rule("waf-edge-koyo-prod", `(http.host in {"prod.koyo.example.org"})`, true, map[string]any{"X-Ademe-Edge": set("autre-" + secret)}))
	rules := f.Rules("koyo.example.org")
	horsLive := koyo("koyo.example.org")
	horsLive.Live = false

	e, n := audit(t, f, []inventory.App{horsLive}, team(ptr(secret), false), horsLive, preprod, prod)
	want := "zone koyo.example.org : règle " + rules[0]["id"].(string) + " sur X-Ademe-Edge hors des règles attendues, à retirer\n" +
		"zone koyo.example.org : règle " + rules[1]["id"].(string) + " sur X-Ademe-Edge hors des règles attendues, à retirer"
	if e != want || !strings.Contains(n, "koyo : "+cloudflare.NotLive) || strings.Contains(e+n, "absente") {
		t.Fatalf("écarts :\n%s\nnotes :\n%s", e, n)
	}

	e, _ = audit(t, f, []inventory.App{koyo("koyo.example.org")}, team(ptr(secret), false), koyo("koyo.example.org"), preprod, prod)
	if e != "zone koyo.example.org : règle "+rules[1]["id"].(string)+" sur X-Ademe-Edge hors des règles attendues, à retirer" {
		t.Fatalf("écarts :\n%s", e)
	}
}
