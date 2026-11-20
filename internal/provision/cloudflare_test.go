package provision

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/cloudflare/cftest"
	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const cfToken = "jeton-cloudflare-de-test-qui-ne-doit-jamais-sortir"

const koyoExpr = `(http.host in {"koyo.example.org" "www.koyo.example.org"})`

// koyoZones : koyo en edge, avec la zone koyo.example.org, et koyo-preprod dont
// le host est dans la même zone.
func koyoZones(t *testing.T, names ...string) []inventory.App {
	t.Helper()
	y := strings.Replace(testInventory, "hosts: [koyo.example.org, www.koyo.example.org]\n",
		"hosts: [koyo.example.org, www.koyo.example.org]\n    edge: cloudflare\n    edge_zones: [koyo.example.org]\n", 1) + `
  koyo-preprod:
    repo: incubateur-ademe/koyo
    platform: koyeb
    hosts: [preprod.koyo.example.org]
    host_header: upstream
    edge: cloudflare
    edge_zones: [koyo.example.org]
`
	apps, err := inventory.Parse([]byte(y), map[string]bool{"scalingo": true, "koyeb": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		names = []string{"koyo"}
	}
	var out []inventory.App
	for _, n := range names {
		for _, a := range apps {
			if a.Name == n {
				out = append(out, a)
			}
		}
	}
	return out
}

func koyoTeam(f *fakeCoolify) {
	f.addShared("WAF_BASE", ptr(wafBaseLiteral))
	f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
	f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
	f.addShared("UPSTREAM_KOYO_PREPROD", ptr("https://koyo-preprod.koyeb.app"))
	f.addShared("ORIGIN_TOKEN_KOYO_PREPROD", ptr("jeton-origine-koyo-preprod"))
}

func runCF(t *testing.T, url string, cf *cftest.Fake, apps []inventory.App, apply bool, secrets ...string) (string, error) {
	t.Helper()
	c, err := coolify.New(url, testToken)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(url)
	if cf != nil {
		if cfg.Cloudflare, err = cloudflare.NewAt(cf.URL, cfToken); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	err = Run(context.Background(), c, cfg, apps, apply, &out)
	s := out.String()
	if err != nil {
		s += "\nerreur : " + err.Error()
	}
	for _, x := range append(secrets, testToken, cfToken) {
		if x != "" && strings.Contains(s, x) {
			t.Fatalf("secret ou jeton dans la sortie :\n%s", s)
		}
	}
	return s, err
}

func edgeValue(t *testing.T, r map[string]any) string {
	t.Helper()
	ap, _ := r["action_parameters"].(map[string]any)
	hs, _ := ap["headers"].(map[string]any)
	h, _ := hs["X-Ademe-Edge"].(map[string]any)
	v, _ := h["value"].(string)
	return v
}

func ruleByRef(rules []map[string]any, ref string) map[string]any {
	for _, r := range rules {
		if r["ref"] == ref {
			return r
		}
	}
	return nil
}

func TestEdgeCloudflareCreation(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")

	out, err := runCF(t, srv.URL, cf, koyoZones(t), false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out,
		"+ variable d'équipe EDGE_SECRET_KOYO = (générée, valeur masquée)",
		"+ règle Cloudflare waf-edge-koyo, zone koyo.example.org, dans un ruleset http_request_late_transform à créer : "+koyoExpr+", X-Ademe-Edge = EDGE_SECRET_KOYO",
		"plan seul",
	)
	if len(cf.Writes()) != 0 || f.shared("EDGE_SECRET_KOYO") != nil {
		t.Fatalf("écritures sans --apply : %v", cf.Writes())
	}

	out, err = runCF(t, srv.URL, cf, koyoZones(t), true)
	secret := ""
	if sh := f.shared("EDGE_SECRET_KOYO"); sh != nil && sh.Value != nil {
		secret = *sh.Value
	}
	if err != nil || !reGenere.MatchString(secret) {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("secret généré dans la sortie :\n%s", out)
	}
	mustContain(t, out, "idempotence vérifiée")
	rules := cf.Rules("koyo.example.org")
	if len(rules) != 1 || rules[0]["ref"] != "waf-edge-koyo" || rules[0]["expression"] != koyoExpr || edgeValue(t, rules[0]) != secret {
		t.Fatalf("règles : %d, ref %v, expression %v", len(rules), rules[0]["ref"], rules[0]["expression"])
	}
	if w := cf.Writes(); len(w) != 1 || !strings.HasSuffix(w[0], "/rulesets") || !strings.HasPrefix(w[0], "POST ") {
		t.Fatalf("écritures Cloudflare : %v", w)
	}
}

func TestEdgeCloudflareAjoutSansToucherAuxAutres(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	cf.AddRule("koyo.example.org", map[string]any{"ref": "cache", "action": "rewrite", "expression": "true",
		"action_parameters": map[string]any{"headers": map[string]any{"X-Autre": map[string]any{"operation": "set", "value": "1"}}}})
	cf.AddRule("koyo.example.org", map[string]any{"action": "rewrite", "expression": `(http.host eq "api.koyo.example.org")`, "enabled": false,
		"action_parameters": map[string]any{"headers": map[string]any{"X-Api": map[string]any{"operation": "remove"}}}})
	before := cf.Rules("koyo.example.org")

	out, err := runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "+ règle Cloudflare waf-edge-koyo, zone koyo.example.org : "+koyoExpr+", X-Ademe-Edge = EDGE_SECRET_KOYO", "idempotence vérifiée")
	if strings.Contains(out, "variable d'équipe EDGE_SECRET_KOYO") || strings.Contains(out, "action ops : retirer") {
		t.Fatalf("secret recréé ou règle étrangère signalée :\n%s", out)
	}
	after := cf.Rules("koyo.example.org")
	if len(after) != 3 || !reflect.DeepEqual(after[:2], before) {
		t.Fatalf("règles en place modifiées ou déplacées :\navant %v\naprès %v", before, after[:2])
	}
	if after[2]["ref"] != "waf-edge-koyo" || edgeValue(t, after[2]) != edgeSecretFactice {
		t.Fatalf("règle ajoutée : ref %v", after[2]["ref"])
	}
}

func TestEdgeCloudflareMiseAJourDeLaSeuleRegle(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	cf.AddRule("koyo.example.org", map[string]any{"ref": "cache", "action": "rewrite", "expression": "true",
		"action_parameters": map[string]any{"headers": map[string]any{"X-Autre": map[string]any{"operation": "set", "value": "1"}}}})
	id := cf.AddRule("koyo.example.org", map[string]any{"ref": "waf-edge-koyo", "action": "rewrite", "enabled": false,
		"expression":        `(http.host in {"koyo.example.org"})`,
		"action_parameters": map[string]any{"headers": map[string]any{"X-Ademe-Edge": map[string]any{"operation": "set", "value": "ancien-secret-de-plus-de-32-caracteres-0123"}}}})
	before := cf.Rules("koyo.example.org")[0]

	out, err := runCF(t, srv.URL, cf, koyoZones(t), false, edgeSecretFactice, "ancien-secret")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		"~ règle Cloudflare waf-edge-koyo, zone koyo.example.org : expression différente de "+koyoExpr+" ; règle désactivée ; valeur de X-Ademe-Edge différente du secret de l'app",
		"13 changement(s) prévu(s)",
	)
	if len(cf.Writes()) != 0 {
		t.Fatalf("écritures Cloudflare sans --apply : %v", cf.Writes())
	}
	out, err = runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice, "ancien-secret")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	rules := cf.Rules("koyo.example.org")
	if len(rules) != 2 || !reflect.DeepEqual(rules[0], before) || rules[1]["id"] != id || rules[1]["enabled"] != true || edgeValue(t, rules[1]) != edgeSecretFactice {
		t.Fatalf("règles : %d, autre intacte %t, id %v", len(rules), reflect.DeepEqual(rules[0], before), rules[1]["id"])
	}
	w := cf.Writes()
	if len(w) != 1 || !strings.HasPrefix(w[0], "PATCH ") || !strings.HasSuffix(w[0], "/rules/"+id) {
		t.Fatalf("écritures Cloudflare : %v", w)
	}
}

func TestEdgeCloudflareSecretGenereRemplaceLaValeur(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	cf.AddRule("koyo.example.org", map[string]any{"ref": "waf-edge-koyo", "action": "rewrite", "expression": koyoExpr,
		"action_parameters": map[string]any{"headers": map[string]any{"X-Ademe-Edge": map[string]any{"operation": "set", "value": edgeSecretFactice}}}})
	out, err := runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "~ règle Cloudflare waf-edge-koyo, zone koyo.example.org : valeur de X-Ademe-Edge remplacée par le secret généré", "idempotence vérifiée")
	if v := edgeValue(t, cf.Rules("koyo.example.org")[0]); v != *f.shared("EDGE_SECRET_KOYO").Value || v == edgeSecretFactice {
		t.Fatal("règle non alignée sur le secret généré")
	}
}

func TestEdgeCloudflareDeuxAppsDansUneZoneSansRuleset(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	out, err := runCF(t, srv.URL, cf, koyoZones(t, "koyo", "koyo-preprod"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	rules := cf.Rules("koyo.example.org")
	p := ruleByRef(rules, "waf-edge-koyo-preprod")
	if len(rules) != 2 || ruleByRef(rules, "waf-edge-koyo") == nil || p == nil || p["expression"] != `(http.host in {"preprod.koyo.example.org"})` {
		t.Fatalf("règles : %v", rules)
	}
	if edgeValue(t, p) != *f.shared("EDGE_SECRET_KOYO_PREPROD").Value || edgeValue(t, p) == edgeValue(t, ruleByRef(rules, "waf-edge-koyo")) {
		t.Fatal("secrets des deux apps confondus")
	}
}

func TestEdgeCloudflareRegleEtrangereSignalee(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	manuelle := cf.AddRule("koyo.example.org", map[string]any{"action": "rewrite", "expression": `(http.host eq "koyo.example.org")`,
		"action_parameters": map[string]any{"headers": map[string]any{"x-ademe-edge": map[string]any{"operation": "set", "value": edgeSecretFactice}}}})
	before := cf.Rules("koyo.example.org")
	out, err := runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "! action ops : retirer de la zone koyo.example.org la règle "+manuelle+", qui touche X-Ademe-Edge hors de provision", "idempotence vérifiée")
	if after := cf.Rules("koyo.example.org"); !reflect.DeepEqual(after[0], before[0]) {
		t.Fatal("règle manuelle modifiée")
	}
}

func TestEdgeCloudflareSecretInutilisable(t *testing.T) {
	for _, tc := range []struct {
		name, note string
		set        func(*fakeShared)
		value      string
	}{
		{"verrouillée", "EDGE_SECRET_KOYO illisible (variable verrouillée) : règles Cloudflare non posées", func(s *fakeShared) { s.Locked = true }, edgeSecretFactice},
		{"sans read:sensitive", "EDGE_SECRET_KOYO illisible (jeton sans read:sensitive) : règles Cloudflare non posées", func(s *fakeShared) { s.Hidden = true }, edgeSecretFactice},
		{"vide", "EDGE_SECRET_KOYO vide : règles Cloudflare non posées", func(*fakeShared) {}, ""},
		{"hors format", "action ops : remplacer EDGE_SECRET_KOYO, wafgen run refuse de démarrer avec WAF_EDGE=cloudflare et ce secret", func(*fakeShared) {}, "openssl rand -hex 16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFake(t, testToken)
			koyoTeam(f)
			tc.set(f.addShared("EDGE_SECRET_KOYO", ptr(tc.value)))
			cf := cftest.New(t, cfToken)
			cf.AddZone("koyo.example.org")
			out, err := runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			mustContain(t, out, tc.note)
			if len(cf.Requests) != 0 || strings.Contains(out, "règle Cloudflare waf-edge") {
				t.Fatalf("Cloudflare appelé sans secret utilisable : %v\n%s", cf.Requests, out)
			}
		})
	}
}

func TestPasDeRegleSansEdge(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	apps := koyoZones(t)
	apps[0].Edge = ""
	out, err := runCF(t, srv.URL, cf, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(cf.Requests) != 0 || f.shared("EDGE_SECRET_KOYO") != nil || strings.Contains(out, "EDGE") {
		t.Fatalf("règle ou secret pour une app hors edge : %v\n%s", cf.Requests, out)
	}
}

func TestEdgeCloudflareErreurs(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	cf := cftest.New(t, cfToken)
	out, err := runCF(t, srv.URL, cf, koyoZones(t), false, edgeSecretFactice)
	if err == nil || !strings.Contains(err.Error(), "zone Cloudflare koyo.example.org : koyo.example.org : zone absente ou hors du jeton Cloudflare") {
		t.Fatalf("zone absente : %v\n%s", err, out)
	}
	z := cf.AddZone("koyo.example.org")
	cf.Fail["POST /client/v4/zones/"+z+"/rulesets"] = 400
	out, err = runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
	if err == nil || !strings.Contains(err.Error(), "règle Cloudflare waf-edge-koyo, zone koyo.example.org : Cloudflare POST") || !strings.Contains(err.Error(), "HTTP 400, codes 20021") {
		t.Fatalf("erreur Cloudflare : %v\n%s", err, out)
	}

	out, err = runCF(t, srv.URL, nil, koyoZones(t), false, edgeSecretFactice)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "! règles Cloudflare non vérifiées : CLOUDFLARE_API_TOKEN absent")
}

func TestMainJetonCloudflare(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	y := strings.Replace(testInventory, "hosts: [koyo.example.org, www.koyo.example.org]\n",
		"hosts: [koyo.example.org, www.koyo.example.org]\n    edge: cloudflare\n    edge_zones: [koyo.example.org]\n", 1)
	inv := t.TempDir() + "/inventaire.yaml"
	if err := os.WriteFile(inv, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"COOLIFY_URL": srv.URL, "COOLIFY_TOKEN": testToken, "WAF_OPS_PROJECT_UUID": "proj-waf",
		"WAF_OPS_SERVER_UUID": "srv-waf-1", "WAF_OPS_DESTINATION_UUID": "dest-waf", "WAF_OPS_GITHUB_APP_UUID": ghAppUUID,
	}
	main := func(app string) error {
		var out, errw bytes.Buffer
		return Main(context.Background(), []string{"--etc", "../..", "--inventaire", inv, "--app", app}, func(k string) string { return env[k] }, &out, &errw)
	}
	if err := main("koyo"); err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN manquant, requis pour les edge_zones de koyo") {
		t.Fatalf("sans jeton : %v", err)
	}
	if err := main("waf-pilote"); err != nil {
		t.Fatalf("app hors edge sans jeton Cloudflare : %v", err)
	}
	env["CLOUDFLARE_API_TOKEN"] = "a b"
	if err := main("koyo"); err == nil || strings.Contains(err.Error(), "a b") {
		t.Fatalf("jeton invalide : %v", err)
	}
}

func TestEdgeCloudflareEnabledAbsentEtZoneInactive(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	cf := cftest.New(t, cfToken)
	cf.AddZone("koyo.example.org")
	cf.OmitEnabled = true
	out, err := runCF(t, srv.URL, cf, koyoZones(t), true, edgeSecretFactice)
	if err != nil {
		t.Fatalf("enabled absent : %v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")

	cf.Status["koyo.example.org"] = "pending"
	out, err = runCF(t, srv.URL, cf, koyoZones(t), false, edgeSecretFactice)
	if err == nil || !strings.Contains(err.Error(), "koyo.example.org : zone non active chez Cloudflare") {
		t.Fatalf("zone pending : %v\n%s", err, out)
	}
}

func TestCreationDuSecretRefuseeHorsAdmin(t *testing.T) {
	f, srv := newFake(t, testToken)
	koyoTeam(f)
	f.notAdmin = true
	out, err := run(t, srv.URL, koyoEdge(t), true)
	if err == nil || !strings.Contains(err.Error(), "création de EDGE_SECRET_KOYO : Coolify POST /api/v1/team/envs : HTTP 403") ||
		!strings.Contains(err.Error(), "admin de l'équipe") {
		t.Fatalf("erreur : %v\n%s", err, out)
	}
	if f.appByName("waf-koyo-1") != nil {
		t.Fatal("app créée malgré l'échec de la variable d'équipe")
	}
}
