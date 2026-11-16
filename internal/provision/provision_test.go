package provision

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

const testToken = "7|jeton-coolify-de-test-qui-ne-doit-jamais-sortir"

const testInventory = `
defaults:
  ceilings: { events_per_second: 100, upload_max_size: 100MiB, detection_only_max_days: 14 }
  host_header: visitor
  branch: main
  resources: { memory: 512M, cpu_weight: 64 }
  waf_dir: waf
  internal_events: 0
apps:
  waf-pilote:
    repo: incubateur-ademe/waf-pilote
    platform: scalingo
    hosts: [waf-pilote.incubateur.ademe.dev]
    host_header: visitor
    crs_plugins: []
    live: true
  koyo:
    repo: incubateur-ademe/koyo
    platform: koyeb
    hosts: [koyo.example.org, www.koyo.example.org]
    host_header: upstream
    live: false
`

const pilotUpstream = "https://waf-pilote.osc-fr1.scalingo.io"

func testApps(t *testing.T, only string) []inventory.App {
	t.Helper()
	apps, err := inventory.Parse([]byte(testInventory), map[string]bool{"scalingo": true, "koyeb": true})
	if err != nil {
		t.Fatal(err)
	}
	if only == "" {
		return apps
	}
	for _, a := range apps {
		if a.Name == only {
			return []inventory.App{a}
		}
	}
	t.Fatalf("app %s absente", only)
	return nil
}

func testConfig(url string) Config {
	return Config{
		URL: url, Token: testToken, ProjectUUID: "proj-waf", Environment: "production",
		ServerUUID: "srv-waf-1", DestinationUUID: "dest-waf", GithubAppUUID: ghAppUUID,
		VM: "1", BaseRef: DefaultBaseRef,
	}
}

func run(t *testing.T, url string, apps []inventory.App, apply bool) (string, error) {
	t.Helper()
	c, err := coolify.New(url, testToken)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = Run(context.Background(), c, testConfig(url), apps, apply, &out)
	s := out.String()
	if strings.Contains(s, testToken) || (err != nil && strings.Contains(err.Error(), testToken)) {
		t.Fatalf("jeton dans la sortie")
	}
	if strings.Contains(s, "ne-doit-pas-sortir") {
		t.Fatalf("secret de l'App GitHub dans la sortie")
	}
	return s, err
}

func mustContain(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Errorf("sortie sans %q :\n%s", p, s)
		}
	}
}

// pilotApp pose l'app pilote telle qu'en service : réglages faits à la main,
// stop_grace_period vide et UPSTREAM littéral.
func pilotApp(f *fakeCoolify) *fakeApp {
	a := f.addApp("waf-waf-pilote-1", "dest-waf", map[string]any{
		"git_repository": "incubateur-ademe/waf-pilote", "git_branch": "main", "build_pack": "dockerfile",
		"base_directory": "/waf", "dockerfile_location": "/Dockerfile", "watch_paths": "waf/**",
		"ports_exposes": "8080", "fqdn": "https://waf-pilote.incubateur.ademe.dev",
		"health_check_path": "/healthz", "health_check_port": "2020", "health_check_interval": 2,
		"health_check_retries": 3, "health_check_timeout": 5, "health_check_start_period": 60,
		"limits_memory": "512m", "limits_cpu_shares": 64,
		"is_git_submodules_enabled": false, "is_git_lfs_enabled": false, "inject_build_args_to_dockerfile": false,
	})
	a.setEnv(f, "WAF_TENANT", ptr("waf-pilote"), false, true)
	a.setEnv(f, "WAF_HOSTS", ptr("waf-pilote.incubateur.ademe.dev"), false, true)
	a.setEnv(f, "WAF_HOST_HEADER", ptr("visitor"), false, true)
	a.setEnv(f, "WAF_PLATFORM", ptr("scalingo"), false, true)
	a.setEnv(f, "WAF_CRS_PLUGINS", nil, false, true)
	a.setEnv(f, "WAF_CEILINGS", ptr("events_per_second=100,upload_max_size=100MiB,detection_only_max_days=14"), false, true)
	a.setEnv(f, "UPSTREAM", ptr(pilotUpstream), false, true)
	a.setEnv(f, "WAF_DETECTION_UNTIL", ptr("{{team.DETECTION_UNTIL_WAF_PILOTE}}"), false, true)
	a.setEnv(f, "WAF_UNINSPECTED_PATHS", ptr("{{team.UNINSPECTED_PATHS_WAF_PILOTE}}"), false, true)
	a.setEnv(f, "WAF_FORCE_DETECTION", ptr("{{team.FORCE_DETECTION_WAF_PILOTE}}"), false, true)
	a.setEnv(f, "WAF_BASE", ptr("{{team.WAF_BASE}}"), true, false)
	a.setEnv(f, "NOTE_OPS", ptr("pilote"), false, true)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	f.addShared("DETECTION_UNTIL_WAF_PILOTE", nil)
	f.addShared("UNINSPECTED_PATHS_WAF_PILOTE", nil)
	f.addShared("FORCE_DETECTION_WAF_PILOTE", ptr("2026-11-17T00:00:00+01:00"))
	return a
}

func TestNommage(t *testing.T) {
	apps := testApps(t, "")
	if got := ResourceName(apps[1], "1"); got != "waf-waf-pilote-1" {
		t.Fatalf("nom = %q", got)
	}
	if got := Domains(apps[0]); strings.Join(got, ",") != "http://koyo.example.org:8080,http://www.koyo.example.org:8080" {
		t.Fatalf("domaines avant mise en service = %v", got)
	}
	if got := Domains(apps[1]); strings.Join(got, ",") != "https://waf-pilote.incubateur.ademe.dev" {
		t.Fatalf("domaines en service = %v", got)
	}
	envs := wantEnvs(apps[0], testConfig("x"))
	keys := map[string]string{}
	for _, e := range envs {
		keys[e.key] = e.value
	}
	if keys["UPSTREAM"] != "{{team.UPSTREAM_KOYO}}" || keys["ORIGIN_TOKEN"] != "{{team.ORIGIN_TOKEN_KOYO}}" || keys["WAF_BASE"] != "{{team.WAF_BASE}}" {
		t.Fatalf("références = %v", keys)
	}
	for _, e := range wantEnvs(apps[1], testConfig("x")) {
		if e.key == "ORIGIN_TOKEN" {
			t.Fatal("ORIGIN_TOKEN posé hors Koyeb")
		}
	}
}

func TestCreation(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	f.addShared("DETECTION_UNTIL_KOYO", ptr("2026-11-20T00:00:00+01:00"))
	apps := testApps(t, "")

	out, err := run(t, srv.URL, apps, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}
	mustContain(t, out,
		"waf-koyo-1 : création", "waf-waf-pilote-1 : création",
		"domains = http://koyo.example.org:8080,http://www.koyo.example.org:8080",
		"+ variable d'équipe UPSTREAM_KOYO, créée vide",
		"+ variable d'équipe ORIGIN_TOKEN_KOYO, créée vide",
		"action ops : saisir UPSTREAM_KOYO",
		"action ops : saisir ORIGIN_TOKEN_KOYO",
		"plan seul",
	)
	if strings.Contains(out, "variable d'équipe DETECTION_UNTIL_KOYO") {
		t.Fatal("variable partagée existante recréée")
	}

	out, err = run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")

	for _, k := range []string{"UPSTREAM_KOYO", "ORIGIN_TOKEN_KOYO", "UPSTREAM_WAF_PILOTE", "FORCE_DETECTION_WAF_PILOTE"} {
		if s := f.shared(k); s == nil || s.Value != nil {
			t.Fatalf("%s : %+v, attendue créée vide", k, s)
		}
	}
	if v := f.shared("DETECTION_UNTIL_KOYO").Value; v == nil || *v != "2026-11-20T00:00:00+01:00" {
		t.Fatal("valeur partagée existante modifiée")
	}

	a := f.appByName("waf-waf-pilote-1")
	if a == nil || a.dest != "dest-waf" {
		t.Fatalf("app pilote : %+v", a)
	}
	st := a.data["settings"].(map[string]any)
	if norm(plain, st["stop_grace_period"]) != "20" || st["is_force_https_enabled"] != true || st["is_git_submodules_enabled"] != false || st["inject_build_args_to_dockerfile"] != false {
		t.Fatalf("réglages : %v", st)
	}
	if a.data["fqdn"] != "https://waf-pilote.incubateur.ademe.dev" || norm(plain, a.data["health_check_port"]) != "2020" || a.data["limits_memory"] != "512m" {
		t.Fatalf("app : %v", a.data)
	}
	if k := f.appByName("waf-koyo-1"); k.data["settings"].(map[string]any)["is_force_https_enabled"] != false {
		t.Fatal("is_force_https_enabled doit suivre live")
	}
	for _, e := range a.envs {
		if e.Preview {
			continue
		}
		wantBuild := e.Key == "WAF_BASE"
		if e.Buildtime != wantBuild || e.Runtime == wantBuild {
			t.Errorf("%s : build=%t runtime=%t", e.Key, e.Buildtime, e.Runtime)
		}
	}
	ceil := a.env("WAF_CEILINGS")
	c, err := render.ParseCeilings(*ceil.Value)
	if err != nil || c != render.DefaultCeilings() {
		t.Fatalf("WAF_CEILINGS = %q : %+v, %v", *ceil.Value, c, err)
	}
	if v := a.env("UPSTREAM").Value; v == nil || *v != "{{team.UPSTREAM_WAF_PILOTE}}" {
		t.Fatalf("UPSTREAM = %v", v)
	}
	if v := f.appByName("waf-koyo-1").env("ORIGIN_TOKEN"); v == nil || *v.Value != "{{team.ORIGIN_TOKEN_KOYO}}" {
		t.Fatal("ORIGIN_TOKEN absent sur l'app Koyeb")
	}
	for _, w := range f.writes {
		if strings.Contains(w, "deploy") || strings.Contains(w, "start") || strings.Contains(w, "restart") {
			t.Fatalf("déploiement déclenché : %s", w)
		}
	}

	n := len(f.writes)
	out, err = run(t, srv.URL, apps, true)
	if err != nil || len(f.writes) != n {
		t.Fatalf("troisième passage : %v, %d écritures\n%s", err, len(f.writes)-n, out)
	}
	mustContain(t, out, "0 changement(s) prévu(s)")
}

func TestMiseAJourPilote(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.env("WAF_TENANT").Buildtime = true
	apps := testApps(t, "waf-pilote")

	out, err := run(t, srv.URL, apps, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}
	mustContain(t, out,
		"waf-waf-pilote-1 ("+a.data["uuid"].(string)+") : mise à jour",
		"~ stop_grace_period : (vide) -> 20",
		`~ env WAF_TENANT : "waf-pilote" build=true runtime=true -> "waf-pilote" build=false runtime=true`,
		"+ variable d'équipe UPSTREAM_WAF_PILOTE, créée vide",
		`UPSTREAM : valeur littérale "`+pilotUpstream+`" conservée`,
		"action ops : saisir UPSTREAM_WAF_PILOTE dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision",
		"variable hors liste conservée : NOTE_OPS",
		"redéploiement nécessaire",
	)
	if strings.Contains(out, "health_check") || strings.Contains(out, "env UPSTREAM") || strings.Contains(out, "is_git_lfs") {
		t.Fatalf("écart inattendu :\n%s", out)
	}

	out, err = run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	if v := a.env("UPSTREAM").Value; v == nil || *v != pilotUpstream {
		t.Fatalf("UPSTREAM littéral remplacé alors que la clé partagée est vide : %v", v)
	}
	if a.env("NOTE_OPS") == nil {
		t.Fatal("variable hors liste supprimée")
	}
	if v := f.shared("FORCE_DETECTION_WAF_PILOTE").Value; v == nil || *v != "2026-11-17T00:00:00+01:00" {
		t.Fatal("valeur partagée existante modifiée")
	}
	for _, w := range f.writes {
		if strings.HasPrefix(w, "POST /api/v1/applications") {
			t.Fatalf("app recréée : %v", f.writes)
		}
	}
}

func TestReferenceAvecEspaces(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.env("WAF_BASE").Value = ptr("{{ team.WAF_BASE }}")
	apps := testApps(t, "waf-pilote")

	out, err := run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "env WAF_BASE") {
		t.Fatalf("WAF_BASE réécrite pour des espaces :\n%s", out)
	}
	if v := a.env("WAF_BASE").Value; v == nil || *v != "{{ team.WAF_BASE }}" {
		t.Fatalf("WAF_BASE modifiée : %v", v)
	}
	mustContain(t, out, "idempotence vérifiée")
}

func TestUpstreamRemplaceSiPartageeRemplie(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	apps := testApps(t, "waf-pilote")

	out, err := run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "UPSTREAM : valeur littérale remplacée par {{team.UPSTREAM_WAF_PILOTE}}", "idempotence vérifiée")
	if v := a.env("UPSTREAM").Value; v == nil || *v != "{{team.UPSTREAM_WAF_PILOTE}}" {
		t.Fatalf("UPSTREAM = %v", v)
	}
	if strings.Contains(out, "action ops : saisir UPSTREAM") {
		t.Fatal("action ops demandée alors que la clé est remplie")
	}
}

func TestDestinationCoolifyRefusee(t *testing.T) {
	f, srv := newFake(t, testToken)
	apps := testApps(t, "waf-pilote")
	cfg := testConfig(srv.URL)
	cfg.DestinationUUID = "dest-coolify"
	c, _ := coolify.New(srv.URL, testToken)
	var out bytes.Buffer
	err := Run(context.Background(), c, cfg, apps, true, &out)
	if err == nil || !strings.Contains(err.Error(), `réseau "coolify"`) {
		t.Fatalf("erreur = %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures : %v", f.writes)
	}

	f2, srv2 := newFake(t, testToken)
	f2.addApp("waf-waf-pilote-1", "dest-coolify", nil)
	_, err = run(t, srv2.URL, apps, true)
	if err == nil || !strings.Contains(err.Error(), "refusée") {
		t.Fatalf("app existante sur le réseau coolify : erreur = %v", err)
	}
	if len(f2.writes) != 0 {
		t.Fatalf("écritures : %v", f2.writes)
	}
}

func TestDestinationAdditionnelleRefusee(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.extra = []string{"dest-coolify"}
	_, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "destination additionnelle dest-coolify") || !strings.Contains(err.Error(), `réseau "coolify"`) {
		t.Fatalf("erreur = %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures : %v", f.writes)
	}

	f2, srv2 := newFake(t, testToken)
	f2.dests["dest-waf-2"] = fakeDest{"waf-1-waf-2", "waf-2", "srv-waf-1"}
	pilotApp(f2).extra = []string{"dest-waf-2"}
	_, err = run(t, srv2.URL, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "destination additionnelle dest-waf-2") {
		t.Fatalf("destination additionnelle hors réseau coolify : erreur = %v", err)
	}
	if len(f2.writes) != 0 {
		t.Fatalf("écritures : %v", f2.writes)
	}
}

func TestDestinationRelueApresCreation(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	f.createLandsOn = "dest-coolify"
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "waf-waf-pilote-1 créée, mais") || !strings.Contains(err.Error(), `réseau "coolify"`) {
		t.Fatalf("erreur = %v\n%s", err, out)
	}
	var creations int
	for _, w := range f.writes {
		switch {
		case w == "POST /api/v1/applications/private-github-app":
			creations++
		case strings.HasPrefix(w, "PATCH "):
			t.Fatalf("écriture après une destination refusée : %v", f.writes)
		}
	}
	if creations != 1 {
		t.Fatalf("écritures : %v", f.writes)
	}
}

func TestIdempotenceControlee(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	f.ignorePatch = map[string]bool{"stop_grace_period": true}
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "idempotence") {
		t.Fatalf("erreur = %v\n%s", err, out)
	}
	mustContain(t, out, "second calcul :", "~ stop_grace_period : (vide) -> 20")
	if strings.Contains(out, "idempotence vérifiée") {
		t.Fatalf("idempotence annoncée :\n%s", out)
	}
}

func TestSourceGithubAppCorrigee(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.data["source_id"] = 3
	apps := testApps(t, "waf-pilote")

	out, err := run(t, srv.URL, apps, false)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, `~ source : App\Models\GithubApp #3 -> GithubApp #7`)
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}

	out, err = run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	if norm(plain, a.data["source_id"]) != "7" {
		t.Fatalf("source_id = %v", a.data["source_id"])
	}
	var patched bool
	for _, b := range f.bodies {
		if strings.Contains(b, `"github_app_uuid":"`+ghAppUUID+`"`) {
			patched = true
		}
	}
	if !patched {
		t.Fatalf("github_app_uuid absent des écritures : %v", f.bodies)
	}
}

func TestDoublonDeNom(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addApp("waf-waf-pilote-1", "dest-waf", nil)
	f.addApp("waf-waf-pilote-1", "dest-waf", nil)
	_, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "plusieurs apps") || len(f.writes) != 0 {
		t.Fatalf("erreur = %v, écritures = %v", err, f.writes)
	}
}

func TestJetonRefuse(t *testing.T) {
	_, srv := newFake(t, "un-autre-jeton")
	_, err := run(t, srv.URL, testApps(t, "waf-pilote"), false)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("erreur = %v", err)
	}
}

func TestVariableRequiseManquante(t *testing.T) {
	f, srv := newFake(t, testToken)
	env := map[string]string{
		"COOLIFY_URL":              srv.URL,
		"COOLIFY_TOKEN":            testToken,
		"WAF_OPS_PROJECT_UUID":     "proj-waf",
		"WAF_OPS_GITHUB_APP_UUID":  ghAppUUID,
		"WAF_OPS_DESTINATION_UUID": "",
	}
	var out, errw bytes.Buffer
	err := Main(context.Background(), []string{"--etc", "../..", "--inventaire", srv.URL + "/inventaire.yaml"}, func(k string) string { return env[k] }, &out, &errw)
	if err == nil || err.Error() != "variables manquantes : WAF_OPS_SERVER_UUID, WAF_OPS_DESTINATION_UUID" {
		t.Fatalf("erreur = %v", err)
	}
	if f.requests != 0 {
		t.Fatalf("%d appel(s) avant l'arrêt", f.requests)
	}
	if strings.Contains(out.String()+errw.String()+err.Error(), testToken) {
		t.Fatal("jeton dans la sortie")
	}
}

func TestMainPlanSeul(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	env := map[string]string{
		"COOLIFY_URL":              srv.URL,
		"COOLIFY_TOKEN":            testToken,
		"WAF_OPS_PROJECT_UUID":     "proj-waf",
		"WAF_OPS_SERVER_UUID":      "srv-waf-1",
		"WAF_OPS_DESTINATION_UUID": "dest-waf",
		"WAF_OPS_GITHUB_APP_UUID":  ghAppUUID,
	}
	var out, errw bytes.Buffer
	err := Main(context.Background(), []string{"--etc", "../..", "--inventaire", "../../inventaire.yaml", "--app", "waf-pilote"},
		func(k string) string { return env[k] }, &out, &errw)
	if err != nil {
		t.Fatalf("%v\n%s", err, errw.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}
	s := out.String()
	mustContain(t, s, "waf-waf-pilote-1", "stop_grace_period", "plan seul")
	if strings.Contains(s, "tacct") || strings.Contains(s+errw.String(), testToken) {
		t.Fatalf("sortie :\n%s", s)
	}

	err = Main(context.Background(), []string{"--etc", "../..", "--inventaire", "../../inventaire.yaml", "--app", "inconnue"},
		func(k string) string { return env[k] }, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "absente de l'inventaire") {
		t.Fatalf("erreur = %v", err)
	}
}

func TestConfigDefauts(t *testing.T) {
	env := map[string]string{
		"COOLIFY_URL": "https://x", "COOLIFY_TOKEN": "t", "WAF_OPS_PROJECT_UUID": "p",
		"WAF_OPS_SERVER_UUID": "s", "WAF_OPS_DESTINATION_UUID": "d", "WAF_OPS_GITHUB_APP_UUID": "g",
	}
	c, err := LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Environment != "production" || c.VM != "1" || c.BaseRef != "{{team.WAF_BASE}}" {
		t.Fatalf("défauts : %+v", c)
	}
	env["WAF_OPS_VM"] = "x"
	if _, err := LoadConfig(func(k string) string { return env[k] }); err == nil {
		t.Fatal("WAF_OPS_VM invalide acceptée")
	}
}

func TestOriginTokenLitteralMasque(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := f.addApp("waf-koyo-1", "dest-waf", nil)
	const secret = "origine-koyeb-0123456789abcdef0123456789abcdef"
	a.setEnv(f, "ORIGIN_TOKEN", ptr(secret), true, true)
	out, err := run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("ORIGIN_TOKEN littéral affiché :\n%s", out)
	}
	mustContain(t, out, "ORIGIN_TOKEN : valeur littérale (valeur masquée) conservée", "idempotence vérifiée")
	if e := a.env("ORIGIN_TOKEN"); *e.Value != secret || e.Buildtime {
		t.Fatalf("ORIGIN_TOKEN : %+v", e)
	}
}
