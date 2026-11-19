package provision

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

const testToken = "7|jeton-coolify-de-test-qui-ne-doit-jamais-sortir"

const testInventory = `
vms:
  "1": { stage: prod, ip: 78.232.54.148 }
  preprod: { stage: preprod, ip: 51.15.20.30 }
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
// stop_grace_period vide, UPSTREAM littéral, aucune variable d'équipe hors WAF_BASE.
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
	a.setEnv(f, "WAF_BASE", ptr("{{team.WAF_BASE}}"), true, false)
	a.setEnv(f, "NOTE_OPS", ptr("pilote"), false, true)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	return a
}

func TestNommage(t *testing.T) {
	apps := testApps(t, "")
	if got := ResourceName(apps[1], "1"); got != "waf-waf-pilote-1" {
		t.Fatalf("nom = %q", got)
	}
	if got := Domains(apps[0]); strings.Join(got, ",") != "http://koyo.example.org,http://www.koyo.example.org" {
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
		"domains = http://koyo.example.org,http://www.koyo.example.org",
		"+ env WAF_DETECTION_UNTIL = \"{{team.DETECTION_UNTIL_KOYO}}\"",
		"action ops : créer UPSTREAM_KOYO avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision ; d'ici là UPSTREAM n'est pas posée",
		"action ops : créer ORIGIN_TOKEN_KOYO avec sa valeur dans l'UI Coolify",
		"action ops : créer UPSTREAM_WAF_PILOTE avec sa valeur",
		"plan seul",
	)
	for _, k := range []string{"créée vide", "saisir", "env UPSTREAM", "env ORIGIN_TOKEN", "env WAF_UNINSPECTED_PATHS", "env WAF_FORCE_DETECTION", "UNTIL_WAF_PILOTE"} {
		if strings.Contains(out, k) {
			t.Fatalf("plan avec %q :\n%s", k, out)
		}
	}

	out, err = run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")

	if len(f.team) != 2 {
		t.Fatalf("variables d'équipe : %d, 2 attendues", len(f.team))
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
	for _, k := range []string{"UPSTREAM", "WAF_DETECTION_UNTIL", "WAF_UNINSPECTED_PATHS", "WAF_FORCE_DETECTION"} {
		if a.env(k) != nil {
			t.Fatalf("%s posée sur le pilote sans variable d'équipe", k)
		}
	}
	koyo := f.appByName("waf-koyo-1")
	if koyo.env("UPSTREAM") != nil || koyo.env("ORIGIN_TOKEN") != nil {
		t.Fatal("référence requise posée sans variable d'équipe")
	}
	if v := koyo.env("WAF_DETECTION_UNTIL"); v == nil || *v.Value != "{{team.DETECTION_UNTIL_KOYO}}" {
		t.Fatal("WAF_DETECTION_UNTIL absente alors que la clé existe")
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
	mustContain(t, out, "0 changement(s) prévu(s)", "action ops : créer UPSTREAM_KOYO")

	// ops crée les clés requises avec leur valeur dans l'UI, puis relance provision.
	f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
	f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `+ env UPSTREAM = "{{team.UPSTREAM_KOYO}}"`, `+ env ORIGIN_TOKEN = "{{team.ORIGIN_TOKEN_KOYO}}"`, "idempotence vérifiée")
	if strings.Contains(out, "action ops") || strings.Contains(out, "jeton-origine-koyo") {
		t.Fatalf("sortie :\n%s", out)
	}
	if v := koyo.env("UPSTREAM"); v == nil || *v.Value != "{{team.UPSTREAM_KOYO}}" {
		t.Fatal("UPSTREAM non posée une fois la clé créée")
	}
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
		`UPSTREAM : valeur littérale "`+pilotUpstream+`" conservée`,
		"action ops : créer UPSTREAM_WAF_PILOTE avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision pour remplacer la valeur littérale",
		"variable hors liste conservée : NOTE_OPS",
		"redéploiement nécessaire",
	)
	if strings.Contains(out, "health_check") || strings.Contains(out, "env UPSTREAM") || strings.Contains(out, "is_git_lfs") || strings.Contains(out, "env WAF_DETECTION_UNTIL") || strings.Contains(out, "créée vide") {
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
	if len(f.team) != 1 {
		t.Fatalf("variables d'équipe : %d, WAF_BASE seule attendue", len(f.team))
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
	for _, vm := range []string{"preprod", "2"} {
		env["WAF_OPS_VM"] = vm
		if c, err := LoadConfig(func(k string) string { return env[k] }); err != nil || c.VM != vm {
			t.Fatalf("WAF_OPS_VM %q : %+v, %v", vm, c, err)
		}
	}
	for _, vm := range []string{"Preprod", "waf_1", "waf-1", "vm-de-plus-de-seize"} {
		env["WAF_OPS_VM"] = vm
		if _, err := LoadConfig(func(k string) string { return env[k] }); err == nil {
			t.Fatalf("WAF_OPS_VM %q acceptée", vm)
		}
	}
}

// stagesInventory : le pilote passe sur la VM de preprod, koyo reste en prod.
const stagesInventory = `
vms:
  "1": { stage: prod, ip: 78.232.54.148 }
  preprod: { stage: preprod, ip: 51.15.20.30 }
apps:
  waf-pilote:
    repo: incubateur-ademe/waf-pilote
    platform: scalingo
    hosts: [waf-pilote.incubateur.ademe.dev]
    branch: main
    resources: { memory: 512M, cpu_weight: 64 }
    live: true
    stage: preprod
  koyo:
    repo: incubateur-ademe/koyo
    platform: koyeb
    hosts: [koyo.example.org]
    branch: main
    resources: { memory: 512M, cpu_weight: 64 }
`

func TestMainStages(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	inv := t.TempDir() + "/inventaire.yaml"
	if err := os.WriteFile(inv, []byte(stagesInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"COOLIFY_URL":              srv.URL,
		"COOLIFY_TOKEN":            testToken,
		"WAF_OPS_PROJECT_UUID":     "proj-waf",
		"WAF_OPS_SERVER_UUID":      "srv-waf-1",
		"WAF_OPS_DESTINATION_UUID": "dest-waf",
		"WAF_OPS_GITHUB_APP_UUID":  ghAppUUID,
	}
	main := func(args ...string) (string, error) {
		var out, errw bytes.Buffer
		err := Main(context.Background(), append([]string{"--etc", "../..", "--inventaire", inv}, args...),
			func(k string) string { return env[k] }, &out, &errw)
		return out.String(), err
	}

	out, err := main()
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "waf-koyo-1 : création")
	if strings.Contains(out, "waf-pilote") {
		t.Fatalf("app de preprod traitée sur la VM 1 :\n%s", out)
	}
	if _, err := main("--app", "waf-pilote"); err == nil || !strings.Contains(err.Error(), "app waf-pilote en stage preprod, VM 1 en stage prod") {
		t.Fatalf("erreur = %v", err)
	}

	env["WAF_OPS_VM"], env["WAF_OPS_SERVER_UUID"], env["WAF_OPS_DESTINATION_UUID"] = "preprod", "srv-waf-preprod", "dest-waf-preprod"
	out, err = main()
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "waf-waf-pilote-preprod : création", "jumeau waf-waf-pilote-1 sur un autre serveur")
	if strings.Contains(out, "koyo") {
		t.Fatalf("app de prod traitée sur la VM preprod :\n%s", out)
	}

	env["WAF_OPS_VM"] = "2"
	if _, err := main(); err == nil || !strings.Contains(err.Error(), `VM "2" absente de vms`) {
		t.Fatalf("erreur = %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}
}

func preprodConfig(url string) Config {
	c := testConfig(url)
	c.VM, c.ServerUUID, c.DestinationUUID, c.OtherVMs = "preprod", "srv-waf-preprod", "dest-waf-preprod", []string{"1"}
	return c
}

func runCfg(t *testing.T, cfg Config, apps []inventory.App, apply bool) (string, error) {
	t.Helper()
	c, err := coolify.New(cfg.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = Run(context.Background(), c, cfg, apps, apply, &out)
	if strings.Contains(out.String(), testToken) || (err != nil && strings.Contains(err.Error(), testToken)) {
		t.Fatalf("jeton dans la sortie")
	}
	return out.String(), err
}

// Le pilote migre de waf-1 vers la VM de preprod : son jumeau -1 tient encore le
// domaine, que Coolify refuse sans force_domain_override.
func TestJumeauSurUneAutreVM(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	apps := testApps(t, "waf-pilote")

	sans := preprodConfig(srv.URL)
	sans.OtherVMs = nil
	if _, err := runCfg(t, sans, apps, true); err == nil || !strings.Contains(err.Error(), "waf-pilote.incubateur.ademe.dev par waf-waf-pilote-1 (application)") {
		t.Fatalf("création sans jumeau connu : %v", err)
	}

	n0 := len(f.writes)
	out, err := runCfg(t, preprodConfig(srv.URL), apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "waf-waf-pilote-preprod : création", "jumeau waf-waf-pilote-1 sur un autre serveur : force_domain_override si Coolify ne signale de conflit de domaine qu'avec lui", "idempotence vérifiée")
	a := f.appByName("waf-waf-pilote-preprod")
	if a == nil || a.dest != "dest-waf-preprod" || a.data["fqdn"] != "https://waf-pilote.incubateur.ademe.dev" {
		t.Fatalf("app preprod : %+v", a)
	}
	creates := 0
	for i := n0; i < len(f.writes); i++ {
		if f.writes[i] == "POST /api/v1/applications/private-github-app" {
			creates++
			if forced := strings.Contains(f.bodies[i], `"force_domain_override":true`); forced != (creates == 2) {
				t.Fatalf("création %d : force_domain_override=%t, attendu au seul second essai", creates, forced)
			}
		}
	}
	if creates != 2 {
		t.Fatalf("%d créations, 2 attendues : sans l'option, puis avec après le 409 du jumeau", creates)
	}
	if strings.Contains(out[strings.Index(out, "second calcul"):], "jumeau") {
		t.Fatalf("note de jumeau sans écriture de domaine :\n%s", out)
	}

	// Un changement de domaine sur l'app existante repasse l'option.
	a.data["fqdn"] = "http://waf-pilote.incubateur.ademe.dev"
	n := len(f.bodies)
	out, err = runCfg(t, preprodConfig(srv.URL), apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(f.bodies[n:], "\n"), `"force_domain_override":true`) {
		t.Fatalf("PATCH des domaines sans force_domain_override :\n%s", strings.Join(f.bodies[n:], "\n"))
	}
}

func TestJumeauSurLeMemeServeurRefuse(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	cfg := preprodConfig(srv.URL)
	cfg.ServerUUID, cfg.DestinationUUID = "srv-waf-1", "dest-waf"
	_, err := runCfg(t, cfg, testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "jumeau waf-waf-pilote-1 sur le serveur srv-waf-1, celui de WAF_OPS_SERVER_UUID : WAF_OPS_VM=preprod") {
		t.Fatalf("erreur = %v", err)
	}
	if len(f.writes) != 0 || f.appByName("waf-waf-pilote-preprod") != nil {
		t.Fatalf("écritures : %v", f.writes)
	}
}

func TestConflitHorsDuJumeau(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	f.addApp("site-vitrine", "dest-coolify", map[string]any{"fqdn": "https://waf-pilote.incubateur.ademe.dev"})
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	_, err := runCfg(t, preprodConfig(srv.URL), testApps(t, "waf-pilote"), true)
	if err == nil || !strings.Contains(err.Error(), "par site-vitrine (application)") {
		t.Fatalf("erreur = %v", err)
	}
	if strings.Contains(strings.Join(f.bodies, "\n"), "force_domain_override") || f.appByName("waf-waf-pilote-preprod") != nil {
		t.Fatalf("domaine forcé malgré un conflit hors du jumeau :\n%s", strings.Join(f.bodies, "\n"))
	}
}

func TestBaseParServeur(t *testing.T) {
	f, srv := newFake(t, testToken)
	pilotApp(f)
	f.addShared("UPSTREAM_WAF_PILOTE", ptr(pilotUpstream))
	apps := testApps(t, "waf-pilote")
	cfg := testConfig(srv.URL)
	cfg.BaseRef = "{{server.WAF_BASE}}"

	out, err := runCfg(t, cfg, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "action ops : créer WAF_BASE avec sa valeur dans l'UI Coolify (variables partagées du serveur), puis relancer provision")
	if v := f.appByName("waf-waf-pilote-1").env("WAF_BASE"); v == nil || *v.Value != "{{team.WAF_BASE}}" {
		t.Fatalf("WAF_BASE changée sans variable de serveur : %+v", v)
	}

	f.addServerShared("srv-waf-1", "WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:4a96"))
	out, err = runCfg(t, cfg, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `~ env WAF_BASE : "{{team.WAF_BASE}}" -> "{{server.WAF_BASE}}"`,
		"WAF_BASE : la base des apps de la VM 1 passe de {{team.WAF_BASE}} à {{server.WAF_BASE}} au prochain build", "idempotence vérifiée")
	if v := f.appByName("waf-waf-pilote-1").env("WAF_BASE"); v == nil || *v.Value != "{{server.WAF_BASE}}" || !v.Buildtime || v.Runtime {
		t.Fatalf("WAF_BASE : %+v", v)
	}

	cfg.ServerUUID, cfg.DestinationUUID = "srv-inconnu", "dest-waf"
	if _, err := runCfg(t, cfg, apps, false); err == nil {
		t.Fatal("destination d'un autre serveur acceptée")
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

func TestReferencesOptionnelles(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.setEnv(f, "WAF_DETECTION_UNTIL", ptr("{{team.DETECTION_UNTIL_WAF_PILOTE}}"), false, true)
	a.setEnv(f, "WAF_UNINSPECTED_PATHS", ptr("/metrics"), false, true)
	a.setEnv(f, "WAF_FORCE_DETECTION", ptr("{{ team.FORCE_DETECTION_WAF_PILOTE }}"), false, true)
	f.addShared("FORCE_DETECTION_WAF_PILOTE", ptr("2026-11-17T00:00:00+01:00"))
	apps := testApps(t, "waf-pilote")

	out, err := run(t, srv.URL, apps, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("écritures sans --apply : %v", f.writes)
	}
	mustContain(t, out,
		`~ env WAF_DETECTION_UNTIL : "{{team.DETECTION_UNTIL_WAF_PILOTE}}" -> ""`,
		"WAF_DETECTION_UNTIL : référence orpheline, wafgen run refuserait de démarrer ; vidée, DETECTION_UNTIL_WAF_PILOTE étant absente",
		`WAF_UNINSPECTED_PATHS : valeur littérale "/metrics" conservée, UNINSPECTED_PATHS_WAF_PILOTE étant absente`,
	)
	if strings.Contains(out, "env WAF_FORCE_DETECTION") || strings.Contains(out, "env WAF_UNINSPECTED_PATHS") || strings.Contains(out, "- env") {
		t.Fatalf("écart inattendu :\n%s", out)
	}

	out, err = run(t, srv.URL, apps, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	for _, w := range f.writes {
		if strings.HasPrefix(w, "DELETE ") {
			t.Fatalf("suppression demandée, le jeton SecOps n'a pas l'ability delete : %v", f.writes)
		}
	}
	if e := a.env("WAF_DETECTION_UNTIL"); e == nil || e.Value != nil || e.Buildtime || !e.Runtime {
		t.Fatalf("référence orpheline non neutralisée : %+v", e)
	}
	if v := a.env("WAF_UNINSPECTED_PATHS").Value; v == nil || *v != "/metrics" {
		t.Fatalf("WAF_UNINSPECTED_PATHS littérale modifiée : %v", v)
	}
	if v := a.env("WAF_FORCE_DETECTION").Value; v == nil || *v != "{{ team.FORCE_DETECTION_WAF_PILOTE }}" {
		t.Fatalf("WAF_FORCE_DETECTION : %v", v)
	}
}

func TestReferenceRequiseOrphelineConservee(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	a := f.addApp("waf-koyo-1", "dest-waf", nil)
	a.setEnv(f, "UPSTREAM", ptr("{{team.UPSTREAM_KOYO}}"), false, true)
	out, err := run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out,
		"UPSTREAM : référence orpheline, wafgen run refuserait de démarrer\n",
		"action ops : créer UPSTREAM_KOYO avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis redéployer l'app\n",
		"idempotence vérifiée",
	)
	if strings.Contains(out, "UPSTREAM n'est pas posée") {
		t.Fatalf("note « n'est pas posée » alors que l'app porte UPSTREAM :\n%s", out)
	}
	if strings.Contains(out, "- env UPSTREAM") || a.env("UPSTREAM") == nil {
		t.Fatalf("UPSTREAM requise supprimée :\n%s", out)
	}
	for _, w := range f.writes {
		if strings.HasPrefix(w, "DELETE ") {
			t.Fatalf("suppression d'une référence requise : %s", w)
		}
	}
}

func TestFauxCoolifyRefuseUneValeurPartageeVide(t *testing.T) {
	f, srv := newFake(t, testToken)
	for _, v := range []string{"", "   "} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/team/envs", strings.NewReader(`{"key":"UPSTREAM_X","value":"`+v+`"}`))
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 500 {
			t.Fatalf("valeur %q : HTTP %d, 500 attendu comme Coolify 4.7.5", v, resp.StatusCode)
		}
	}
	if f.shared("UPSTREAM_X") != nil {
		t.Fatal("variable vide créée")
	}
	f.writes = nil
}

const wafBaseLiteral = "ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"

func TestWafBaseLitteraleGardee(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		team         *string
	}{
		{"absente", "action ops : créer WAF_BASE avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision pour remplacer la valeur littérale", nil},
		{"vide", "action ops : remplir WAF_BASE dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision pour remplacer la valeur littérale", ptr("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFake(t, testToken)
			a := pilotApp(f)
			a.env("WAF_BASE").Value = ptr(wafBaseLiteral)
			f.team = nil
			if tc.team != nil {
				f.addShared("WAF_BASE", tc.team)
			}
			out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if strings.Contains(out, "env WAF_BASE") {
				t.Fatalf("WAF_BASE littérale réécrite :\n%s", out)
			}
			mustContain(t, out, `WAF_BASE : valeur littérale "`+wafBaseLiteral+`" conservée, WAF_BASE étant `+tc.name, tc.action, "idempotence vérifiée")
			if v := a.env("WAF_BASE").Value; v == nil || *v != wafBaseLiteral {
				t.Fatalf("WAF_BASE = %v", v)
			}
		})
	}

	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.env("WAF_BASE").Value = ptr(wafBaseLiteral)
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `~ env WAF_BASE : "`+wafBaseLiteral+`" -> "{{team.WAF_BASE}}"`, "idempotence vérifiée")
}

func TestWafBaseNonPoseeSansCle(t *testing.T) {
	f, srv := newFake(t, testToken)
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "action ops : créer WAF_BASE avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision ; d'ici là WAF_BASE n'est pas posée et le build échoue", "idempotence vérifiée")
	if strings.Contains(out, "env WAF_BASE") || f.appByName("waf-waf-pilote-1").env("WAF_BASE") != nil {
		t.Fatalf("WAF_BASE posée sans variable d'équipe :\n%s", out)
	}
	if strings.Count(out, "créer WAF_BASE") != 1 {
		t.Fatalf("note WAF_BASE en double :\n%s", out)
	}
}

func TestCleEquipeVide(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr(wafBaseLiteral))
	f.addShared("UPSTREAM_KOYO", ptr(""))
	f.addShared("DETECTION_UNTIL_KOYO", ptr(""))
	f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
	out, err := run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "env UPSTREAM") || strings.Contains(out, "créer UPSTREAM_KOYO") {
		t.Fatalf("référence requise posée sur une clé vide, ou création demandée d'une clé existante :\n%s", out)
	}
	mustContain(t, out,
		"action ops : remplir UPSTREAM_KOYO dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision ; d'ici là UPSTREAM n'est pas posée et wafgen run refuse de démarrer",
		`+ env WAF_DETECTION_UNTIL = "{{team.DETECTION_UNTIL_KOYO}}"`,
		`+ env ORIGIN_TOKEN = "{{team.ORIGIN_TOKEN_KOYO}}"`,
		"idempotence vérifiée",
	)
	koyo := f.appByName("waf-koyo-1")
	if koyo.env("UPSTREAM") != nil || koyo.env("WAF_DETECTION_UNTIL") == nil {
		t.Fatalf("variables : UPSTREAM=%v WAF_DETECTION_UNTIL=%v", koyo.env("UPSTREAM"), koyo.env("WAF_DETECTION_UNTIL"))
	}
}

func TestCleEquipeIllisible(t *testing.T) {
	for _, tc := range []struct {
		name, cause    string
		locked, hidden bool
	}{
		{"verrouillée", "variable verrouillée", true, false},
		{"sans read:sensitive", "jeton sans read:sensitive", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFake(t, testToken)
			f.addShared("WAF_BASE", ptr(wafBaseLiteral))
			f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
			s := f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
			s.Locked, s.Hidden = tc.locked, tc.hidden
			out, err := run(t, srv.URL, testApps(t, "koyo"), true)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			mustContain(t, out,
				`+ env ORIGIN_TOKEN = "{{team.ORIGIN_TOKEN_KOYO}}"`,
				"valeur de ORIGIN_TOKEN_KOYO illisible ("+tc.cause+") : non vérifiée",
				"idempotence vérifiée",
			)
			if strings.Contains(out, "action ops") {
				t.Fatalf("action ops sur une clé illisible :\n%s", out)
			}
		})
	}
}

func TestValeurEnPlaceGardee(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	a.setEnv(f, "WAF_UNINSPECTED_PATHS", nil, false, true)
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "env WAF_UNINSPECTED_PATHS") {
		t.Fatalf("référence inutilisable posée :\n%s", out)
	}
	mustContain(t, out, "idempotence vérifiée")
	if e := a.env("WAF_UNINSPECTED_PATHS"); e == nil || e.Value != nil {
		t.Fatalf("WAF_UNINSPECTED_PATHS : %+v", e)
	}
}

func koyoApps(t *testing.T, canonical string) []inventory.App {
	t.Helper()
	y := strings.Replace(testInventory, "hosts: [koyo.example.org, www.koyo.example.org]\n",
		"hosts: [koyo.example.org, www.koyo.example.org]\n    canonical: "+canonical+"\n", 1)
	apps, err := inventory.Parse([]byte(y), map[string]bool{"scalingo": true, "koyeb": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.Name == "koyo" {
			return []inventory.App{a}
		}
	}
	t.Fatal("app koyo absente")
	return nil
}

func TestCanonicalPoseeModifieeVidee(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
	f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))

	out, err := run(t, srv.URL, koyoApps(t, "koyo.example.org"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `+ env WAF_CANONICAL_HOST = "koyo.example.org"`, "idempotence vérifiée")
	a := f.appByName("waf-koyo-1")
	if e := a.env("WAF_CANONICAL_HOST"); e == nil || e.Value == nil || *e.Value != "koyo.example.org" || e.Buildtime || !e.Runtime {
		t.Fatalf("WAF_CANONICAL_HOST : %+v", e)
	}

	out, err = run(t, srv.URL, koyoApps(t, "www.koyo.example.org"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `~ env WAF_CANONICAL_HOST : "koyo.example.org" -> "www.koyo.example.org"`, "idempotence vérifiée")

	out, err = run(t, srv.URL, testApps(t, "koyo"), false)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, `~ env WAF_CANONICAL_HOST : "www.koyo.example.org" -> ""`, "1 changement(s) prévu(s)")
	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	if e := a.env("WAF_CANONICAL_HOST"); e == nil || e.Value != nil {
		t.Fatalf("WAF_CANONICAL_HOST non vidée : %+v", e)
	}
	for _, w := range f.writes {
		if strings.HasPrefix(w, "DELETE ") {
			t.Fatalf("suppression demandée, le jeton SecOps n'a pas l'ability delete : %v", f.writes)
		}
	}

	n := len(f.writes)
	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil || len(f.writes) != n {
		t.Fatalf("passage sans canonical : %v, %d écritures\n%s", err, len(f.writes)-n, out)
	}
	if strings.Contains(out, "WAF_CANONICAL_HOST") {
		t.Fatalf("WAF_CANONICAL_HOST vide encore citée :\n%s", out)
	}
}

func TestCanonicalAbsenteNonCreee(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "WAF_CANONICAL_HOST") || a.env("WAF_CANONICAL_HOST") != nil {
		t.Fatalf("WAF_CANONICAL_HOST posée sans canonical :\n%s", out)
	}
}

const edgeSecretFactice = "secret-edge-factice-0123456789abcdef-ABCDEF"

func koyoEdge(t *testing.T) []inventory.App {
	t.Helper()
	y := strings.Replace(testInventory, "hosts: [koyo.example.org, www.koyo.example.org]\n",
		"hosts: [koyo.example.org, www.koyo.example.org]\n    edge: cloudflare\n", 1)
	apps, err := inventory.Parse([]byte(y), map[string]bool{"scalingo": true, "koyeb": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.Name == "koyo" {
			return []inventory.App{a}
		}
	}
	t.Fatal("app koyo absente")
	return nil
}

func noDelete(t *testing.T, f *fakeCoolify) {
	t.Helper()
	for _, w := range f.writes {
		if strings.HasPrefix(w, "DELETE ") {
			t.Fatalf("suppression demandée, le jeton SecOps n'a pas l'ability delete : %v", f.writes)
		}
	}
}

func TestEdgePoseeEtVidee(t *testing.T) {
	f, srv := newFake(t, testToken)
	f.addShared("WAF_BASE", ptr("ghcr.io/incubateur-ademe/waf-base@sha256:f4bc"))
	f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
	f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
	var outs []string

	out, err := run(t, srv.URL, koyoEdge(t), true)
	outs = append(outs, out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out,
		"action ops : créer EDGE_SECRET_KOYO avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision ; d'ici là WAF_EDGE_SECRET n'est pas posée et le WAF garde l'IP vue par Traefik",
		"WAF_EDGE retenue tant que EDGE_SECRET_KOYO n'est pas remplie",
		"idempotence vérifiée",
	)
	if strings.Contains(out, "env WAF_EDGE") || strings.Contains(out, "refuse de démarrer") {
		t.Fatalf("WAF_EDGE posée sans secret, ou démarrage refusé annoncé :\n%s", out)
	}
	a := f.appByName("waf-koyo-1")
	for _, k := range []string{"WAF_EDGE", "WAF_EDGE_SECRET"} {
		if e := a.env(k); e != nil {
			t.Fatalf("%s créée sans la variable d'équipe : %+v", k, e)
		}
	}

	f.addShared("EDGE_SECRET_KOYO", ptr(edgeSecretFactice))
	out, err = run(t, srv.URL, koyoEdge(t), true)
	outs = append(outs, out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out,
		`+ env WAF_EDGE_SECRET = "{{team.EDGE_SECRET_KOYO}}"`,
		`+ env WAF_EDGE = "cloudflare"`,
		"idempotence vérifiée",
	)
	if strings.Contains(out, "retenue") {
		t.Fatalf("WAF_EDGE encore retenue avec le secret rempli :\n%s", out)
	}
	if e := a.env("WAF_EDGE_SECRET"); e == nil || e.Value == nil || *e.Value != "{{team.EDGE_SECRET_KOYO}}" || e.Buildtime || !e.Runtime {
		t.Fatalf("WAF_EDGE_SECRET : %+v", e)
	}
	if e := a.env("WAF_EDGE"); e == nil || e.Value == nil || *e.Value != "cloudflare" || e.Buildtime || !e.Runtime {
		t.Fatalf("WAF_EDGE : %+v", e)
	}

	out, err = run(t, srv.URL, testApps(t, "koyo"), false)
	outs = append(outs, out)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		`~ env WAF_EDGE : "cloudflare" -> ""`,
		`~ env WAF_EDGE_SECRET : "{{team.EDGE_SECRET_KOYO}}" -> ""`,
		"2 changement(s) prévu(s)",
	)
	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	outs = append(outs, out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "idempotence vérifiée")
	for _, k := range []string{"WAF_EDGE", "WAF_EDGE_SECRET"} {
		if e := a.env(k); e == nil || e.Value != nil {
			t.Fatalf("%s non vidée : %+v", k, e)
		}
	}
	noDelete(t, f)

	n := len(f.writes)
	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	outs = append(outs, out)
	if err != nil || len(f.writes) != n {
		t.Fatalf("passage sans edge : %v, %d écritures\n%s", err, len(f.writes)-n, out)
	}
	if strings.Contains(out, "WAF_EDGE") || strings.Contains(out, "EDGE_SECRET") {
		t.Fatalf("variables d'edge vides encore citées :\n%s", out)
	}
	if v := f.shared("EDGE_SECRET_KOYO").Value; v == nil || *v != edgeSecretFactice {
		t.Fatal("variable d'équipe modifiée")
	}
	for _, o := range outs {
		if strings.Contains(o, edgeSecretFactice) {
			t.Fatalf("secret d'edge dans la sortie :\n%s", o)
		}
	}
}

func TestEdgeAbsenteNonCreee(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := pilotApp(f)
	out, err := run(t, srv.URL, testApps(t, "waf-pilote"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "EDGE") || a.env("WAF_EDGE") != nil || a.env("WAF_EDGE_SECRET") != nil {
		t.Fatalf("variables d'edge posées sans edge :\n%s", out)
	}
}

func TestEdgeSecretLitteralMasque(t *testing.T) {
	f, srv := newFake(t, testToken)
	a := f.addApp("waf-koyo-1", "dest-waf", nil)
	a.setEnv(f, "WAF_EDGE_SECRET", ptr(edgeSecretFactice), false, true)

	out, err := run(t, srv.URL, koyoEdge(t), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out,
		"WAF_EDGE_SECRET : valeur littérale (valeur masquée) conservée, EDGE_SECRET_KOYO étant absente",
		`+ env WAF_EDGE = "cloudflare"`,
		"idempotence vérifiée",
	)
	if strings.Contains(out, edgeSecretFactice) {
		t.Fatalf("secret littéral affiché :\n%s", out)
	}
	if e := a.env("WAF_EDGE_SECRET"); e.Value == nil || *e.Value != edgeSecretFactice {
		t.Fatalf("WAF_EDGE_SECRET littérale modifiée : %+v", e)
	}

	out, err = run(t, srv.URL, testApps(t, "koyo"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, `~ env WAF_EDGE_SECRET : (valeur masquée) -> ""`, "idempotence vérifiée")
	if strings.Contains(out, edgeSecretFactice) {
		t.Fatalf("secret littéral affiché au retrait :\n%s", out)
	}
	if e := a.env("WAF_EDGE_SECRET"); e.Value != nil {
		t.Fatalf("WAF_EDGE_SECRET non vidée : %+v", e)
	}
	noDelete(t, f)
}

func TestEdgeRetenueOuGardee(t *testing.T) {
	ref := ptr("{{team.EDGE_SECRET_KOYO}}")
	for _, tc := range []struct {
		name      string
		team      *string
		secret    *string
		edge      *string
		notes     []string
		edgeAfter *string
	}{
		{
			name: "clé vide",
			team: ptr(""),
			notes: []string{
				"action ops : remplir EDGE_SECRET_KOYO dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision ; d'ici là WAF_EDGE_SECRET n'est pas posée et le WAF garde l'IP vue par Traefik",
				"WAF_EDGE retenue tant que EDGE_SECRET_KOYO n'est pas remplie",
			},
		},
		{
			name:   "référence en place, clé vide",
			team:   ptr(""),
			secret: ref,
			notes: []string{
				"action ops : remplir EDGE_SECRET_KOYO dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision\n",
				"WAF_EDGE retenue tant que EDGE_SECRET_KOYO n'est pas remplie",
			},
		},
		{
			name:   "WAF_EDGE en place, clé supprimée",
			secret: ref,
			edge:   ptr("cloudflare"),
			notes: []string{
				"WAF_EDGE_SECRET : référence orpheline, wafgen run refuserait de démarrer\n",
				"action ops : créer EDGE_SECRET_KOYO avec sa valeur dans l'UI Coolify (variables partagées de l'équipe), puis redéployer l'app\n",
			},
			edgeAfter: ptr("cloudflare"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFake(t, testToken)
			f.addShared("WAF_BASE", ptr(wafBaseLiteral))
			f.addShared("UPSTREAM_KOYO", ptr("https://koyo.koyeb.app"))
			f.addShared("ORIGIN_TOKEN_KOYO", ptr("jeton-origine-koyo"))
			if tc.team != nil {
				f.addShared("EDGE_SECRET_KOYO", tc.team)
			}
			a := f.addApp("waf-koyo-1", "dest-waf", nil)
			if tc.secret != nil {
				a.setEnv(f, "WAF_EDGE_SECRET", tc.secret, false, true)
			}
			if tc.edge != nil {
				a.setEnv(f, "WAF_EDGE", tc.edge, false, true)
			}
			out, err := run(t, srv.URL, koyoEdge(t), true)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			mustContain(t, out, append(tc.notes, "idempotence vérifiée")...)
			if strings.Contains(out, "env WAF_EDGE") {
				t.Fatalf("variable d'edge écrite sans secret utilisable :\n%s", out)
			}
			if tc.edgeAfter == nil && strings.Contains(out, "redéployer l'app") {
				t.Fatalf("redéploiement annoncé alors que WAF_EDGE attend provision :\n%s", out)
			}
			if tc.edgeAfter != nil && strings.Contains(out, "retenue") {
				t.Fatalf("WAF_EDGE en place annoncée retenue :\n%s", out)
			}
			e := a.env("WAF_EDGE")
			switch {
			case tc.edgeAfter == nil && e != nil:
				t.Fatalf("WAF_EDGE posée : %+v", e)
			case tc.edgeAfter != nil && (e == nil || e.Value == nil || *e.Value != *tc.edgeAfter):
				t.Fatalf("WAF_EDGE en place modifiée : %+v", e)
			}
			noDelete(t, f)
		})
	}
}
