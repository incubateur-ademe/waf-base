package inventory

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

func platforms(t *testing.T) map[string]bool {
	t.Helper()
	pol, err := policy.Load("../../policy")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for k := range pol.Origines {
		out[k] = true
	}
	return out
}

func TestInventaireDuRepo(t *testing.T) {
	b, err := os.ReadFile("../../inventaire.yaml")
	if err != nil {
		t.Fatal(err)
	}
	apps, err := Parse(b, platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0].Name != "tacct" || apps[1].Name != "waf-pilote" {
		t.Fatalf("apps = %+v", apps)
	}
	p := apps[1]
	if p.Branch != "main" || p.WafDir != "waf" || p.Memory != "512M" || p.CPUWeight != 64 || !p.Live || p.HostHeader != "visitor" {
		t.Fatalf("défauts mal fusionnés : %+v", p)
	}
	if apps[0].HostHeader != "upstream" || apps[0].Live {
		t.Fatalf("valeurs de tacct : %+v", apps[0])
	}
	want := "events_per_second=100,upload_max_size=100MiB,detection_only_max_days=14"
	if got := p.Ceilings.Env(); got != want {
		t.Fatalf("WAF_CEILINGS = %q, attendu %q", got, want)
	}
	c, err := render.ParseCeilings(p.Ceilings.Env())
	if err != nil || c != render.DefaultCeilings() {
		t.Fatalf("WAF_CEILINGS relu = %+v, %v ; attendu les défauts de render", c, err)
	}
}

const base = `
defaults:
  ceilings: { events_per_second: 100, upload_max_size: 100MiB, detection_only_max_days: 14 }
  host_header: visitor
  branch: main
  resources: { memory: 512M, cpu_weight: 64 }
  waf_dir: waf
  internal_events: 0
apps:
`

func TestSurcharge(t *testing.T) {
	y := base + `
  app-a:
    repo: incubateur-ademe/a
    platform: koyeb
    hosts: [a.example.org]
    branch: production
    waf_dir: waf/app-a
    resources: { memory: 1G }
    ceilings: { events_per_second: 300, upload_max_size: 20MiB }
    crs_plugins: [wordpress-rule-exclusions]
    live: true
  app-b:
    repo: incubateur-ademe/b
    platform: scalingo
    hosts: [b.example.org, www.b.example.org]
`
	apps, err := Parse([]byte(y), platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	a, b := apps[0], apps[1]
	if a.Branch != "production" || a.WafDir != "waf/app-a" || a.Memory != "1G" || a.CPUWeight != 64 {
		t.Fatalf("surcharge de app-a : %+v", a)
	}
	if a.LimitsMemory() != "1g" || b.LimitsMemory() != "512m" {
		t.Fatalf("limits_memory : %q, %q", a.LimitsMemory(), b.LimitsMemory())
	}
	if got := a.Ceilings.Env(); got != "events_per_second=300,upload_max_size=20MiB,detection_only_max_days=14" {
		t.Fatalf("plafonds de app-a : %q", got)
	}
	c, err := render.ParseCeilings(a.Ceilings.Env())
	if err != nil || c.EventsPerSecond != 300 || c.UploadMaxSize != 20<<20 || c.DetectionOnlyMaxDays != 14 {
		t.Fatalf("plafonds relus : %+v, %v", c, err)
	}
	if len(a.CRSPlugins) != 1 || len(b.CRSPlugins) != 0 || b.Live || b.Branch != "main" {
		t.Fatalf("app-b : %+v", b)
	}
	if a.EnvSuffix() != "APP_A" {
		t.Fatalf("suffixe : %q", a.EnvSuffix())
	}
}

func TestSansDefauts(t *testing.T) {
	y := `
apps:
  solo:
    repo: incubateur-ademe/solo
    platform: scalingo
    hosts: [solo.example.org]
    branch: main
    resources: { memory: 256M, cpu_weight: 32 }
`
	apps, err := Parse([]byte(y), platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := render.ParseCeilings(apps[0].Ceilings.Env())
	if err != nil || c != render.DefaultCeilings() {
		t.Fatalf("plafonds par défaut : %+v, %v", c, err)
	}
	if apps[0].WafDir != "waf" || apps[0].HostHeader != "visitor" {
		t.Fatalf("défauts intégrés : %+v", apps[0])
	}
}

func TestErreurs(t *testing.T) {
	app := func(extra string) string {
		return base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [a.example.org]\n" + extra
	}
	cases := []struct {
		nom, yaml, msg string
	}{
		{"champ inconnu", app("    upstream: https://x.osc-fr1.scalingo.io\n"), "upstream"},
		{"aucune app", base, "aucune app"},
		{"nom invalide", base + "  App_A:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [a.example.org]\n", "nom invalide"},
		{"plateforme inconnue", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: heroku\n    hosts: [a.example.org]\n", "heroku"},
		{"host invalide", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [A_B.example]\n", "WAF_HOSTS"},
		{"hosts absents", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n", "hosts manquants"},
		{"repo absent", base + "  app-a:\n    platform: scalingo\n    hosts: [a.example.org]\n", "repo"},
		{"host en double", app("") + "  app-b:\n    repo: incubateur-ademe/b\n    platform: scalingo\n    hosts: [a.example.org]\n", "revendiqué"},
		{"host avec virgule", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [\"a.example.org,b.example.org\"]\n", "un seul host"},
		{"host avec espace", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [\" a.example.org\"]\n", "un seul host"},
		{"host revendiqué via une virgule", app("") + "  app-b:\n    repo: incubateur-ademe/b\n    platform: scalingo\n    hosts: [\"b.example.org,a.example.org\"]\n", "un seul host"},
		{"mémoire", app("    resources: { memory: 512Mi }\n"), "resources.memory"},
		{"poids CPU", app("    resources: { cpu_weight: 1 }\n"), "cpu_weight"},
		{"taille d'upload", app("    ceilings: { upload_max_size: 100MB }\n"), "upload_max_size"},
		{"waf_dir hors du repo", app("    waf_dir: ../secret\n"), "waf_dir"},
		{"host_header", app("    host_header: origin\n"), "host_header"},
		{"plugin", app("    crs_plugins: [../x]\n"), "crs_plugins"},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml), platforms(t))
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("erreur = %v, attendu %q", err, c.msg)
			}
		})
	}
}

func TestReadRefuseHTTP(t *testing.T) {
	if _, err := Read(context.Background(), "http://example.org/inventaire.yaml"); err == nil {
		t.Fatal("URL http acceptée")
	}
}
