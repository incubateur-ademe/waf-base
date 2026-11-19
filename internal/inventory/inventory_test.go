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

// Le fichier du repo change à chaque mise en service : ce test n'en vérifie que les
// invariants. La fusion des défauts, canonical et edge ont leurs tests sur des
// inventaires factices.
func TestInventaireDuRepo(t *testing.T) {
	b, err := os.ReadFile("../../inventaire.yaml")
	if err != nil {
		t.Fatal(err)
	}
	apps, err := Parse(b, platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) == 0 {
		t.Fatal("inventaire du repo sans app")
	}
	for _, a := range apps {
		if _, err := render.ParseHosts(strings.Join(a.Hosts, ",")); err != nil {
			t.Fatalf("%s : WAF_HOSTS illisible par wafgen run : %v", a.Name, err)
		}
		if _, err := render.ParseCeilings(a.Ceilings.Env()); err != nil {
			t.Fatalf("%s : WAF_CEILINGS illisible par wafgen run : %v", a.Name, err)
		}
	}
}

const vms = `
vms:
  1: { stage: prod, ip: 192.0.2.10 }
  preprod: { stage: preprod, ip: 198.51.100.20 }
`

const base = vms + `defaults:
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
	y := vms + `apps:
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
	if apps[0].WafDir != "waf" || apps[0].HostHeader != "visitor" || apps[0].Stage != StageProd {
		t.Fatalf("défauts intégrés : %+v", apps[0])
	}
}

func TestCanonical(t *testing.T) {
	y := base + `
  app-a:
    repo: incubateur-ademe/a
    platform: scalingo
    hosts: [a.example.org, www.a.example.org]
    canonical: a.example.org
  app-b:
    repo: incubateur-ademe/b
    platform: scalingo
    hosts: [b.example.org, www.b.example.org]
`
	apps, err := Parse([]byte(y), platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	if apps[0].Canonical != "a.example.org" || apps[1].Canonical != "" {
		t.Fatalf("canonical : %q, %q", apps[0].Canonical, apps[1].Canonical)
	}
}

func TestEdge(t *testing.T) {
	y := base + `
  app-a:
    repo: incubateur-ademe/a
    platform: scalingo
    hosts: [a.example.org]
    edge: cloudflare
  app-b:
    repo: incubateur-ademe/b
    platform: scalingo
    hosts: [b.example.org]
`
	apps, err := Parse([]byte(y), platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	if apps[0].Edge != render.EdgeCloudflare || apps[1].Edge != "" {
		t.Fatalf("edge : %q, %q", apps[0].Edge, apps[1].Edge)
	}
}

func TestStages(t *testing.T) {
	y := base + `
  app-a:
    repo: incubateur-ademe/a
    platform: scalingo
    hosts: [a.example.org]
  app-b:
    repo: incubateur-ademe/b
    platform: scalingo
    hosts: [b.example.org]
    stage: preprod
`
	inv, err := Load([]byte(y), platforms(t))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Apps[0].Stage != StageProd || inv.Apps[1].Stage != StagePreprod {
		t.Fatalf("stages : %q, %q", inv.Apps[0].Stage, inv.Apps[1].Stage)
	}
	want := []VM{{Name: "1", Stage: StageProd, IP: "192.0.2.10"}, {Name: "preprod", Stage: StagePreprod, IP: "198.51.100.20"}}
	if len(inv.VMs) != 2 || inv.VMs[0] != want[0] || inv.VMs[1] != want[1] {
		t.Fatalf("vms : %+v", inv.VMs)
	}
	if v, ok := inv.VM("preprod"); !ok || v != want[1] {
		t.Fatalf("VM(preprod) : %+v, %t", v, ok)
	}
	if _, ok := inv.VM("2"); ok {
		t.Fatal("VM(2) trouvée")
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
		{"canonical hors des hosts", app("    canonical: www.a.example.org\n"), "canonical"},
		{"canonical d'une autre app", app("") + "  app-b:\n    repo: incubateur-ademe/b\n    platform: scalingo\n    hosts: [b.example.org]\n    canonical: a.example.org\n", "canonical"},
		{"canonical en majuscules", base + "  app-a:\n    repo: incubateur-ademe/a\n    platform: scalingo\n    hosts: [a.example.org]\n    canonical: A.example.org\n", "canonical"},
		{"canonical dans defaults", strings.Replace(app(""), "defaults:\n", "defaults:\n  canonical: a.example.org\n", 1), "canonical propre à une app, interdit dans defaults"},
		{"edge inconnu", app("    edge: fastly\n"), `edge "fastly" : cloudflare seule valeur admise`},
		{"edge en majuscules", app("    edge: Cloudflare\n"), "cloudflare seule valeur admise"},
		{"edge dans defaults", strings.Replace(app("    edge: cloudflare\n"), "defaults:\n", "defaults:\n  edge: cloudflare\n", 1), "edge propre à une app, interdit dans defaults"},
		{"stage inconnu", app("    stage: staging\n"), `stage "staging" : prod ou preprod`},
		{"stage dans defaults", strings.Replace(app(""), "defaults:\n", "defaults:\n  stage: preprod\n", 1), "stage propre à une app, interdit dans defaults"},
		{"stage sans VM", strings.Replace(app("    stage: preprod\n"), "  preprod: { stage: preprod, ip: 198.51.100.20 }\n", "", 1), "aucune VM du stage preprod"},
		{"vms absent", strings.Replace(app(""), vms, "", 1), "vms manquant"},
		{"nom de vm", strings.Replace(app(""), "  preprod:", "  Pre_prod:", 1), `vm "Pre_prod"`},
		{"stage de vm", strings.Replace(app(""), "{ stage: preprod,", "{ stage: recette,", 1), `stage "recette"`},
		{"ip de vm privée", strings.Replace(app(""), "198.51.100.20", "172.16.12.5", 1), "IPv4 publique attendue"},
		{"ip de vm en IPv6", strings.Replace(app(""), "198.51.100.20", "2001:db8::1", 1), "IPv4 publique attendue"},
		{"ip de vm illisible", strings.Replace(app(""), "198.51.100.20", "198.51.100.020", 1), "IPv4 publique attendue"},
		{"ip de vm en double", strings.Replace(app(""), "198.51.100.20", "192.0.2.10", 1), "portée par les vm 1 et preprod"},
		{"champ de vm inconnu", strings.Replace(app(""), "ip: 198.51.100.20 }", "ip: 198.51.100.20, server: x }", 1), "server"},
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
