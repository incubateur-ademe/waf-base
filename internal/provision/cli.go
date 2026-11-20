package provision

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

const Usage = `wafgen provision [--apply] [--app <nom>] [--inventaire <chemin|URL https>] [--etc /etc/waf]

Aligne les apps WAF de Coolify (waf-<app>-<WAF_OPS_VM>) sur l'inventaire, pour
les seules apps du stage de la VM. Pour une app en edge cloudflare, crée
EDGE_SECRET_<APP> si elle manque et pose la règle waf-edge-<app> de chacune de
ses edge_zones. Sans --apply, affiche le plan et n'écrit rien. Ne déclenche
aucun déploiement.

Environnement : COOLIFY_URL, COOLIFY_TOKEN, WAF_OPS_PROJECT_UUID,
WAF_OPS_SERVER_UUID, WAF_OPS_DESTINATION_UUID, WAF_OPS_GITHUB_APP_UUID,
WAF_OPS_ENVIRONMENT (production), WAF_OPS_VM (1, une VM de vms dans l'inventaire),
WAF_OPS_BASE_REF ({{team.WAF_BASE}}, ou {{server.WAF_BASE}} pour une base par VM),
CLOUDFLARE_API_TOKEN (requis pour une app avec edge_zones).`

// Main lit les options et l'environnement, puis lance provision. La configuration
// est vérifiée avant toute lecture réseau.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, Usage) }
	apply := fs.Bool("apply", false, "écrire les changements")
	only := fs.String("app", "", "ne traiter que cette app de l'inventaire")
	src := fs.String("inventaire", inventory.DefaultURL, "chemin ou URL https de l'inventaire")
	etc := fs.String("etc", "/etc/waf", "racine de la conf de base (policy/)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("argument inattendu : %s", fs.Arg(0))
	}
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return err
	}
	pol, err := policy.Load(filepath.Join(*etc, "policy"))
	if err != nil {
		return err
	}
	platforms := map[string]bool{}
	for k := range pol.Origines {
		platforms[k] = true
	}
	b, err := inventory.Read(ctx, *src)
	if err != nil {
		return err
	}
	inv, err := inventory.Load(b, platforms)
	if err != nil {
		return err
	}
	vm, ok := inv.VM(cfg.VM)
	if !ok {
		return fmt.Errorf("VM %q absente de vms dans l'inventaire", cfg.VM)
	}
	for _, v := range inv.VMs {
		if v.Name != vm.Name {
			cfg.OtherVMs = append(cfg.OtherVMs, v.Name)
		}
	}
	var apps []inventory.App
	found := false
	for _, a := range inv.Apps {
		if *only != "" && a.Name != *only {
			continue
		}
		found = true
		if a.Stage != vm.Stage {
			if *only != "" {
				return fmt.Errorf("app %s en stage %s, VM %s en stage %s", a.Name, a.Stage, vm.Name, vm.Stage)
			}
			continue
		}
		apps = append(apps, a)
	}
	if *only != "" && !found {
		return fmt.Errorf("app %q absente de l'inventaire", *only)
	}
	var zoned []string
	for _, a := range apps {
		if a.Edge == render.EdgeCloudflare && len(a.EdgeZones) > 0 {
			zoned = append(zoned, a.Name)
		}
	}
	if len(zoned) > 0 {
		if cfg.CloudflareToken == "" {
			return fmt.Errorf("%s manquant, requis pour les edge_zones de %s", cloudflare.TokenEnv, strings.Join(zoned, ", "))
		}
		cf, err := cloudflare.New(cfg.CloudflareToken)
		if err != nil {
			return err
		}
		cfg.Cloudflare = cf
	}
	client, err := coolify.New(cfg.URL, cfg.Token)
	if err != nil {
		return err
	}
	return Run(ctx, client, cfg, apps, *apply, stdout)
}
