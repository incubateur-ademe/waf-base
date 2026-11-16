package provision

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/policy"
)

const Usage = `wafgen provision [--apply] [--app <nom>] [--inventaire <chemin|URL https>] [--etc /etc/waf]

Aligne les apps WAF de Coolify (jumeau -<WAF_OPS_VM>) sur l'inventaire. Sans
--apply, affiche le plan et n'écrit rien. Ne déclenche aucun déploiement.

Environnement : COOLIFY_URL, COOLIFY_TOKEN, WAF_OPS_PROJECT_UUID,
WAF_OPS_SERVER_UUID, WAF_OPS_DESTINATION_UUID, WAF_OPS_GITHUB_APP_UUID,
WAF_OPS_ENVIRONMENT (production), WAF_OPS_VM (1),
WAF_OPS_BASE_REF ({{team.WAF_BASE}}).`

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
	apps, err := inventory.Parse(b, platforms)
	if err != nil {
		return err
	}
	if *only != "" {
		var sel []inventory.App
		for _, a := range apps {
			if a.Name == *only {
				sel = append(sel, a)
			}
		}
		if len(sel) == 0 {
			return fmt.Errorf("app %q absente de l'inventaire", *only)
		}
		apps = sel
	}
	client, err := coolify.New(cfg.URL, cfg.Token)
	if err != nil {
		return err
	}
	return Run(ctx, client, cfg, apps, *apply, stdout)
}
