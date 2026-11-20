package ops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
)

const Usage = `wafgen ops [controle | fgp-scopes]

  (sans argument)  boucle : contrôle toutes les 5 minutes, pulse updown, état dans WAF_OPS_STATE
  controle         un passage : notes et écarts sur la sortie, code 1 s'il y a un écart ; pas de pulse
  fgp-scopes       demandes de blobs d'API de lecture, une par région, au format de /api/generate de FGP

Contrôle : pour chaque app live et Scalingo des stages traités, règles du
firewall égales aux IP des VM de son stage si LOCK_<APP> est posée, et chaque
host rattaché à l'app en host_header visitor.

Environnement : COOLIFY_URL, COOLIFY_TOKEN (read:sensitive, pour UPSTREAM_<APP>),
WAF_OPS_STAGES (prod, preprod, ou les deux séparés par une virgule),
WAF_OPS_FGP ({"url", "api": {"<région>": "<blob>"}}), WAF_OPS_FGP_KEY,
WAF_OPS_PULSE_URL (boucle), WAF_OPS_INVENTAIRE (inventaire de main),
WAF_OPS_ETC (/etc/waf), WAF_OPS_STATE (/var/lib/waf-ops).`

var nowFunc = time.Now

// Main lance la commande ops. ctx s'annule à SIGTERM : la boucle s'arrête entre
// deux passages.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ops", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, Usage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := ""
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("argument inattendu : %s", fs.Arg(1))
	}
	mode := ModeBoucle
	switch cmd {
	case "":
	case "controle":
		mode = ModeControle
	case "fgp-scopes":
		mode = ModeScopes
	default:
		fs.Usage()
		return flag.ErrHelp
	}
	cfg, err := LoadConfig(getenv, mode)
	if err != nil {
		return err
	}
	cl, err := coolify.New(cfg.CoolifyURL, cfg.CoolifyToken)
	if err != nil {
		return err
	}
	if mode == ModeScopes {
		s, err := Scopes(ctx, cfg, cl)
		if err != nil {
			return err
		}
		return writeScopes(stdout, s)
	}
	d := Deps{Coolify: cl, Scalingo: NewFGPClient(cfg.FGP), Now: nowFunc}
	if mode == ModeControle {
		r, err := Controle(ctx, cfg, d)
		for _, n := range r.Notes {
			fmt.Fprintf(stdout, "note : %s\n", n)
		}
		for _, e := range r.Ecarts {
			fmt.Fprintf(stdout, "écart : %s\n", e)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%d app(s) contrôlée(s), %d écart(s)\n", r.Apps, len(r.Ecarts))
		if len(r.Ecarts) > 0 {
			return fmt.Errorf("%d écart(s)", len(r.Ecarts))
		}
		return nil
	}
	l := log.New(stderr, "wafgen ops: ", 0)
	l.Printf("boucle : stages %v, contrôle toutes les %s", cfg.StageList(), Interval)
	Boucle(ctx, cfg, d, HTTPPulse{URL: cfg.PulseURL}, l.Printf, Interval)
	l.Printf("arrêt")
	return nil
}
