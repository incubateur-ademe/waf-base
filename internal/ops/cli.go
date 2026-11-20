package ops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/coolify"
)

const Usage = `wafgen ops [controle | audit | github | cloudflare | fgp-scopes]

  (sans argument)  boucle : contrôle toutes les 5 minutes, audit toutes les heures, pulse updown,
                   état dans WAF_OPS_STATE
  controle         un contrôle : notes et écarts sur la sortie, code 1 s'il y a un écart ; pas de pulse
  audit            un audit depuis les curseurs de l'état, sans les avancer ni écrire l'état ; pas de pulse
  github           un audit GitHub, en lecture ; pas de pulse
  cloudflare       un audit Cloudflare, en lecture ; pas de pulse
  fgp-scopes       demandes de blobs d'API de lecture, une par région, au format de /api/generate de FGP

Contrôle : pour chaque app live et Scalingo des stages traités, règles du
firewall égales aux IP des VM de son stage si LOCK_<APP> est posée, et chaque
host rattaché à l'app en host_header visitor.

Audit : Activity Scalingo de chaque app depuis l'audit précédent (règles et
domaines ajoutés ou retirés, SCALINGO_FORBIDDEN_PAGE_URL), puis, si l'app est
verrouillée, 403 du firewall sur son origine ; DNS de chaque host vers les VM
de son stage (ou Cloudflare en edge) ; certificat servi par chaque VM à plus
de 21 jours de l'échéance ; plan de provision vide sur chaque VM, si
WAF_OPS_PROVISION est posée. Ses écarts restent dans le pulse jusqu'à l'audit
suivant.

Tâches facultatives, lancées si leurs variables sont posées : copie
quotidienne d'acme.json et poussée des certificats sur Scalingo
(WAF_OPS_ACME_SSH_KEY, WAF_OPS_ACME_KNOWN_HOSTS, WAF_OPS_ACME_VMS,
WAF_OPS_FGP_ECRITURE) ; audit GitHub horaire (WAF_OPS_GITHUB_APP_ID,
WAF_OPS_GITHUB_APP_KEY) ; audit Cloudflare horaire (CLOUDFLARE_API_TOKEN). Une
config incomplète met la tâche en échec à chaque passage, sans arrêter les
autres.

Environnement : COOLIFY_URL, COOLIFY_TOKEN (read:sensitive, pour UPSTREAM_<APP>),
WAF_OPS_STAGES (prod, preprod, ou les deux séparés par une virgule),
WAF_OPS_FGP ({"url", "api": {"<région>": "<blob>"}}), WAF_OPS_FGP_KEY,
WAF_OPS_PULSE_URL (boucle), WAF_OPS_INVENTAIRE (inventaire de main),
WAF_OPS_PROVISION ({"project", "environment", "github_app", "base_ref", "vms":
{"<vm>": {"server", "destination", "base_ref"}}}, facultative),
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
	case "controle", "audit", "github", "cloudflare":
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
	fgp := NewFGPClient(cfg.FGP)
	d := Deps{Coolify: cl, Scalingo: fgp, Origine: Sonde{}, DNS: net.DefaultResolver, Certs: TLSServi{}, Provision: cl, Domaines: fgp, Now: nowFunc}
	if cfg.Opt.CloudflareToken != "" {
		cf, err := cloudflare.New(cfg.Opt.CloudflareToken)
		if err != nil {
			return err
		}
		d.Cloudflare = cf
	}
	if mode == ModeControle {
		var r Rapport
		switch cmd {
		case TacheGitHub, TacheCloudflare:
			if msg, ko := cfg.Opt.Erreurs[cmd]; ko {
				return fmt.Errorf("%s : configuration : %s", cmd, msg)
			}
			if cmd == TacheGitHub {
				r, err = GitHub(ctx, cfg, d)
			} else {
				r, err = Cloudflare(ctx, cfg, d)
			}
		case "audit":
			e, lerr := LireEtat(cfg.State)
			if lerr != nil {
				return lerr
			}
			if last, ok := e.Taches["audit"]; ok {
				fmt.Fprintf(stdout, "dernier audit de la boucle : %s, %d écart(s)\n", last.A.UTC().Format(time.RFC3339), len(last.Ecarts))
				for _, x := range last.Ecarts {
					fmt.Fprintf(stdout, "  écart gardé dans le pulse : %s\n", x)
				}
				if last.Erreur != "" {
					fmt.Fprintf(stdout, "  erreur gardée dans le pulse : %s\n", last.Erreur)
				}
				fmt.Fprintln(stdout, "audit de maintenant :")
			}
			r, _, err = Audit(ctx, cfg, d, e.Taches["audit"].Curseurs)
		default:
			r, err = Controle(ctx, cfg, d)
		}
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
	l.Printf("boucle : stages %v, contrôle toutes les %s, audit toutes les %s", cfg.StageList(), Interval, PeriodeAudit)
	ts, absentes := Taches(cfg, d)
	noms := make([]string, 0, len(ts))
	for _, t := range ts {
		noms = append(noms, t.Nom)
	}
	l.Printf("tâches : %s", strings.Join(noms, ", "))
	if len(absentes) > 0 {
		l.Printf("tâches sans configuration, non lancées : %s", strings.Join(absentes, ", "))
	}
	ko := make([]string, 0, len(cfg.Opt.Erreurs))
	for nom := range cfg.Opt.Erreurs {
		ko = append(ko, nom)
	}
	sort.Strings(ko)
	for _, nom := range ko {
		l.Printf("%s : configuration : %s", nom, cfg.Opt.Erreurs[nom])
	}
	o := &Runner{Cfg: cfg, Deps: d, Pulse: HTTPPulse{URL: cfg.PulseURL}, Logf: l.Printf, Taches: ts}
	o.Boucle(ctx, Interval)
	l.Printf("arrêt")
	return nil
}
