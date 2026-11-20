// wafgen construit, vérifie et lance le WAF d'une app.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/incubateur-ademe/waf-base/internal/ops"
	"github.com/incubateur-ademe/waf-base/internal/provision"
	"github.com/incubateur-ademe/waf-base/internal/runner"
)

const usage = `wafgen <commande> [--etc /etc/waf]

  check      lint du waf/ du tenant, rendu fictif, caddy validate, attaque canonique en mémoire
  run        rendu depuis les variables ops, lancement de Caddy, contrôles de démarrage
  rev        empreinte de waf/ (Dockerfile exclu), comme run et l'audit la calculent
  provision  aligne les apps WAF de Coolify sur l'inventaire (plan seul sans --apply)
  ops        waf-ops : contrôle des 5 minutes et pulse en boucle, ou un passage (ops controle)

Prévus aux étapes suivantes : smoke, status, rules, audit, rollout.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("wafgen: ")
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd == "ops" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := ops.Main(ctx, os.Args[2:], os.Getenv, os.Stdout, os.Stderr)
		stop()
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		if err != nil {
			log.Fatalf("ops : %v", err)
		}
		return
	}
	if cmd == "provision" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := provision.Main(ctx, os.Args[2:], os.Getenv, os.Stdout, os.Stderr)
		stop()
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		if err != nil {
			log.Fatalf("provision : %v", err)
		}
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	etc := fs.String("etc", "/etc/waf", "racine de la conf de base")
	state := fs.String("state", "/var/lib/waf", "dossier des fichiers générés")
	caddy := fs.String("caddy", "/usr/bin/caddy", "binaire caddy")
	_ = fs.Parse(os.Args[2:])
	p := runner.Paths{Etc: *etc, State: *state, Caddy: *caddy}
	logf := func(format string, a ...any) { log.Printf(format, a...) }

	switch cmd {
	case "check":
		if _, err := runner.Check(p, logf); err != nil {
			log.Fatalf("check : %v", err)
		}
	case "run":
		if err := runner.Run(p, logf); err != nil {
			log.Fatalf("run : %v", err)
		}
	case "rev":
		dir := p.TenantDir()
		if fs.NArg() == 1 {
			dir = fs.Arg(0)
		}
		rev, err := runner.Revision(filepath.Clean(dir))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(rev)
	case "smoke", "status", "rules", "audit", "rollout":
		log.Printf("%s : pas encore écrit (étapes 2 et suivantes)", cmd)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}
