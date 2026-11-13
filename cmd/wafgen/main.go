// wafgen construit, vérifie et lance le WAF d'une app.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/incubateur-ademe/waf-base/internal/runner"
)

const usage = `wafgen <commande> [--etc /etc/waf]

  check   lint du waf/ du tenant, rendu fictif, caddy validate, attaque canonique en mémoire
  run     rendu depuis les variables ops, lancement de Caddy, contrôles de démarrage
  rev     empreinte de waf/ (Dockerfile exclu), comme run et l'audit la calculent

Prévus aux étapes suivantes : smoke, status, rules, provision, audit, rollout.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("wafgen: ")
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
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
	case "smoke", "status", "rules", "provision", "audit", "rollout":
		log.Printf("%s : pas encore écrit (étapes 2 et suivantes)", cmd)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}
