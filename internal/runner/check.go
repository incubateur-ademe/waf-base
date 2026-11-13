package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/lint"
	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
	"github.com/incubateur-ademe/waf-base/internal/selftest"
	"github.com/incubateur-ademe/waf-base/internal/tenant"
)

type Paths struct {
	Etc   string
	State string
	Caddy string
}

func (p Paths) TenantDir() string { return filepath.Join(p.Etc, "tenant") }

// Revision est l'empreinte des fichiers de waf/, Dockerfile exclu.
func Revision(dir string) (string, error) {
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == "Dockerfile" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		lines = append(lines, rel+"\x00"+hex.EncodeToString(h[:]))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])[:12], nil
}

type Report struct {
	Lint     *lint.Result
	Outcomes []selftest.Outcome
	Fails    []string
}

// Check lint le tenant, rend la conf avec des valeurs fictives, la valide avec
// caddy et rejoue l'attaque canonique dans Coraza en mémoire.
func Check(p Paths, logf func(string, ...any)) (*Report, error) {
	pol, err := policy.Load(filepath.Join(p.Etc, "policy"))
	if err != nil {
		return nil, err
	}
	pl, err := lint.CRSParanoia(filepath.Join(p.Etc, "crs", "rules"))
	if err != nil {
		return nil, err
	}
	rep := &Report{Lint: lint.Tenant(p.TenantDir(), pol, pl)}
	for _, f := range rep.Lint.Findings {
		logf("%s", f)
	}
	if errs := rep.Lint.Errors(); len(errs) > 0 {
		return rep, fmt.Errorf("%d erreur(s) de forme dans waf/", len(errs))
	}
	// Le plafond réel de l'app n'est connu qu'au démarrage (WAF_CEILINGS) : check
	// borne au plafond maximal de la politique, run au plafond de l'app.
	waf, err := tenant.Load(filepath.Join(p.TenantDir(), "waf.yaml"), pol.Formes.RateLimit.PlafondMaxParSeconde)
	if err != nil {
		return rep, err
	}
	rev, err := Revision(p.TenantDir())
	if err != nil {
		return rep, err
	}
	state, err := os.MkdirTemp("", "wafcheck-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(state)
	in := &render.Input{
		Etc:         p.Etc,
		State:       state,
		Tenant:      "check",
		Hosts:       []string{"check.invalid"},
		HostHeader:  "visitor",
		Platform:    "scalingo",
		Upstream:    "https://check.osc-fr1.scalingo.io",
		Revision:    rev,
		Base:        baseRef(),
		WAF:         waf,
		TenantFiles: render.TenantFiles(p.Etc),
		Now:         time.Now(),
	}
	if err := writeState(in); err != nil {
		return rep, err
	}
	base, err := os.ReadFile(filepath.Join(p.Etc, "caddy", "base.json"))
	if err != nil {
		return rep, err
	}
	cfg, err := render.Caddy(base, in)
	if err != nil {
		return rep, err
	}
	again, _ := render.Caddy(base, in)
	if string(again) != string(cfg) {
		return rep, fmt.Errorf("rendu non déterministe")
	}
	cfgPath := filepath.Join(state, "caddy.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return rep, err
	}
	if p.Caddy != "" {
		cmd := exec.Command(p.Caddy, "validate", "--config", cfgPath)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+state, "XDG_DATA_HOME="+state)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return rep, fmt.Errorf("caddy validate : %v\n%s", err, tail(string(out), 40))
		}
		logf("caddy validate : conf valide")
	}
	w, err := selftest.NewWAF(render.Directives(in) + "SecAuditEngine Off\n")
	if err != nil {
		return rep, fmt.Errorf("chargement Coraza : %w", err)
	}
	targets := selftest.Targets(rep.Lint.Prefixes)
	rep.Outcomes = selftest.InProc(w, "check.invalid", targets)
	rep.Fails = selftest.Verdict(rep.Outcomes)
	for _, f := range rep.Fails {
		logf("%s", f)
	}
	if len(rep.Fails) > 0 {
		return rep, fmt.Errorf("attaque canonique : %d échec(s)", len(rep.Fails))
	}
	logf("attaque canonique bloquée par 949110 ou 19110 : %d variantes sur %d chemins, révision %s", len(rep.Outcomes), len(targets), rev)
	return rep, nil
}

// baseRef renvoie la référence de l'image de base : le digest passé en WAF_BASE
// au build de l'app (ONBUILD ENV), à défaut le commit de waf-base.
func baseRef() string {
	if v := os.Getenv("WAF_BASE_REF"); v != "" {
		return v
	}
	return os.Getenv("WAF_BASE_VERSION")
}

func writeState(in *render.Input) error {
	for name, content := range map[string]string{
		"ops.conf":      render.OpsConf(in),
		"override.conf": render.OverrideConf(in),
		"mode.prom":     render.ModeProm(in),
	} {
		if err := os.WriteFile(filepath.Join(in.State, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func tail(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}
