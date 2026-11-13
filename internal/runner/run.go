package runner

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/lint"
	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
	"github.com/incubateur-ademe/waf-base/internal/selftest"
	"github.com/incubateur-ademe/waf-base/internal/tenant"
)

const (
	local      = "http://127.0.0.1:8080"
	drainDelay = 10 * time.Second
	maxForce   = 72 * time.Hour
)

var watchedEnv = regexp.MustCompile(`^(WAF_|UPSTREAM$|ORIGIN_TOKEN$)`)

// Inputs lit et vérifie les variables posées par wafgen provision.
func Inputs(p Paths, pol *policy.Policy, lr *lint.Result, now time.Time) (*render.Input, error) {
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if watchedEnv.MatchString(k) && strings.Contains(v, "{{") {
			return nil, fmt.Errorf("%s contient encore « {{ » : variable partagée Coolify introuvable", k)
		}
	}
	req := func(k string) (string, error) {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			return "", fmt.Errorf("%s manquante", k)
		}
		return v, nil
	}
	name, err := req("WAF_TENANT")
	if err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`).MatchString(name) {
		return nil, fmt.Errorf("WAF_TENANT %q invalide", name)
	}
	hostsRaw, err := req("WAF_HOSTS")
	if err != nil {
		return nil, err
	}
	hosts, err := render.ParseHosts(hostsRaw)
	if err != nil {
		return nil, err
	}
	upstream, err := req("UPSTREAM")
	if err != nil {
		return nil, err
	}
	platform := envOr("WAF_PLATFORM", "scalingo")
	if _, ok := pol.Origines[platform]; !ok {
		return nil, fmt.Errorf("WAF_PLATFORM %q inconnue", platform)
	}
	if !pol.OrigineAdmise(platform, upstream) {
		return nil, fmt.Errorf("UPSTREAM %q hors des motifs de policy/origines.yaml pour %s", upstream, platform)
	}
	if platform == "koyeb" && len(os.Getenv("ORIGIN_TOKEN")) < 32 {
		return nil, fmt.Errorf("ORIGIN_TOKEN manquant ou trop court pour une origine Koyeb")
	}
	hh := envOr("WAF_HOST_HEADER", "visitor")
	if hh != "visitor" && hh != "upstream" {
		return nil, fmt.Errorf("WAF_HOST_HEADER : visitor ou upstream")
	}
	ceil, err := render.ParseCeilings(os.Getenv("WAF_CEILINGS"))
	if err != nil {
		return nil, err
	}
	waf, err := tenant.Load(filepath.Join(p.TenantDir(), "waf.yaml"), ceil.EventsPerSecond)
	if err != nil {
		return nil, err
	}
	var plugins []string
	for _, s := range strings.Split(os.Getenv("WAF_CRS_PLUGINS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			if !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(s) {
				return nil, fmt.Errorf("WAF_CRS_PLUGINS : %q", s)
			}
			if _, err := os.Stat(filepath.Join(p.Etc, "plugins", s)); err != nil {
				return nil, fmt.Errorf("plugin CRS %q absent de l'image", s)
			}
			plugins = append(plugins, s)
		}
	}
	detection, err := deadline("WAF_DETECTION_UNTIL", now, time.Duration(ceil.DetectionOnlyMaxDays)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	force, err := deadline("WAF_FORCE_DETECTION", now, maxForce)
	if err != nil {
		return nil, err
	}
	un, err := render.ParseUninspected(os.Getenv("WAF_UNINSPECTED_PATHS"), ceil)
	if err != nil {
		return nil, err
	}
	rev, err := Revision(p.TenantDir())
	if err != nil {
		return nil, err
	}
	return &render.Input{
		Etc:            p.Etc,
		State:          p.State,
		Tenant:         name,
		Hosts:          hosts,
		HostHeader:     hh,
		Platform:       platform,
		Upstream:       upstream,
		CRSPlugins:     plugins,
		Revision:       rev,
		Base:           baseRef(),
		WAF:            waf,
		TenantFiles:    render.TenantFiles(p.Etc),
		DetectionUntil: detection,
		ForceUntil:     force,
		Uninspected:    un,
		Now:            now,
	}, nil
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func deadline(k string, now time.Time, max time.Duration) (time.Time, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s : date ISO 8601 avec fuseau attendue", k)
	}
	if t.Sub(now) > max {
		return time.Time{}, fmt.Errorf("%s : échéance à plus de %s", k, max)
	}
	return t, nil
}

// MemLimit renvoie 80 % de la limite mémoire du cgroup, 0 sans limite.
func MemLimit() int64 {
	for _, f := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n > 1<<50 {
			return 0
		}
		return n * 8 / 10
	}
	return 0
}

// auditTap recopie la sortie standard de Caddy et, pendant l'autotest seulement,
// lit l'audit Coraza des requêtes dont il a émis le nonce. Il ne cesse jamais de
// vider le pipe : une ligne trop longue est recopiée sans être lue.
type auditTap struct {
	mu       sync.Mutex
	active   bool
	expected map[string]bool
	msgs     map[string][]string
}

const maxAuditLine = 1 << 20

func newTap() *auditTap {
	return &auditTap{active: true, expected: map[string]bool{}, msgs: map[string][]string{}}
}

func (a *auditTap) expect(nonce string) {
	a.mu.Lock()
	a.expected[nonce] = true
	a.mu.Unlock()
}

func (a *auditTap) stop() {
	a.mu.Lock()
	a.active, a.expected, a.msgs = false, nil, nil
	a.mu.Unlock()
}

func (a *auditTap) scan(r io.Reader, w io.Writer) {
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		_, _ = w.Write(chunk)
		a.mu.Lock()
		active := a.active
		a.mu.Unlock()
		if active && !tooLong {
			if len(line)+len(chunk) > maxAuditLine {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if active && !tooLong && len(line) > 0 {
			a.parse(line)
		}
		line, tooLong = line[:0], false
		if err != nil {
			if err != io.EOF {
				_, _ = io.Copy(w, r)
			}
			return
		}
	}
}

func (a *auditTap) parse(line []byte) {
	if !strings.Contains(string(line), "waf_nonce=") {
		return
	}
	var al struct {
		Transaction struct {
			Request struct {
				URI string `json:"uri"`
			} `json:"request"`
		} `json:"transaction"`
		Messages []struct {
			ErrorMessage string `json:"error_message"`
		} `json:"messages"`
	}
	if json.Unmarshal(line, &al) != nil {
		return
	}
	i := strings.Index(al.Transaction.Request.URI, "waf_nonce=")
	if i < 0 {
		return
	}
	nonce := al.Transaction.Request.URI[i+len("waf_nonce="):]
	if j := strings.IndexByte(nonce, '&'); j >= 0 {
		nonce = nonce[:j]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.expected[nonce] {
		return
	}
	for _, m := range al.Messages {
		a.msgs[nonce] = append(a.msgs[nonce], m.ErrorMessage)
	}
}

var reMsgID = regexp.MustCompile(`\[id "([0-9]+)"\]`)

func (a *auditTap) blockingRule(nonce string, wait time.Duration) int {
	end := time.Now().Add(wait)
	for time.Now().Before(end) {
		a.mu.Lock()
		msgs := append([]string(nil), a.msgs[nonce]...)
		a.mu.Unlock()
		for _, m := range msgs {
			for _, sm := range reMsgID.FindAllStringSubmatch(m, -1) {
				id, _ := strconv.Atoi(sm[1])
				if selftest.Allowed[id] {
					return id
				}
			}
		}
		if len(msgs) > 0 {
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run démarre Caddy, vérifie l'origine et l'attaque canonique, puis sert jusqu'à SIGTERM.
func Run(p Paths, logf func(string, ...any)) error {
	pol, err := policy.Load(filepath.Join(p.Etc, "policy"))
	if err != nil {
		return err
	}
	lr := lint.Tenant(p.TenantDir(), pol, nil)
	if errs := lr.Errors(); len(errs) > 0 {
		for _, f := range errs {
			logf("%s", f)
		}
		return fmt.Errorf("waf/ refusé par le linter")
	}
	in, err := Inputs(p, pol, lr, time.Now())
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(p.State, "ready"))
	if err := writeState(in); err != nil {
		return err
	}
	base, err := os.ReadFile(filepath.Join(p.Etc, "caddy", "base.json"))
	if err != nil {
		return err
	}
	cfg, err := render.Caddy(base, in)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(p.State, "caddy.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	mode, until := render.Mode(in)
	logf("tenant %s, révision %s, base %s, mode %s %s", in.Tenant, in.Revision, in.Base, mode, until.Format(time.RFC3339))

	cmd := exec.Command(p.Caddy, "run", "--config", cfgPath)
	cmd.Env = os.Environ()
	if lim := MemLimit(); lim > 0 && os.Getenv("GOMEMLIMIT") == "" {
		cmd.Env = append(cmd.Env, "GOMEMLIMIT="+strconv.FormatInt(lim, 10))
		logf("GOMEMLIMIT=%d", lim)
	}
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	tap := newTap()
	go tap.scan(stdout, os.Stdout)
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	fail := func(e error) error {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		}
		return e
	}

	if err := waitListen([]string{"127.0.0.1:8080", "127.0.0.1:2020"}, 60*time.Second, exited); err != nil {
		return fail(err)
	}
	if err := originCheck(in, logf); err != nil {
		return fail(err)
	}
	if mode == "block" {
		if err := httpSelftest(in, lr, tap, logf); err != nil {
			return fail(err)
		}
	} else {
		logf("mode %s jusqu'au %s : attaque canonique non rejouée", mode, until.Format(time.RFC3339))
	}
	tap.stop()
	if err := os.WriteFile(filepath.Join(p.State, "ready"), []byte(in.Revision+"\n"), 0o644); err != nil {
		return fail(err)
	}
	logf("prêt")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-exited:
		return fmt.Errorf("caddy s'est arrêté : %v", err)
	case s := <-sig:
		logf("signal %s : /healthz passe en 503, arrêt dans %s", s, drainDelay)
		_ = os.Remove(filepath.Join(p.State, "ready"))
		time.Sleep(drainDelay)
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
		}
		return nil
	}
}

func waitListen(addrs []string, max time.Duration, exited chan error) error {
	end := time.Now().Add(max)
	for _, a := range addrs {
		for {
			c, err := net.DialTimeout("tcp", a, time.Second)
			if err == nil {
				c.Close()
				break
			}
			select {
			case e := <-exited:
				exited <- e
				return fmt.Errorf("caddy s'est arrêté au démarrage : %v", e)
			default:
			}
			if time.Now().After(end) {
				return fmt.Errorf("%s n'écoute pas après %s", a, max)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return nil
}

// Signature de la page 403 du routeur Scalingo, à confirmer sur une app réelle à l'étape 2.
var scalingoRefusal = regexp.MustCompile(`(?i)scalingo`)

func originCheck(in *render.Input, logf func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", in.Upstream+"/", nil)
	if in.HostHeader == "visitor" {
		req.Host = in.Hosts[0]
	}
	req.Header.Set("User-Agent", "wafgen-origin-check")
	if in.Platform == "koyeb" {
		req.Header.Set("X-Ademe-Waf", os.Getenv("ORIGIN_TOKEN"))
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		var dnsErr *net.DNSError
		var certErr *tls.CertificateVerificationError
		var hostErr x509.HostnameError
		var unkAuth x509.UnknownAuthorityError
		if errors.As(err, &dnsErr) || errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &unkAuth) {
			return fmt.Errorf("origine : %v ; erreur de nom ou de certificat, le conteneur ne servirait que des 502", err)
		}
		logf("origine injoignable (journalisé, pas bloquant) : %v", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	switch {
	case resp.StatusCode == 403 && in.Platform == "scalingo" && scalingoRefusal.Match(body):
		return errors.New("origine : 403 du firewall applicatif Scalingo, l'IP de cette VM manque dans ses règles")
	case (resp.StatusCode == 401 || resp.StatusCode == 403) && in.Platform == "koyeb":
		return fmt.Errorf("origine : %d, jeton refusé par le middleware", resp.StatusCode)
	case resp.StatusCode >= 500:
		logf("origine : statut %d (journalisé, pas bloquant)", resp.StatusCode)
	default:
		logf("origine : statut %d", resp.StatusCode)
	}
	return nil
}

func httpSelftest(in *render.Input, lr *lint.Result, tap *auditTap, logf func(string, ...any)) error {
	cl := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	targets := selftest.Targets(lr.Prefixes)
	key := selftest.Key()
	var fails []string
	n := 0
	for _, host := range in.Hosts {
		var outs []selftest.Outcome
		for _, t := range targets {
			for _, m := range t.Methods {
				for _, v := range selftest.Variants(key, "", m) {
					nonce := newNonce()
					v.Query.Set("waf_nonce", nonce)
					tap.expect(nonce)
					req, err := selftest.Request(local, host, t.Path, v)
					if err != nil {
						return err
					}
					resp, err := cl.Do(req)
					if err != nil {
						return fmt.Errorf("attaque canonique %s %s : %v", host, t.Path, err)
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					o := selftest.Outcome{Path: t.Path, Root: t.Root, Method: m, Variant: v.Name, Status: resp.StatusCode}
					if resp.StatusCode == 403 {
						o.RuleID = tap.blockingRule(nonce, 3*time.Second)
					}
					outs = append(outs, o)
					n++
				}
			}
		}
		for _, f := range selftest.Verdict(outs) {
			fails = append(fails, host+" : "+f)
		}
	}
	for _, f := range fails {
		logf("%s", f)
	}
	if len(fails) > 0 {
		return fmt.Errorf("attaque canonique : %d échec(s)", len(fails))
	}
	logf("attaque canonique bloquée par 949110 ou 19110 : %d requêtes sur %d hosts", n, len(in.Hosts))
	return nil
}
