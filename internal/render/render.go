// Package render produit la conf d'un WAF : texte directives de Coraza,
// ops.conf, override.conf, conf Caddy JSON et fichier de mode.
// Aucune valeur venue d'un fichier du tenant n'est concaténée dans un texte que
// Caddy interprète : la conf Caddy est sérialisée par encoding/json.
package render

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/tenant"
)

type Uninspected struct {
	Method string
	Path   string
	Prefix bool
	Max    int64
}

type Input struct {
	Etc            string
	State          string
	Tenant         string
	Hosts          []string
	HostHeader     string
	Platform       string
	Upstream       string
	CRSPlugins     []string
	Revision       string
	Base           string
	WAF            *tenant.Config
	TenantFiles    map[string]bool
	DetectionUntil time.Time
	ForceUntil     time.Time
	Uninspected    []Uninspected
	Now            time.Time
}

const BodyLimit = 13107200

func (in *Input) tenantFile(name string) string {
	return filepath.Join(in.Etc, "tenant", "coraza", name)
}

func (in *Input) plugins(kind string) []string {
	var out []string
	for _, p := range in.CRSPlugins {
		pat := filepath.Join(in.Etc, "plugins", p, "plugins", "*-"+kind+".conf")
		if m, _ := filepath.Glob(pat); len(m) > 0 {
			out = append(out, "Include "+pat)
		}
	}
	return out
}

// Directives renvoie le texte passé à coraza_waf, dans l'ordre de la section 5.7.
func Directives(in *Input) string {
	l := []string{
		fmt.Sprintf("# wafgen tenant=%s rev=%s", in.Tenant, in.Revision),
		"Include " + filepath.Join(in.Etc, "coraza/coraza.conf-recommended"),
		"Include " + filepath.Join(in.Etc, "coraza/10-moteur.conf"),
		"Include " + filepath.Join(in.Etc, "crs/crs-setup.conf.example"),
	}
	l = append(l, in.plugins("config")...)
	if in.TenantFiles["config.conf"] {
		l = append(l, "Include "+in.tenantFile("config.conf"))
	}
	l = append(l,
		"Include "+filepath.Join(in.Etc, "coraza/20-planchers.conf"),
		"Include "+filepath.Join(in.State, "ops.conf"),
	)
	l = append(l, in.plugins("before")...)
	if in.TenantFiles["before.conf"] {
		l = append(l, "Include "+in.tenantFile("before.conf"))
	}
	l = append(l, "Include "+filepath.Join(in.Etc, "crs/rules/*.conf"))
	l = append(l, in.plugins("after")...)
	if in.TenantFiles["after.conf"] {
		l = append(l, "Include "+in.tenantFile("after.conf"))
	}
	l = append(l,
		"Include "+filepath.Join(in.Etc, "coraza/90-garde-fous.conf"),
		"Include "+filepath.Join(in.State, "override.conf"),
	)
	return strings.Join(l, "\n") + "\n"
}

// OpsConf traduit les variables ops : détection forcée, fenêtre de détection et
// chemins non inspectés. Chargé avant les règles du tenant et la CRS, il passe en
// détection seule toutes les règles de phase 1 qui suivent ; 10050, chargée avant,
// continue de bloquer les chemins non canoniques.
func OpsConf(in *Input) string {
	var b strings.Builder
	b.WriteString("# GÉNÉRÉ par wafgen run depuis les variables ops, ne pas éditer.\n")
	if !in.ForceUntil.IsZero() && in.ForceUntil.After(in.Now) {
		fmt.Fprintf(&b, "SecRule TIME_EPOCH \"@lt %d\" \"id:15201,phase:1,pass,nolog,t:none,ctl:ruleEngine=DetectionOnly\"\n", in.ForceUntil.Unix())
	}
	if !in.DetectionUntil.IsZero() && in.DetectionUntil.After(in.Now) {
		fmt.Fprintf(&b, "SecRule TIME_EPOCH \"@lt %d\" \"id:15001,phase:1,pass,nolog,t:none,ctl:ruleEngine=DetectionOnly\"\n", in.DetectionUntil.Unix())
	}
	for i, u := range in.Uninspected {
		op := "@streq"
		if u.Prefix {
			op = "@beginsWith"
		}
		fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"%s %s\" \"id:%d,phase:1,pass,nolog,t:none,t:lowercase,chain\"\n", op, strings.ToLower(u.Path), 15101+i)
		fmt.Fprintf(&b, "SecRule REQUEST_METHOD \"@streq %s\" \"t:none,ctl:requestBodyAccess=Off\"\n", u.Method)
	}
	return b.String()
}

// OverrideConf reste vide : la détection forcée vit dans ops.conf pour précéder
// les règles de phase 1 du tenant et de la CRS. Le fichier garde sa place en fin
// de chargement pour une surcharge ops future.
func OverrideConf(in *Input) string {
	return "# GÉNÉRÉ par wafgen run, ne pas éditer.\n"
}

func Mode(in *Input) (mode string, until time.Time) {
	switch {
	case !in.ForceUntil.IsZero() && in.ForceUntil.After(in.Now):
		return "force", in.ForceUntil
	case !in.DetectionUntil.IsZero() && in.DetectionUntil.After(in.Now):
		return "detection", in.DetectionUntil
	}
	return "block", time.Time{}
}

func ModeProm(in *Input) string {
	mode, until := Mode(in)
	u := ""
	if !until.IsZero() {
		u = until.UTC().Format(time.RFC3339)
	}
	esc := func(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) }
	return fmt.Sprintf("# HELP waf_tenant_mode Mode du WAF de l'app (block, detection, force).\n# TYPE waf_tenant_mode gauge\nwaf_tenant_mode{tenant=\"%s\",mode=\"%s\",until=\"%s\"} 1\n# HELP waf_tenant_info Révision des règles et digest de la base servis.\n# TYPE waf_tenant_info gauge\nwaf_tenant_info{tenant=\"%s\",revision=\"%s\",base=\"%s\"} 1\n",
		esc(in.Tenant), mode, u, esc(in.Tenant), esc(in.Revision), esc(in.Base))
}

type obj = map[string]any

func windowNS(w string) int64 {
	d, _ := time.ParseDuration(w)
	return int64(d)
}

func pathMatcher(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			p += "*"
		}
		out = append(out, p)
	}
	return out
}

func zoneMatcher(z tenant.Zone) obj {
	m := obj{"path": pathMatcher(z.Paths)}
	if len(z.Methods) > 0 {
		m["method"] = z.Methods
	}
	return m
}

func rateLimit(in *Input) obj {
	zones := obj{}
	var others []any
	for _, z := range in.WAF.RateLimits.Zones {
		zones[in.Tenant+"__"+z.Name] = obj{
			"match":       []any{zoneMatcher(z)},
			"key":         "{http.vars.client_ip}",
			"ipv6_prefix": 64,
			"max_events":  z.Events,
			"window":      windowNS(z.Window),
		}
		others = append(others, zoneMatcher(z))
	}
	def := obj{
		"key":         "{http.vars.client_ip}",
		"ipv6_prefix": 64,
		"max_events":  in.WAF.RateLimits.Default.Events,
		"window":      windowNS(in.WAF.RateLimits.Default.Window),
	}
	if len(others) > 0 {
		def["match"] = []any{obj{"not": others}}
	}
	zones[in.Tenant+"__defaut"] = def
	return obj{"handler": "rate_limit", "rate_limits": zones, "disable_metrics": true}
}

func requestBody(in *Input) []any {
	var routes []any
	var not []any
	for _, u := range in.Uninspected {
		p := u.Path
		if u.Prefix {
			p += "*"
		}
		m := obj{"path": []string{p}, "method": []string{u.Method}}
		not = append(not, m)
		routes = append(routes, obj{
			"match":  []any{m},
			"handle": []any{obj{"handler": "request_body", "max_size": u.Max}},
		})
	}
	def := obj{"handle": []any{obj{"handler": "request_body", "max_size": BodyLimit}}}
	if len(not) > 0 {
		def["match"] = []any{obj{"not": not}}
	}
	return append(routes, def)
}

func reverseProxy(in *Input) (obj, error) {
	u, err := url.Parse(in.Upstream)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("UPSTREAM %q : https://<hôte> attendu, sans chemin", in.Upstream)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	set := obj{
		"X-Forwarded-For":   []string{"{http.vars.client_ip}"},
		"X-Forwarded-Proto": []string{"https"},
	}
	headers := obj{"request": obj{"set": set}}
	if in.Platform == "koyeb" {
		set["X-Ademe-Waf"] = []string{"{env.ORIGIN_TOKEN}"}
	}
	// Caddy 2.11 pose Host à l'hôte amont pour toute origine HTTPS
	// (HTTPTransport.RequestHeaderOps) : le Host du visiteur doit être explicite.
	set["Host"] = []string{"{http.request.host}"}
	if in.HostHeader == "upstream" {
		set["Host"] = []string{"{http.reverse_proxy.upstream.host}"}
		headers["response"] = obj{"replace": obj{"Location": []any{obj{
			"search_regexp": "^" + regexp.QuoteMeta(strings.TrimSuffix(in.Upstream, "/")),
			"replace":       "",
		}}}}
	}
	return obj{
		"handler":   "reverse_proxy",
		"upstreams": []any{obj{"dial": u.Hostname() + ":" + port}},
		"transport": obj{"protocol": "http", "tls": obj{"server_name": u.Hostname()}},
		"headers":   headers,
	}, nil
}

// SiteRoute renvoie la route Caddy des hosts de l'app, équivalente au site de la section 5.7.
func SiteRoute(in *Input) (obj, error) {
	rp, err := reverseProxy(in)
	if err != nil {
		return nil, err
	}
	socle := []any{
		obj{"handler": "headers", "response": obj{"deferred": true, "delete": []string{"Server", "X-Powered-By"}}},
		obj{"handler": "headers", "response": obj{
			"require": obj{"headers": obj{"X-Content-Type-Options": nil}},
			"set":     obj{"X-Content-Type-Options": []string{"nosniff"}},
		}},
		obj{"handler": "headers", "response": obj{
			"require": obj{"headers": obj{"Strict-Transport-Security": nil}},
			"set":     obj{"Strict-Transport-Security": []string{"max-age=31536000"}},
		}},
	}
	routes := []any{obj{"handle": socle}}
	routes = append(routes, requestBody(in)...)
	routes = append(routes, obj{
		"match":  []any{obj{"header": obj{"X-Forwarded-Proto": []string{"http"}}}},
		"handle": []any{obj{"handler": "static_response", "status_code": 301, "headers": obj{"Location": []string{"https://{http.request.host}{http.request.uri}"}}}},
	})
	inner := []any{
		obj{"match": []any{obj{"path": []string{"/__waf/healthz"}}}, "handle": []any{obj{"handler": "static_response", "status_code": 200}}},
		obj{"match": []any{obj{"path": []string{"/__waf/ip"}}}, "handle": []any{obj{"handler": "static_response", "status_code": 200, "body": "{http.vars.client_ip}"}}},
		// L'autotest de wafgen run arrive du loopback : il ne doit ni consommer ni
		// subir le rate limit de l'app. En service, le pair est toujours Traefik.
		obj{
			"match":  []any{obj{"not": []any{obj{"remote_ip": obj{"ranges": []string{"127.0.0.0/8", "::1/128"}}}}}},
			"handle": []any{rateLimit(in)},
		},
		obj{"handle": []any{
			obj{"handler": "waf", "load_owasp_crs": false, "directives": Directives(in)},
			obj{"handler": "encode", "encodings": obj{"zstd": obj{}, "gzip": obj{}}, "prefer": []string{"zstd", "gzip"}},
			rp,
		}},
	}
	routes = append(routes, obj{"handle": []any{obj{"handler": "subroute", "routes": inner}}})
	return obj{
		"match":    []any{obj{"host": in.Hosts}},
		"handle":   []any{obj{"handler": "subroute", "routes": routes}},
		"terminal": true,
	}, nil
}

// Caddy ajoute la route de l'app en tête du serveur :8080 de la conf de base.
func Caddy(base []byte, in *Input) ([]byte, error) {
	var cfg obj
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, fmt.Errorf("conf de base : %w", err)
	}
	apps, _ := cfg["apps"].(obj)
	httpApp, _ := apps["http"].(obj)
	servers, _ := httpApp["servers"].(obj)
	var srv obj
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s, _ := servers[n].(obj)
		if l, _ := s["listen"].([]any); len(l) == 1 && l[0] == ":8080" {
			srv = s
		}
	}
	if srv == nil {
		return nil, fmt.Errorf("conf de base : serveur :8080 introuvable")
	}
	route, err := SiteRoute(in)
	if err != nil {
		return nil, err
	}
	existing, _ := srv["routes"].([]any)
	srv["routes"] = append([]any{route}, existing...)
	return json.MarshalIndent(cfg, "", "  ")
}

// ---------- variables ops

var reHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)

func ParseHosts(s string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if !reHost.MatchString(h) || len(h) > 253 {
			return nil, fmt.Errorf("WAF_HOSTS : host %q invalide", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 || len(out) > 20 {
		return nil, fmt.Errorf("WAF_HOSTS : 1 à 20 hosts")
	}
	return out, nil
}

type Ceilings struct {
	EventsPerSecond      int
	UploadMaxSize        int64
	DetectionOnlyMaxDays int
}

func DefaultCeilings() Ceilings {
	return Ceilings{EventsPerSecond: 100, UploadMaxSize: 100 << 20, DetectionOnlyMaxDays: 14}
}

func ParseSize(s string) (int64, error) {
	m := regexp.MustCompile(`^([0-9]{1,6})(MiB|KiB)$`).FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("taille %q : <n>MiB ou <n>KiB", s)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	if m[2] == "MiB" {
		return n << 20, nil
	}
	return n << 10, nil
}

func ParseCeilings(s string) (Ceilings, error) {
	c := DefaultCeilings()
	if strings.TrimSpace(s) == "" {
		return c, nil
	}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return c, fmt.Errorf("WAF_CEILINGS : %q", kv)
		}
		var err error
		switch k {
		case "events_per_second":
			c.EventsPerSecond, err = strconv.Atoi(v)
		case "upload_max_size":
			c.UploadMaxSize, err = ParseSize(v)
		case "detection_only_max_days":
			c.DetectionOnlyMaxDays, err = strconv.Atoi(v)
		default:
			err = fmt.Errorf("clé inconnue")
		}
		if err != nil {
			return c, fmt.Errorf("WAF_CEILINGS %s : %v", k, err)
		}
	}
	return c, nil
}

var reUninspectedPath = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,200}$`)

// ParseUninspected lit « POST /api/uploads 50MiB, PUT /fichiers/ 20MiB ».
// Un chemin terminé par / vaut pour tout ce qui commence par lui.
func ParseUninspected(s string, c Ceilings) ([]Uninspected, error) {
	var out []Uninspected
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	for _, e := range strings.Split(s, ",") {
		f := strings.Fields(e)
		if len(f) != 3 {
			return nil, fmt.Errorf("UNINSPECTED : « MÉTHODE /chemin TAILLE » attendu, pas %q", e)
		}
		if f[0] != "POST" && f[0] != "PUT" && f[0] != "PATCH" {
			return nil, fmt.Errorf("UNINSPECTED : méthode %q", f[0])
		}
		if !reUninspectedPath.MatchString(f[1]) || strings.Contains(f[1], "//") {
			return nil, fmt.Errorf("UNINSPECTED : chemin %q", f[1])
		}
		n, err := ParseSize(f[2])
		if err != nil || n > c.UploadMaxSize {
			return nil, fmt.Errorf("UNINSPECTED : taille %q (plafond %d octets)", f[2], c.UploadMaxSize)
		}
		out = append(out, Uninspected{Method: f[0], Path: f[1], Prefix: strings.HasSuffix(f[1], "/"), Max: n})
	}
	if len(out) > 5 {
		return nil, fmt.Errorf("UNINSPECTED : 5 chemins au plus")
	}
	return out, nil
}

// TenantFiles liste les fichiers Coraza présents dans le dossier du tenant.
func TenantFiles(etc string) map[string]bool {
	out := map[string]bool{}
	for _, n := range []string{"config.conf", "before.conf", "after.conf"} {
		if st, err := os.Stat(filepath.Join(etc, "tenant", "coraza", n)); err == nil && st.Mode().IsRegular() {
			out[n] = true
		}
	}
	return out
}
