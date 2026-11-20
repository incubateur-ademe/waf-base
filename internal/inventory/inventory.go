// Package inventory lit inventaire.yaml : apps protégées et défauts fusionnés
// dans chacune (section 5.7 du design).
package inventory

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/incubateur-ademe/waf-base/internal/render"
)

const DefaultURL = "https://raw.githubusercontent.com/incubateur-ademe/waf-base/main/inventaire.yaml"

const maxSize = 1 << 20

type ceilings struct {
	EventsPerSecond      *int    `yaml:"events_per_second"`
	UploadMaxSize        *string `yaml:"upload_max_size"`
	DetectionOnlyMaxDays *int    `yaml:"detection_only_max_days"`
}

type resources struct {
	Memory    *string `yaml:"memory"`
	CPUWeight *int    `yaml:"cpu_weight"`
}

// entry sert aux défauts comme aux apps : un champ absent vaut nil et laisse
// passer la valeur des défauts.
type entry struct {
	Repo           *string    `yaml:"repo"`
	Platform       *string    `yaml:"platform"`
	Hosts          []string   `yaml:"hosts"`
	Canonical      *string    `yaml:"canonical"`
	Edge           *string    `yaml:"edge"`
	EdgeZones      []string   `yaml:"edge_zones"`
	Stage          *string    `yaml:"stage"`
	HostHeader     *string    `yaml:"host_header"`
	CRSPlugins     *[]string  `yaml:"crs_plugins"`
	Live           *bool      `yaml:"live"`
	Branch         *string    `yaml:"branch"`
	WafDir         *string    `yaml:"waf_dir"`
	Resources      *resources `yaml:"resources"`
	Ceilings       *ceilings  `yaml:"ceilings"`
	InternalEvents *int       `yaml:"internal_events"`
}

type vmEntry struct {
	Stage string `yaml:"stage"`
	IP    string `yaml:"ip"`
}

type file struct {
	VMs      map[string]vmEntry `yaml:"vms"`
	Defaults entry              `yaml:"defaults"`
	Apps     map[string]entry   `yaml:"apps"`
}

const (
	StageProd    = "prod"
	StagePreprod = "preprod"
)

// VM est une VM WAF. Elle porte les apps de son stage, et son IP est celle que
// le firewall de ces apps autorise.
type VM struct {
	Name  string
	Stage string
	IP    string
}

type Inventory struct {
	Apps []App
	VMs  []VM
}

// VM rend la VM de ce nom.
func (inv Inventory) VM(name string) (VM, bool) {
	for _, v := range inv.VMs {
		if v.Name == name {
			return v, true
		}
	}
	return VM{}, false
}

type Ceilings struct {
	EventsPerSecond      int
	UploadMaxSize        string
	DetectionOnlyMaxDays int
}

// Env rend la valeur de WAF_CEILINGS, au format lu par render.ParseCeilings.
func (c Ceilings) Env() string {
	return fmt.Sprintf("events_per_second=%d,upload_max_size=%s,detection_only_max_days=%d",
		c.EventsPerSecond, c.UploadMaxSize, c.DetectionOnlyMaxDays)
}

type App struct {
	Name           string
	Repo           string
	Platform       string
	Hosts          []string
	Canonical      string
	Edge           string
	EdgeZones      []string
	Stage          string
	HostHeader     string
	CRSPlugins     []string
	Live           bool
	Branch         string
	WafDir         string
	Memory         string
	CPUWeight      int
	Ceilings       Ceilings
	InternalEvents int
}

// EnvSuffix donne le suffixe des variables partagées de l'app : WAF_PILOTE pour waf-pilote.
func (a App) EnvSuffix() string {
	return strings.ToUpper(strings.ReplaceAll(a.Name, "-", "_"))
}

// LimitsMemory traduit 512M en 512m, la forme que Coolify passe à Docker.
func (a App) LimitsMemory() string {
	return strings.ToLower(a.Memory)
}

var (
	reName    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	reRepo    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	reBranch  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)
	reWafDir  = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	reMemory  = regexp.MustCompile(`^[1-9][0-9]{0,5}[MG]$`)
	rePlugin  = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	reDotDots = regexp.MustCompile(`(^|/)\.\.?(/|$)`)
	reVMName  = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// Parse rend les apps de l'inventaire, lu et validé par Load.
func Parse(b []byte, platforms map[string]bool) ([]App, error) {
	inv, err := Load(b, platforms)
	return inv.Apps, err
}

// Load lit l'inventaire, fusionne les défauts dans chaque app et valide le
// résultat. platforms liste les plateformes de policy/origines.yaml.
func Load(b []byte, platforms map[string]bool) (Inventory, error) {
	var f file
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil {
		return Inventory{}, fmt.Errorf("inventaire : %w", err)
	}
	if len(f.Apps) == 0 {
		return Inventory{}, fmt.Errorf("inventaire : aucune app")
	}
	if f.Defaults.Canonical != nil {
		return Inventory{}, fmt.Errorf("inventaire : canonical propre à une app, interdit dans defaults")
	}
	if f.Defaults.Edge != nil {
		return Inventory{}, fmt.Errorf("inventaire : edge propre à une app, interdit dans defaults")
	}
	if f.Defaults.Stage != nil {
		return Inventory{}, fmt.Errorf("inventaire : stage propre à une app, interdit dans defaults")
	}
	if f.Defaults.EdgeZones != nil {
		return Inventory{}, fmt.Errorf("inventaire : edge_zones propre à une app, interdit dans defaults")
	}
	vms, err := parseVMs(f.VMs)
	if err != nil {
		return Inventory{}, err
	}
	stages := map[string]bool{}
	for _, v := range vms {
		stages[v.Stage] = true
	}
	names := make([]string, 0, len(f.Apps))
	for n := range f.Apps {
		names = append(names, n)
	}
	sort.Strings(names)
	owner := map[string]string{}
	apps := make([]App, 0, len(names))
	for _, n := range names {
		a := merge(n, f.Defaults, f.Apps[n])
		hosts, err := validate(a, platforms)
		if err != nil {
			return Inventory{}, fmt.Errorf("inventaire, app %s : %w", n, err)
		}
		if !stages[a.Stage] {
			return Inventory{}, fmt.Errorf("inventaire, app %s : aucune VM du stage %s dans vms", n, a.Stage)
		}
		for _, h := range hosts {
			if o, ok := owner[h]; ok {
				return Inventory{}, fmt.Errorf("inventaire : host %s revendiqué par %s et %s", h, o, n)
			}
			owner[h] = n
		}
		apps = append(apps, a)
	}
	return Inventory{Apps: apps, VMs: vms}, nil
}

// parseVMs valide les VM : nom repris dans celui des apps Coolify
// (waf-<app>-<vm>) et dans le hostname waf-<vm> que lit waf-pulse, stage connu,
// IPv4 publique propre à chaque VM.
func parseVMs(in map[string]vmEntry) ([]VM, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("inventaire : vms manquant, une VM au moins")
	}
	names := make([]string, 0, len(in))
	for n := range in {
		names = append(names, n)
	}
	sort.Strings(names)
	owner := map[netip.Addr]string{}
	out := make([]VM, 0, len(names))
	for _, n := range names {
		v := in[n]
		if !reVMName.MatchString(n) {
			return nil, fmt.Errorf("inventaire, vm %q : minuscules et chiffres, 16 caractères au plus", n)
		}
		if !validStage(v.Stage) {
			return nil, fmt.Errorf("inventaire, vm %s : stage %q, %s ou %s", n, v.Stage, StageProd, StagePreprod)
		}
		ip, err := netip.ParseAddr(v.IP)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || reserved(ip) {
			return nil, fmt.Errorf("inventaire, vm %s : ip %q, IPv4 publique attendue", n, v.IP)
		}
		if o, ok := owner[ip]; ok {
			return nil, fmt.Errorf("inventaire : ip %s portée par les vm %s et %s", ip, o, n)
		}
		owner[ip] = n
		out = append(out, VM{Name: n, Stage: v.Stage, IP: ip.String()})
	}
	return out, nil
}

// Plages IPv4 que netip ne classe ni privées ni hors unicast global : aucune ne
// peut être l'IP publique d'une VM.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func reserved(ip netip.Addr) bool {
	for _, p := range reservedV4 {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func validStage(s string) bool {
	return s == StageProd || s == StagePreprod
}

func pick[T any](app, def *T, fallback T) T {
	switch {
	case app != nil:
		return *app
	case def != nil:
		return *def
	}
	return fallback
}

func merge(name string, def, e entry) App {
	a := App{
		Name:           name,
		Repo:           pick(e.Repo, def.Repo, ""),
		Platform:       pick(e.Platform, def.Platform, ""),
		Canonical:      pick(e.Canonical, nil, ""),
		Edge:           pick(e.Edge, nil, ""),
		Stage:          pick(e.Stage, nil, StageProd),
		HostHeader:     pick(e.HostHeader, def.HostHeader, "visitor"),
		CRSPlugins:     pick(e.CRSPlugins, def.CRSPlugins, nil),
		Live:           pick(e.Live, def.Live, false),
		Branch:         pick(e.Branch, def.Branch, ""),
		WafDir:         pick(e.WafDir, def.WafDir, "waf"),
		InternalEvents: pick(e.InternalEvents, def.InternalEvents, 0),
	}
	a.Hosts = e.Hosts
	if a.Hosts == nil {
		a.Hosts = def.Hosts
	}
	a.EdgeZones = e.EdgeZones
	var dr, er resources
	if def.Resources != nil {
		dr = *def.Resources
	}
	if e.Resources != nil {
		er = *e.Resources
	}
	a.Memory = pick(er.Memory, dr.Memory, "")
	a.CPUWeight = pick(er.CPUWeight, dr.CPUWeight, 0)

	base := render.DefaultCeilings()
	var dc, ec ceilings
	if def.Ceilings != nil {
		dc = *def.Ceilings
	}
	if e.Ceilings != nil {
		ec = *e.Ceilings
	}
	a.Ceilings = Ceilings{
		EventsPerSecond:      pick(ec.EventsPerSecond, dc.EventsPerSecond, base.EventsPerSecond),
		UploadMaxSize:        pick(ec.UploadMaxSize, dc.UploadMaxSize, strconv.FormatInt(base.UploadMaxSize>>20, 10)+"MiB"),
		DetectionOnlyMaxDays: pick(ec.DetectionOnlyMaxDays, dc.DetectionOnlyMaxDays, base.DetectionOnlyMaxDays),
	}
	return a
}

// validate rend les hosts tels que render.ParseHosts les lit, pour que les
// contrôles entre apps portent sur ce que le WAF verra.
func validate(a App, platforms map[string]bool) ([]string, error) {
	hosts, err := validateHosts(a.Hosts)
	if err != nil {
		return nil, err
	}
	if a.Canonical != "" && !slices.Contains(hosts, a.Canonical) {
		return nil, fmt.Errorf("canonical %q absent des hosts de l'app", a.Canonical)
	}
	if err := validateEdgeZones(a); err != nil {
		return nil, err
	}
	return hosts, validateRest(a, platforms)
}

// validateEdgeZones refuse une zone sans host de l'app : la règle Cloudflare
// n'y viserait rien. Une zone imbriquée dans une autre ne garde que les hosts
// qu'elle porte, comme Cloudflare.
func validateEdgeZones(a App) error {
	if len(a.EdgeZones) == 0 {
		return nil
	}
	if a.Edge == "" {
		return fmt.Errorf("edge_zones sans edge : la règle Cloudflare n'est posée que pour une app en edge")
	}
	seen := map[string]bool{}
	for _, z := range a.EdgeZones {
		parsed, err := render.ParseHosts(z)
		if err != nil || len(parsed) != 1 || parsed[0] != z {
			return fmt.Errorf("edge_zones : zone %q invalide", z)
		}
		if seen[z] {
			return fmt.Errorf("edge_zones : zone %s en double", z)
		}
		seen[z] = true
	}
	zh := a.ZoneHosts()
	for _, z := range a.EdgeZones {
		if len(zh[z]) == 0 {
			return fmt.Errorf("edge_zones : zone %s sans host de l'app", z)
		}
	}
	return nil
}

// ZoneHosts range chaque host de l'app dans la plus longue de ses edge_zones
// qui le porte. Les hosts hors de toute zone n'y figurent pas.
func (a App) ZoneHosts() map[string][]string {
	out := map[string][]string{}
	for _, h := range a.Hosts {
		best := ""
		for _, z := range a.EdgeZones {
			if (h == z || strings.HasSuffix(h, "."+z)) && len(z) > len(best) {
				best = z
			}
		}
		if best != "" {
			out[best] = append(out[best], h)
		}
	}
	for z := range out {
		sort.Strings(out[z])
	}
	return out
}

// validateHosts lit chaque host seul : ParseHosts sur la liste jointe accepte
// une virgule ou un espace dans une entrée, qui changerait WAF_HOSTS.
func validateHosts(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("hosts manquants")
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, h := range in {
		parsed, err := render.ParseHosts(h)
		if err != nil {
			return nil, err
		}
		if len(parsed) != 1 || parsed[0] != h {
			return nil, fmt.Errorf("host %q : un seul host par entrée, sans virgule ni espace", h)
		}
		if seen[parsed[0]] {
			return nil, fmt.Errorf("host %s en double", parsed[0])
		}
		seen[parsed[0]] = true
		out = append(out, parsed[0])
	}
	if _, err := render.ParseHosts(strings.Join(out, ",")); err != nil {
		return nil, err
	}
	return out, nil
}

func validateRest(a App, platforms map[string]bool) error {
	if !reName.MatchString(a.Name) || strings.HasSuffix(a.Name, "-") {
		return fmt.Errorf("nom invalide : minuscules, chiffres et tirets, 41 caractères au plus")
	}
	if !reRepo.MatchString(a.Repo) {
		return fmt.Errorf("repo %q : <organisation>/<dépôt> attendu", a.Repo)
	}
	if !platforms[a.Platform] {
		return fmt.Errorf("plateforme %q absente de policy/origines.yaml", a.Platform)
	}
	if a.Edge != "" && a.Edge != render.EdgeCloudflare {
		return fmt.Errorf("edge %q : %s seule valeur admise", a.Edge, render.EdgeCloudflare)
	}
	if !validStage(a.Stage) {
		return fmt.Errorf("stage %q : %s ou %s", a.Stage, StageProd, StagePreprod)
	}
	if a.HostHeader != "visitor" && a.HostHeader != "upstream" {
		return fmt.Errorf("host_header %q : visitor ou upstream", a.HostHeader)
	}
	for _, p := range a.CRSPlugins {
		if !rePlugin.MatchString(p) {
			return fmt.Errorf("crs_plugins : %q", p)
		}
	}
	if !reBranch.MatchString(a.Branch) || strings.Contains(a.Branch, "..") {
		return fmt.Errorf("branch %q invalide", a.Branch)
	}
	if !reWafDir.MatchString(a.WafDir) || reDotDots.MatchString(a.WafDir) {
		return fmt.Errorf("waf_dir %q : chemin relatif sans . ni ..", a.WafDir)
	}
	if !reMemory.MatchString(a.Memory) {
		return fmt.Errorf("resources.memory %q : <n>M ou <n>G attendu", a.Memory)
	}
	if a.CPUWeight < 2 || a.CPUWeight > 262144 {
		return fmt.Errorf("resources.cpu_weight %d : de 2 à 262144", a.CPUWeight)
	}
	c := a.Ceilings
	if c.EventsPerSecond < 1 {
		return fmt.Errorf("ceilings.events_per_second %d : 1 au moins", c.EventsPerSecond)
	}
	if _, err := render.ParseSize(c.UploadMaxSize); err != nil {
		return fmt.Errorf("ceilings.upload_max_size : %v", err)
	}
	if c.DetectionOnlyMaxDays < 1 {
		return fmt.Errorf("ceilings.detection_only_max_days %d : 1 au moins", c.DetectionOnlyMaxDays)
	}
	if _, err := render.ParseCeilings(c.Env()); err != nil {
		return err
	}
	return nil
}

// Read lit l'inventaire depuis un chemin local ou une URL https.
func Read(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") {
		return nil, fmt.Errorf("inventaire : URL https attendue")
	}
	if !strings.HasPrefix(src, "https://") {
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("inventaire : %w", err)
		}
		return b, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, fmt.Errorf("inventaire : %w", err)
	}
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return fmt.Errorf("redirection refusée vers %s", r.URL.Redacted())
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inventaire : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inventaire : %s a répondu %d", src, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("inventaire : %w", err)
	}
	if len(b) > maxSize {
		return nil, fmt.Errorf("inventaire : plus de %d octets", maxSize)
	}
	return b, nil
}
