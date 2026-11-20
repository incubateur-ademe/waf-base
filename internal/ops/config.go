// Package ops porte waf-ops, le conteneur d'outils qui contrôle les WAF : boucle
// des contrôles, accès à l'API Scalingo par FGP, pulse updown (section 9.2 du
// design).
package ops

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	DefaultFGPURL = "https://fgp.incubateur.ademe.fr"
	DefaultState  = "/var/lib/waf-ops"
	// Plafond d'un blob côté FGP.
	maxBlob = 4096
	// Longueur minimale de la clé choisie à la génération des blobs.
	minKey = 24
)

var reRegion = regexp.MustCompile(`^osc-[a-z0-9-]{1,32}$`)

// FGP décrit l'accès à l'API Scalingo par fine-grained-proxy : un blob d'API par
// région, tous chiffrés avec la même clé. Le JSON de WAF_OPS_FGP ne porte que
// les blobs, opaques sans la clé, qui arrive par WAF_OPS_FGP_KEY.
type FGP struct {
	URL string            `json:"url"`
	API map[string]string `json:"api"`
	Key string            `json:"-"`
}

type Config struct {
	CoolifyURL   string
	CoolifyToken string
	Inventaire   string
	Etc          string
	Stages       map[string]bool
	FGP          FGP
	PulseURL     string
	State        string
	Provision    *Provision
	Opt          Optionnelles
}

// StageList rend les stages traités, triés, pour les messages.
func (c Config) StageList() []string {
	l := make([]string, 0, len(c.Stages))
	for s := range c.Stages {
		l = append(l, s)
	}
	sort.Strings(l)
	return l
}

// Mode dit ce qu'une commande exige de l'environnement.
type Mode int

const (
	// ModeBoucle : contrôles et pulse.
	ModeBoucle Mode = iota
	// ModeControle : un passage, sans pulse.
	ModeControle
	// ModeScopes : génération des scopes FGP, sans FGP ni pulse.
	ModeScopes
)

// LoadConfig lit l'environnement sans appel réseau et liste d'un coup les
// variables requises manquantes.
func LoadConfig(getenv func(string) string, mode Mode) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := Config{
		CoolifyURL:   get("COOLIFY_URL"),
		CoolifyToken: get("COOLIFY_TOKEN"),
		Inventaire:   get("WAF_OPS_INVENTAIRE"),
		Etc:          get("WAF_OPS_ETC"),
		PulseURL:     get("WAF_OPS_PULSE_URL"),
		State:        get("WAF_OPS_STATE"),
	}
	stages, fgpJSON, key := get("WAF_OPS_STAGES"), get("WAF_OPS_FGP"), get("WAF_OPS_FGP_KEY")
	required := []struct{ k, v string }{
		{"COOLIFY_URL", c.CoolifyURL},
		{"COOLIFY_TOKEN", c.CoolifyToken},
		{"WAF_OPS_STAGES", stages},
	}
	if mode != ModeScopes {
		required = append(required, struct{ k, v string }{"WAF_OPS_FGP", fgpJSON}, struct{ k, v string }{"WAF_OPS_FGP_KEY", key})
	}
	if mode == ModeBoucle {
		required = append(required, struct{ k, v string }{"WAF_OPS_PULSE_URL", c.PulseURL})
	}
	var missing []string
	for _, r := range required {
		if r.v == "" {
			missing = append(missing, r.k)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("variables manquantes : %s", strings.Join(missing, ", "))
	}
	if c.Inventaire == "" {
		c.Inventaire = inventory.DefaultURL
	}
	if c.Etc == "" {
		c.Etc = "/etc/waf"
	}
	if c.State == "" {
		c.State = DefaultState
	}
	c.Stages = map[string]bool{}
	for _, s := range strings.Split(stages, ",") {
		s = strings.TrimSpace(s)
		if s != inventory.StageProd && s != inventory.StagePreprod {
			return Config{}, fmt.Errorf("WAF_OPS_STAGES : stage %q, %s ou %s", s, inventory.StageProd, inventory.StagePreprod)
		}
		c.Stages[s] = true
	}
	if mode != ModeScopes {
		fgp, err := parseFGP(fgpJSON, key)
		if err != nil {
			return Config{}, err
		}
		c.FGP = fgp
		p, err := parseProvision(get("WAF_OPS_PROVISION"))
		if err != nil {
			return Config{}, err
		}
		c.Provision = p
		c.Opt = chargerOptionnelles(getenv, c.FGP, c.State)
	}
	if c.PulseURL != "" {
		if u, err := url.Parse(c.PulseURL); err != nil || u.Scheme != "https" || u.Host == "" {
			// La valeur est un secret : elle n'entre pas dans le message.
			return Config{}, fmt.Errorf("WAF_OPS_PULSE_URL : URL https attendue")
		}
	}
	return c, nil
}

func parseFGP(raw, key string) (FGP, error) {
	var f FGP
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		// L'erreur de décodage peut citer un morceau de blob : elle reste hors du message.
		return FGP{}, fmt.Errorf("WAF_OPS_FGP : JSON {\"url\", \"api\": {\"<région>\": \"<blob>\"}} attendu")
	}
	if f.URL == "" {
		f.URL = DefaultFGPURL
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		// L'URL peut porter des identifiants : elle n'entre pas dans le message.
		return FGP{}, fmt.Errorf("WAF_OPS_FGP : url https://<hôte> attendue")
	}
	f.URL = "https://" + u.Host
	if len(f.API) == 0 {
		return FGP{}, fmt.Errorf("WAF_OPS_FGP : aucun blob d'API")
	}
	for region, blob := range f.API {
		if !reRegion.MatchString(region) {
			// Une région et son blob inversés citeraient le blob : la valeur reste hors du message.
			return FGP{}, fmt.Errorf("WAF_OPS_FGP : clé de api hors de osc-<région>")
		}
		if blob == "" || len(blob) > maxBlob || strings.ContainsAny(blob, " \t\r\n") {
			return FGP{}, fmt.Errorf("WAF_OPS_FGP : blob de %s vide, trop long ou avec des blancs", region)
		}
	}
	if len(key) < minKey || strings.ContainsAny(key, " \t\r\n") {
		return FGP{}, fmt.Errorf("WAF_OPS_FGP_KEY : %d caractères sans blanc au moins", minKey)
	}
	f.Key = key
	return f, nil
}
