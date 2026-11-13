// Package tenant lit et borne waf/waf.yaml.
package tenant

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Zone struct {
	Name    string   `yaml:"name" json:"name"`
	Paths   []string `yaml:"paths" json:"paths"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Events  int      `yaml:"events" json:"events"`
	Window  string   `yaml:"window" json:"window"`
	Reason  string   `yaml:"reason" json:"reason"`
}

type Default struct {
	Events int    `yaml:"events"`
	Window string `yaml:"window"`
}

type Config struct {
	Version    int      `yaml:"version"`
	Contacts   []string `yaml:"contacts"`
	RateLimits struct {
		Default Default `yaml:"default"`
		Zones   []Zone  `yaml:"zones"`
	} `yaml:"rate_limits"`
}

var (
	reZone    = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	rePath    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)
	reContact = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$`)
	windows   = []string{"1s", "10s", "1m"}
	methods   = []string{"GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"}
)

const MaxZones = 8

// maxFor convertit le plafond par seconde de l'inventaire en plafond par fenêtre.
func maxFor(window string, perSecond int) int {
	switch window {
	case "10s":
		return perSecond * 10
	case "1m":
		return perSecond * 60
	}
	return perSecond
}

// Load lit waf.yaml ; un fichier absent donne le rate limit par défaut de l'inventaire.
func Load(path string, maxEvents int) (*Config, error) {
	c := &Config{Version: 1}
	c.RateLimits.Default = Default{Events: 40, Window: "1s"}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(c); err != nil {
		return nil, fmt.Errorf("waf.yaml : %w", err)
	}
	return c, c.Validate(maxEvents)
}

func (c *Config) Validate(maxEvents int) error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if c.Version != 1 {
		add("version : 1 attendu")
	}
	if len(c.Contacts) > 10 {
		add("contacts : 10 au plus")
	}
	for _, m := range c.Contacts {
		if !reContact.MatchString(m) {
			add("contact %q : adresse e-mail attendue", m)
		}
	}
	d := c.RateLimits.Default
	if m := maxFor(d.Window, maxEvents); d.Events < 1 || d.Events > m {
		add("rate_limits.default.events : 1 à %d pour une fenêtre de %s", m, d.Window)
	}
	if !slices.Contains(windows, d.Window) {
		add("rate_limits.default.window : %s", strings.Join(windows, ", "))
	}
	if len(c.RateLimits.Zones) > MaxZones {
		add("rate_limits.zones : %d au plus", MaxZones)
	}
	seen := map[string]bool{"defaut": true}
	for i, z := range c.RateLimits.Zones {
		p := fmt.Sprintf("rate_limits.zones[%d]", i)
		if !reZone.MatchString(z.Name) || seen[z.Name] {
			add("%s.name : [a-z0-9_]{1,32}, unique, différent de defaut", p)
		}
		seen[z.Name] = true
		if len(z.Paths) == 0 || len(z.Paths) > 10 {
			add("%s.paths : 1 à 10 chemins", p)
		}
		for _, path := range z.Paths {
			if !rePath.MatchString(path) || path == "/" {
				add("%s.paths : %q refusé (^/[A-Za-z0-9._~/-]{0,200}$, différent de /)", p, path)
			}
		}
		for _, m := range z.Methods {
			if !slices.Contains(methods, m) {
				add("%s.methods : %q refusée", p, m)
			}
		}
		if m := maxFor(z.Window, maxEvents); z.Events < 1 || z.Events > m {
			add("%s.events : 1 à %d pour une fenêtre de %s", p, m, z.Window)
		}
		if !slices.Contains(windows, z.Window) {
			add("%s.window : %s", p, strings.Join(windows, ", "))
		}
		if len(z.Reason) == 0 || len(z.Reason) > 200 || strings.ContainsAny(z.Reason, "\n\r{}`") {
			add("%s.reason : 1 à 200 caractères, sans saut de ligne ni accolade", p)
		}
	}
	if len(errs) > 0 {
		return errors.New("waf.yaml : " + strings.Join(errs, " ; "))
	}
	return nil
}
