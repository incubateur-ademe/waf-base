// Package certs porte la partie certificats de waf-ops : copie quotidienne
// d'acme.json de chaque VM WAF, et poussée du certificat de Traefik sur les
// domaines Scalingo de l'app, pour qu'un abandon du WAF ne tombe pas sur un
// certificat expiré (section 3.7 du design).
package certs

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	EnvCleSSH      = "WAF_OPS_ACME_SSH_KEY"
	EnvKnownHosts  = "WAF_OPS_ACME_KNOWN_HOSTS"
	EnvVMs         = "WAF_OPS_ACME_VMS"
	EnvFGPEcriture = "WAF_OPS_FGP_ECRITURE"

	// Plafond d'un blob côté FGP.
	maxBlob = 4096
	// Longueur minimale de la clé choisie à la génération des blobs.
	minCleFGP = 24
)

var (
	reRegion = regexp.MustCompile(`^osc-[a-z0-9-]{1,32}$`)
	reApp    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reVM     = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// Config : accès SSH aux VM WAF pour acme.json, et blobs FGP d'écriture, un par
// app Scalingo. L'URL et la clé FGP sont celles de WAF_OPS_FGP et
// WAF_OPS_FGP_KEY, que l'appelant a déjà lues.
type Config struct {
	State      string
	FGPURL     string
	FGPKey     string
	Ecriture   map[string]map[string]string
	Signer     ssh.Signer
	KnownHosts map[netip.Addr][]ssh.PublicKey
	VMs        map[string]netip.Addr
	// Racines de confiance des chaînes poussées ; nil : celles du système.
	Roots *x509.CertPool

	sshPort   int
	transport http.RoundTripper
}

// LoadConfig lit la config des certificats sans appel réseau et liste d'un coup
// les variables manquantes. Aucune valeur de variable n'entre dans une erreur.
func LoadConfig(getenv func(string) string, fgpURL, fgpKey, state string) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	vals := map[string]string{}
	var missing []string
	for _, k := range []string{EnvCleSSH, EnvKnownHosts, EnvVMs, EnvFGPEcriture} {
		vals[k] = get(k)
		if vals[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("variables manquantes : %s", strings.Join(missing, ", "))
	}
	if state == "" {
		return Config{}, errors.New("dossier d'état vide")
	}
	base, err := baseFGP(fgpURL)
	if err != nil {
		return Config{}, err
	}
	if len(fgpKey) < minCleFGP || strings.ContainsAny(fgpKey, " \t\r\n") {
		return Config{}, fmt.Errorf("clé FGP : %d caractères sans blanc au moins", minCleFGP)
	}
	signer, err := parseCleSSH(vals[EnvCleSSH])
	if err != nil {
		return Config{}, err
	}
	kh, err := parseKnownHosts(vals[EnvKnownHosts])
	if err != nil {
		return Config{}, err
	}
	vms, err := parseVMs(vals[EnvVMs])
	if err != nil {
		return Config{}, err
	}
	for name, ip := range vms {
		if len(kh[ip]) == 0 {
			return Config{}, fmt.Errorf("%s : aucune clé d'hôte pour %s (VM %s)", EnvKnownHosts, ip, name)
		}
	}
	ec, err := parseEcriture(vals[EnvFGPEcriture])
	if err != nil {
		return Config{}, err
	}
	return Config{
		State:      state,
		FGPURL:     base,
		FGPKey:     fgpKey,
		Ecriture:   ec,
		Signer:     signer,
		KnownHosts: kh,
		VMs:        vms,
	}, nil
}

func baseFGP(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		// L'URL peut porter des identifiants : elle n'entre pas dans le message.
		return "", errors.New("URL FGP : https://<hôte> attendue")
	}
	return "https://" + u.Host, nil
}

// parseCleSSH n'accepte qu'une clé ed25519 sans phrase de passe : la clé dédiée
// à acme.json (authorized_keys2 de chaque VM).
func parseCleSSH(raw string) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey([]byte(raw + "\n"))
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, fmt.Errorf("%s : clé chiffrée, attendue sans phrase de passe", EnvCleSSH)
		}
		return nil, fmt.Errorf("%s : clé privée OpenSSH multiligne attendue", EnvCleSSH)
	}
	if s.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%s : clé %s, ed25519 attendue", EnvCleSSH, s.PublicKey().Type())
	}
	return s, nil
}

// parseKnownHosts lit des lignes « <ip> <type> <clé> » : une IP en clair par
// hôte, sans motif, sans hachage et sans marqueur, pour que l'épinglage se
// relise d'un coup d'œil.
func parseKnownHosts(raw string) (map[netip.Addr][]ssh.PublicKey, error) {
	out := map[netip.Addr][]ssh.PublicKey{}
	for n, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("%s : ligne %d illisible", EnvKnownHosts, n+1)
		}
		if marker != "" {
			return nil, fmt.Errorf("%s : ligne %d : marqueur refusé", EnvKnownHosts, n+1)
		}
		for _, h := range hosts {
			h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(h, ":22"), "["), "]")
			ip, err := netip.ParseAddr(h)
			if err != nil || !ip.Is4() {
				return nil, fmt.Errorf("%s : ligne %d : IPv4 en clair attendue", EnvKnownHosts, n+1)
			}
			out[ip] = append(out[ip], key)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s : aucune clé d'hôte", EnvKnownHosts)
	}
	return out, nil
}

// parseVMs lit « <vm>=<ip privée>,… » : l'inventaire ne porte que l'IP
// publique des VM, et SSH passe par le Private Network.
func parseVMs(raw string) (map[string]netip.Addr, error) {
	out := map[string]netip.Addr{}
	for _, part := range strings.Split(raw, ",") {
		name, ip, ok := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.TrimSpace(name)
		if !ok || !reVM.MatchString(name) {
			return nil, fmt.Errorf("%s : <vm>=<ip privée> séparés par des virgules, nom de VM de l'inventaire", EnvVMs)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s : VM %s en double", EnvVMs, name)
		}
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || !a.Is4() || !a.IsPrivate() {
			return nil, fmt.Errorf("%s : VM %s : IPv4 privée attendue", EnvVMs, name)
		}
		out[name] = a
	}
	return out, nil
}

// parseEcriture lit {"<région>": {"<app Scalingo>": "<blob>"}}. Aucun morceau
// de la valeur n'entre dans un message : elle porte des blobs.
func parseEcriture(raw string) (map[string]map[string]string, error) {
	var m map[string]map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("%s : JSON {\"<région>\": {\"<app>\": \"<blob>\"}} attendu", EnvFGPEcriture)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("%s : aucun blob", EnvFGPEcriture)
	}
	regions := make([]string, 0, len(m))
	for r := range m {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	for i, r := range regions {
		if !reRegion.MatchString(r) {
			return nil, fmt.Errorf("%s : région n°%d hors de osc-<région>", EnvFGPEcriture, i+1)
		}
		apps := m[r]
		if len(apps) == 0 {
			return nil, fmt.Errorf("%s : %s sans blob", EnvFGPEcriture, r)
		}
		for app, blob := range apps {
			if !reApp.MatchString(app) {
				return nil, fmt.Errorf("%s : %s : nom d'app Scalingo invalide", EnvFGPEcriture, r)
			}
			if blob == "" || len(blob) > maxBlob || strings.ContainsAny(blob, " \t\r\n") {
				return nil, fmt.Errorf("%s : blob de %s (%s) vide, trop long ou avec des blancs", EnvFGPEcriture, app, r)
			}
		}
	}
	return m, nil
}

func (c Config) port() int {
	if c.sshPort != 0 {
		return c.sshPort
	}
	return 22
}

func (c Config) client() *http.Client {
	return &http.Client{
		Transport: c.transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
