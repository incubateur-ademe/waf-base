package ops

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	sondeTimeout = 15 * time.Second
	maxSondeBody = 64 << 10
	// Au-delà, les hosts suivants d'une app ne sont pas sondés à l'IP du routeur.
	maxSondeHosts = 10
)

// Signature du refus du firewall applicatif : la page du routeur Scalingo, que
// SCALINGO_FORBIDDEN_PAGE_URL remplacerait (relevé du 2026-11-20 sur waf-pilote).
var reAccessDenied = regexp.MustCompile(`<title>\s*Access denied - Scalingo\s*</title>`)

// Origine sonde l'origine d'une app verrouillée depuis outils, dont l'IP n'est
// dans aucune règle : chaque appel doit recevoir le 403 du firewall.
type Origine interface {
	Sonder(ctx context.Context, app, region string, hosts []string) (ecarts, notes []string)
}

// Sonde fait les trois appels de la section 3.5 du design : la racine de
// l'URL Scalingo de l'app, un chemin aléatoire en POST, et chaque host de l'app
// envoyé à l'IP du routeur. Dial et TLS ne servent qu'aux tests.
type Sonde struct {
	Resolve func(ctx context.Context, host string) ([]string, error)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	TLS     *tls.Config
}

func (s Sonde) client(routeur string) *http.Client {
	d := s.Dial
	if d == nil {
		d = (&net.Dialer{Timeout: sondeTimeout}).DialContext
	}
	dial := d
	if routeur != "" {
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d(ctx, network, net.JoinHostPort(routeur, "443"))
		}
	}
	var tc *tls.Config
	if s.TLS != nil {
		tc = s.TLS.Clone()
	}
	if routeur != "" {
		// À l'IP du routeur, le certificat est celui que Scalingo garde pour le
		// host, poussé à la main ou par waf-ops : son échéance n'est pas l'objet
		// de la sonde. La chaîne et le nom restent vérifiés, pour qu'un tiers sur
		// le chemin ne puisse pas servir un faux 403.
		if tc == nil {
			tc = &tls.Config{}
		}
		roots := tc.RootCAs
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error { return sansEcheance(cs, roots) }
	}
	return &http.Client{
		Timeout: sondeTimeout,
		Transport: &http.Transport{
			DialContext:         dial,
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: sondeTimeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// sansEcheance vérifie la chaîne et le nom du certificat à une date prise au
// milieu de sa période de validité : seule son échéance est ignorée.
func sansEcheance(cs tls.ConnectionState, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("aucun certificat présenté")
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	milieu := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: cs.ServerName, Roots: roots, Intermediates: inter, CurrentTime: milieu}); err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: err}
	}
	return nil
}

func (s Sonde) resolve(ctx context.Context, host string) ([]string, error) {
	if s.Resolve != nil {
		return s.Resolve(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if a.IP.To4() != nil {
			out = append(out, a.IP.String())
		}
	}
	return out, nil
}

func cheminAleatoire() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "/sonde-waf-ops-" + hex.EncodeToString(b)
}

func (s Sonde) Sonder(ctx context.Context, app, region string, hosts []string) (ecarts, notes []string) {
	origin := app + "." + region + ".scalingo.io"
	base := "https://" + origin
	c := s.client("")
	if msg := sonder(ctx, c, http.MethodGet, base+"/"); msg != "" {
		ecarts = append(ecarts, fmt.Sprintf("origine %s/ : %s", base, msg))
	}
	if msg := sonder(ctx, c, http.MethodPost, base+cheminAleatoire()); msg != "" {
		ecarts = append(ecarts, fmt.Sprintf("origine %s, POST sur un chemin aléatoire : %s", base, msg))
	}
	if len(hosts) == 0 {
		return ecarts, notes
	}
	ips, err := s.resolve(ctx, origin)
	if err != nil || len(ips) == 0 {
		ecarts = append(ecarts, fmt.Sprintf("IP du routeur de %s introuvable, hosts non sondés", origin))
		if err != nil {
			notes = append(notes, fmt.Sprintf("résolution de %s : %v", origin, err))
		}
		return ecarts, notes
	}
	cr := s.client(ips[0])
	for i, h := range hosts {
		if i == maxSondeHosts {
			notes = append(notes, fmt.Sprintf("%d host(s) au-delà de %d non sondés à l'IP du routeur", len(hosts)-maxSondeHosts, maxSondeHosts))
			break
		}
		if msg := sonder(ctx, cr, http.MethodGet, "https://"+h+"/"); msg != "" {
			ecarts = append(ecarts, fmt.Sprintf("host %s envoyé au routeur %s : %s", h, ips[0], msg))
		}
	}
	return ecarts, notes
}

// sonder rend "" si la réponse est le refus du firewall, sinon ce qui a été
// reçu. Ni corps ni en-tête n'entrent dans le message.
func sonder(ctx context.Context, c *http.Client, method, u string) string {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return "requête invalide"
	}
	req.Header.Set("User-Agent", "waf-ops-sonde")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) {
			return "sans réponse : certificat refusé"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "sans réponse : délai dépassé"
		}
		return "sans réponse : " + propre(err.Error(), maxDetail)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSondeBody))
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Sprintf("HTTP %d au lieu du 403 du firewall", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !reAccessDenied.Match(body) {
		return "403 sans la page du routeur Scalingo (SCALINGO_FORBIDDEN_PAGE_URL ?)"
	}
	return ""
}
