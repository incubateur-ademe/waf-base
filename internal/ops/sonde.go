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
	Sonder(ctx context.Context, app, region string, hosts []string) (ecarts, notes []string, incertains int)
}

// Sonde fait les trois appels de la section 3.5 du design : la racine de
// l'URL Scalingo de l'app, un chemin aléatoire en POST, et chaque host de l'app
// envoyé à l'IP du routeur. Dial et TLS ne servent qu'aux tests.
type Sonde struct {
	Resolve func(ctx context.Context, host string) ([]string, error)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	TLS     *tls.Config
}

// client : routeur et origine ne servent qu'à l'appel du host à l'IP du
// routeur, où le certificat de l'origine est admis aussi.
func (s Sonde) client(routeur, origine string) *http.Client {
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
		tc.VerifyConnection = func(cs tls.ConnectionState) error { return sansEcheance(cs, roots, origine) }
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
// milieu de sa période de validité : seule son échéance est ignorée. Le nom
// admis est le host, ou l'origine <app>.<région>.scalingo.io : sans certificat
// pour le host, le routeur présente celui de l'origine, qu'un tiers ne peut pas
// présenter non plus. Un host en IP littérale n'a pas de nom vérifiable.
func sansEcheance(cs tls.ConnectionState, roots *x509.CertPool, origine string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("aucun certificat présenté")
	}
	if cs.ServerName == "" {
		return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: errors.New("host sans nom vérifiable")}
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	milieu := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: cs.ServerName, Roots: roots, Intermediates: inter, CurrentTime: milieu})
	if err != nil && origine != "" {
		if _, e2 := leaf.Verify(x509.VerifyOptions{DNSName: origine, Roots: roots, Intermediates: inter, CurrentTime: milieu}); e2 == nil {
			return nil
		}
	}
	if err != nil {
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

func (s Sonde) Sonder(ctx context.Context, app, region string, hosts []string) (ecarts, notes []string, incertains int) {
	origin := app + "." + region + ".scalingo.io"
	base := "https://" + origin
	c := s.client("", "")
	appel := func(cl *http.Client, method, u, quoi string) {
		msg, inc, detail := sonder(ctx, cl, method, u)
		if msg == "" {
			return
		}
		ecarts = append(ecarts, quoi+" : "+msg)
		if detail != "" {
			notes = append(notes, quoi+" : "+detail)
		}
		if inc {
			incertains++
		}
	}
	appel(c, http.MethodGet, base+"/", "origine "+base+"/")
	appel(c, http.MethodPost, base+cheminAleatoire(), "origine "+base+", POST sur un chemin aléatoire")
	if len(hosts) == 0 {
		return ecarts, notes, incertains
	}
	ips, err := s.resolve(ctx, origin)
	if err != nil || len(ips) == 0 {
		ecarts = append(ecarts, fmt.Sprintf("IP du routeur de %s introuvable, hosts non sondés", origin))
		if err != nil {
			notes = append(notes, fmt.Sprintf("résolution de %s : %v", origin, err))
			incertains++
		}
		return ecarts, notes, incertains
	}
	cr := s.client(ips[0], origin)
	for i, h := range hosts {
		if i == maxSondeHosts {
			notes = append(notes, fmt.Sprintf("%d host(s) au-delà de %d non sondés à l'IP du routeur", len(hosts)-maxSondeHosts, maxSondeHosts))
			break
		}
		appel(cr, http.MethodGet, "https://"+h+"/", fmt.Sprintf("host %s envoyé au routeur %s", h, ips[0]))
	}
	return ecarts, notes, incertains
}

// sonder rend "" si la réponse est le refus du firewall, sinon ce qui a été
// reçu ; incertain si rien n'a été reçu, detail pour les logs. Ni corps ni
// en-tête n'entrent dans le message.
func sonder(ctx context.Context, c *http.Client, method, u string) (msg string, incertain bool, detail string) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return "requête invalide", false, ""
	}
	req.Header.Set("User-Agent", "waf-ops-sonde")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		detail = propre(err.Error(), 300)
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) {
			return "sans réponse : certificat refusé", false, detail
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "sans réponse : délai dépassé", true, detail
		}
		return "sans réponse : " + propre(err.Error(), maxDetail), true, detail
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSondeBody))
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Sprintf("HTTP %d au lieu du 403 du firewall", resp.StatusCode), false, ""
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !reAccessDenied.Match(body) {
		return "403 sans la page du routeur Scalingo (SCALINGO_FORBIDDEN_PAGE_URL ?)", false, ""
	}
	return "", false, ""
}
