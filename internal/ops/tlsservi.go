package ops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	// Traefik renouvelle à 30 jours de l'échéance : à 21 jours, le
	// renouvellement a échoué au moins une semaine.
	certMarge   = 21 * 24 * time.Hour
	tlsTimeout  = 15 * time.Second
	maxTLSHosts = 20
)

// Certificats rend le certificat feuille présenté par l'IP pour le host, après
// vérification de la chaîne et du nom.
type Certificats interface {
	Feuille(ctx context.Context, ip, host string) (*x509.Certificate, error)
}

// TLSServi se connecte à ip:443 avec le host en SNI. Roots ne sert qu'aux
// tests : nil, ce sont les racines du système.
type TLSServi struct {
	Roots *x509.CertPool
	Dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (t TLSServi) Feuille(ctx context.Context, ip, host string) (*x509.Certificate, error) {
	d := t.Dial
	if d == nil {
		d = (&net.Dialer{Timeout: tlsTimeout}).DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, tlsTimeout)
	defer cancel()
	raw, err := d(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: t.Roots, MinVersion: tls.VersionTLS12})
	defer c.Close()
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("aucun certificat présenté")
	}
	return certs[0], nil
}

// ControleCertificats : sur chaque VM du stage de l'app, le certificat
// présenté pour chaque host est valide pour lui et n'expire pas avant 21 jours.
// Une VM qui ne répond pas au premier host est injoignable : ses autres hosts
// ne sont pas tentés. incertains compte les contrôles restés sans réponse.
func ControleCertificats(ctx context.Context, c Certificats, a inventory.App, vmIPs []string, now time.Time) (ecarts, notes []string, incertains int) {
	hosts := a.Hosts
	if len(hosts) > maxTLSHosts {
		notes = append(notes, fmt.Sprintf("certificats : %d host(s) au-delà de %d non contrôlés", len(hosts)-maxTLSHosts, maxTLSHosts))
		hosts = hosts[:maxTLSHosts]
	}
	for _, ip := range vmIPs {
		for i, h := range hosts {
			leaf, err := c.Feuille(ctx, ip, h)
			if err != nil {
				msg, reseau := tlsProbleme(err)
				notes = append(notes, fmt.Sprintf("certificat de %s sur %s : %v", h, ip, err))
				if reseau {
					incertains++
				}
				if reseau && i == 0 {
					ecarts = append(ecarts, fmt.Sprintf("certificats : VM %s injoignable en 443 (%s), %d host(s) non contrôlés", ip, msg, len(hosts)))
					break
				}
				ecarts = append(ecarts, fmt.Sprintf("certificat de %s sur %s : %s", h, ip, msg))
				continue
			}
			if reste := leaf.NotAfter.Sub(now); reste < certMarge {
				ecarts = append(ecarts, fmt.Sprintf("certificat de %s sur %s : expire le %s", h, ip, leaf.NotAfter.UTC().Format(time.DateOnly)))
			}
		}
	}
	return ecarts, notes, incertains
}

// tlsProbleme : la cause en clair, et si elle tient au réseau plutôt qu'au
// certificat.
func tlsProbleme(err error) (msg string, reseau bool) {
	var he x509.HostnameError
	var ie x509.CertificateInvalidError
	var ce *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &he):
		return "certificat pour un autre nom", false
	case errors.As(err, &ie) && ie.Reason == x509.Expired && ie.Cert != nil:
		return "certificat expiré le " + ie.Cert.NotAfter.UTC().Format(time.DateOnly), false
	case errors.As(err, &ce):
		return "certificat refusé", false
	case errors.Is(err, context.DeadlineExceeded):
		return "délai dépassé", true
	case errors.As(err, &ne):
		return "connexion en échec", true
	}
	return "poignée de main TLS en échec", false
}
