package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Résolveur ACME du proxy Coolify.
const resolveur = "letsencrypt"

// cleTLS porte une clé privée TLS, toujours derrière un pointeur : fmt
// n'imprime qu'une adresse pour un pointeur imbriqué, et n'appelle pas Format
// sur un champ non exporté. Toute mise en forme directe rend un texte fixe.
// Seul clair() rend la clé, pour le corps du PATCH.
type cleTLS struct{ pem []byte }

const cleMasquee = "<clé TLS>"

func (cleTLS) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, cleMasquee) }
func (cleTLS) MarshalJSON() ([]byte, error) { return json.Marshal(cleMasquee) }
func (cleTLS) MarshalText() ([]byte, error) { return []byte(cleMasquee), nil }
func (cleTLS) LogValue() slog.Value         { return slog.StringValue(cleMasquee) }
func (c *cleTLS) clair() string             { return string(c.pem) }

// certificat : un certificat d'acme.json, chaîne et clé relues et vérifiées
// l'une contre l'autre.
type certificat struct {
	VM      string
	feuille *x509.Certificate
	inter   []*x509.Certificate
	chaine  []byte
	cle     *cleTLS
}

// Les champs certificate et key restent des chaînes : une entrée au base64
// corrompu est sautée seule, au lieu de faire échouer tout le fichier.
type acmeFichier map[string]*struct {
	Certificates []struct {
		Domain struct {
			Main string   `json:"main"`
			SANs []string `json:"sans"`
		} `json:"domain"`
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	} `json:"Certificates"`
}

// parseAcme lit acme.json au format de Traefik : résolveur letsencrypt,
// Certificates[].certificate et .key en PEM encodé en base64. Un certificat
// illisible est sauté avec une note. Aucune erreur ni note ne reprend un
// morceau du fichier, qui porte toutes les clés privées.
func parseAcme(raw []byte, vm string) ([]certificat, []string, error) {
	var f acmeFichier
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, errors.New("acme.json : JSON illisible")
	}
	r, ok := f[resolveur]
	if !ok || r == nil {
		return nil, nil, fmt.Errorf("acme.json : résolveur %s absent", resolveur)
	}
	var out []certificat
	var notes []string
	for i, c := range r.Certificates {
		nom := fmt.Sprintf("n°%d (%s)", i+1, assaini(c.Domain.Main))
		certPEM, err := base64.StdEncoding.DecodeString(c.Certificate)
		if err != nil {
			notes = append(notes, fmt.Sprintf("certificat %s : chaîne hors base64", nom))
			continue
		}
		keyPEM, err := base64.StdEncoding.DecodeString(c.Key)
		if err != nil {
			notes = append(notes, fmt.Sprintf("certificat %s : clé hors base64", nom))
			continue
		}
		chaine, feuille, inter, err := relireChaine(certPEM)
		if err != nil {
			notes = append(notes, fmt.Sprintf("certificat %s : %v", nom, err))
			continue
		}
		cle, err := relireCle(keyPEM)
		if err != nil {
			notes = append(notes, fmt.Sprintf("certificat %s : %v", nom, err))
			continue
		}
		// X509KeyPair vérifie que la clé va avec la feuille ; son erreur reste hors du message.
		if _, err := tls.X509KeyPair(chaine, cle); err != nil {
			notes = append(notes, fmt.Sprintf("certificat %s : clé illisible ou sans rapport avec le certificat", nom))
			continue
		}
		out = append(out, certificat{VM: vm, feuille: feuille, inter: inter, chaine: chaine, cle: &cleTLS{pem: cle}})
	}
	return out, notes, nil
}

// relireChaine ne garde que des blocs CERTIFICATE sans en-tête, ré-encodés : la
// chaîne poussée commence alors par « -----BEGIN CERTIFICATE----- », comme le
// filtre de corps du blob d'écriture l'exige.
func relireChaine(b []byte) ([]byte, *x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	var out bytes.Buffer
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" || len(blk.Headers) > 0 {
			return nil, nil, nil, errors.New("chaîne : bloc PEM autre qu'un certificat")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, nil, errors.New("chaîne : certificat illisible")
		}
		certs = append(certs, c)
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	if len(certs) == 0 {
		return nil, nil, nil, errors.New("chaîne : aucun certificat")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, nil, nil, errors.New("chaîne : contenu hors PEM")
	}
	return out.Bytes(), certs[0], certs[1:], nil
}

// relireCle n'admet qu'un bloc de clé privée en clair, ré-encodé : les types
// que le blob d'écriture laisse passer (PRIVATE KEY, RSA ou EC PRIVATE KEY).
func relireCle(b []byte) ([]byte, error) {
	blk, rest := pem.Decode(b)
	if blk == nil || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("clé : un bloc PEM attendu")
	}
	switch blk.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, errors.New("clé : type de bloc PEM refusé")
	}
	if len(blk.Headers) > 0 {
		return nil, errors.New("clé : bloc PEM chiffré ou avec en-têtes")
	}
	return pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: blk.Bytes}), nil
}

var reAssaini = regexp.MustCompile(`[^a-z0-9.*-]`)

// assaini rend un nom venu d'acme.json ou de Scalingo sûr pour une note : il
// finit dans les logs, où un retour à la ligne forgerait une fausse entrée.
func assaini(s string) string {
	s = reAssaini.ReplaceAllString(strings.ToLower(s), "?")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	if s == "" {
		return "?"
	}
	return s
}

// choisir rend, parmi les certificats qui couvrent host, celui qui expire le
// plus tard et dont la chaîne se vérifie à now contre les racines : un
// certificat de staging, expiré ou pas encore valide n'est jamais poussé.
func choisir(certs []certificat, host string, now time.Time, roots *x509.CertPool) (*certificat, string) {
	var couvrent []certificat
	for _, c := range certs {
		if c.feuille.VerifyHostname(host) == nil {
			couvrent = append(couvrent, c)
		}
	}
	if len(couvrent) == 0 {
		return nil, "aucun certificat pour " + host
	}
	sort.SliceStable(couvrent, func(i, j int) bool { return couvrent[i].feuille.NotAfter.After(couvrent[j].feuille.NotAfter) })
	var raison string
	for i := range couvrent {
		c := couvrent[i]
		pool := x509.NewCertPool()
		for _, ic := range c.inter {
			pool.AddCert(ic)
		}
		_, err := c.feuille.Verify(x509.VerifyOptions{
			DNSName:       host,
			Intermediates: pool,
			Roots:         roots,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err == nil {
			return &c, ""
		}
		if raison == "" {
			raison = raisonChaine(err, c.feuille, now)
		}
	}
	return nil, fmt.Sprintf("aucun certificat valide pour %s (le plus récent : %s)", host, raison)
}

func raisonChaine(err error, f *x509.Certificate, now time.Time) string {
	var ci x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	switch {
	case now.After(f.NotAfter):
		return "expiré le " + jour(f.NotAfter)
	case now.Before(f.NotBefore):
		return "pas encore valide"
	case errors.As(err, &ua):
		return "autorité inconnue"
	case errors.As(err, &ci):
		return "chaîne invalide"
	}
	return "chaîne non vérifiée"
}

func jour(t time.Time) string { return t.UTC().Format("2006-01-02") }
