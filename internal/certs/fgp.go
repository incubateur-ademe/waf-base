package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Domain : un domaine Scalingo, tel que GET /v1/apps/<app>/domains le rend. En
// lecture, tlscert est le sujet du certificat posé, et validity sa fin de
// validité : l'API ne rend jamais le certificat lui-même.
type Domain struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	SSL      bool     `json:"ssl"`
	TLSCert  string   `json:"tlscert"`
	Validity Validite `json:"validity"`
}

// Validite admet null et "" : un domaine sans certificat n'a pas de validité.
type Validite struct{ time.Time }

func (v *Validite) UnmarshalJSON(b []byte) error {
	if s := string(bytes.TrimSpace(b)); s == "null" || s == `""` {
		*v = Validite{}
		return nil
	}
	return v.Time.UnmarshalJSON(b)
}

// Lecteur liste les domaines d'une app Scalingo par le blob FGP de lecture de
// sa région. L'appelant le fournit : c'est le client de waf-ops.
type Lecteur interface {
	DomainesTLS(ctx context.Context, region, app string) ([]Domain, error)
}

// ErreurFGP distingue un refus du proxy (blob sans le scope, clé fausse) d'une
// réponse de Scalingo, par l'en-tête X-FGP-Source.
type ErreurFGP struct {
	Path   string
	Status int
	Source string
}

func (e *ErreurFGP) Error() string {
	if e.Source == "proxy" {
		return fmt.Sprintf("FGP refuse PATCH %s (HTTP %d) : scope absent du blob d'écriture, filtre de corps ou clé fausse", e.Path, e.Status)
	}
	return fmt.Sprintf("Scalingo répond %d au PATCH %s", e.Status, e.Path)
}

// ErrInjoignable : FGP n'a pas répondu, réseau ou délai.
var ErrInjoignable = errors.New("FGP injoignable")

// ErrSansBlob : aucun blob d'écriture pour l'app dans WAF_OPS_FGP_ECRITURE.
var ErrSansBlob = errors.New("aucun blob FGP d'écriture pour l'app")

// Seule route que le client d'écriture accepte d'appeler.
var rePatch = regexp.MustCompile(`^/v1/apps/[a-z0-9][a-z0-9-]{0,62}/domains/[A-Za-z0-9_-]{1,100}$`)

const maxReponse = 1 << 20

type ecrivain interface {
	poser(ctx context.Context, region, app, id string, chaine []byte, cle *cleTLS) (Domain, error)
}

type fgpEcrivain struct{ cfg Config }

var errABlanc = errors.New("à blanc")

// blancEcrivain ne pousse rien : il sert l'aperçu d'un passage.
type blancEcrivain struct{}

func (blancEcrivain) poser(context.Context, string, string, string, []byte, *cleTLS) (Domain, error) {
	return Domain{}, errABlanc
}

// poser envoie la chaîne et la clé sur le domaine par le blob d'écriture de
// l'app. Le corps n'a que tlscert et tlskey : ni canonical ni
// letsencrypt_enabled, que le filtre de corps du blob laisserait passer. Aucune
// erreur ne reprend le corps de la requête ni celui de la réponse.
func (c fgpEcrivain) poser(ctx context.Context, region, app, id string, chaine []byte, cle *cleTLS) (Domain, error) {
	path := "/v1/apps/" + app + "/domains/" + id
	if !reApp.MatchString(app) || !rePatch.MatchString(path) {
		return Domain{}, fmt.Errorf("PATCH hors de la route du client : app %s, domaine %s", assaini(app), assaini(id))
	}
	blob, ok := c.cfg.Ecriture[region][app]
	if !ok {
		return Domain{}, ErrSansBlob
	}
	if !bytes.HasPrefix(chaine, []byte("-----BEGIN CERTIFICATE-----\n")) || cle == nil || len(cle.pem) == 0 {
		return Domain{}, errors.New("chaîne ou clé vide")
	}
	var corps struct {
		Domain struct {
			TLSCert string `json:"tlscert"`
			TLSKey  string `json:"tlskey"`
		} `json:"domain"`
	}
	corps.Domain.TLSCert = string(chaine)
	corps.Domain.TLSKey = cle.clair()
	raw, err := json.Marshal(corps)
	if err != nil {
		return Domain{}, errors.New("corps du PATCH non construit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.cfg.FGPURL+path, bytes.NewReader(raw))
	if err != nil {
		return Domain{}, errors.New("requête PATCH invalide")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FGP-Key", c.cfg.FGPKey)
	req.Header.Set("X-FGP-Blob", blob)
	resp, err := c.cfg.client().Do(req)
	if err != nil {
		// L'erreur de transport cite l'URL, sans les en-têtes ni le corps.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Domain{}, fmt.Errorf("%w : PATCH %s : %v", ErrInjoignable, path, err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxReponse+1))
	if err != nil {
		return Domain{}, fmt.Errorf("%w : PATCH %s : réponse coupée", ErrInjoignable, path)
	}
	if resp.StatusCode != http.StatusOK {
		return Domain{}, &ErreurFGP{Path: path, Status: resp.StatusCode, Source: strings.ToLower(resp.Header.Get("X-FGP-Source"))}
	}
	if len(rb) > maxReponse {
		return Domain{}, fmt.Errorf("PATCH %s : réponse de plus de %d octets", path, maxReponse)
	}
	var out struct {
		Domain *Domain `json:"domain"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || out.Domain == nil {
		return Domain{}, fmt.Errorf("PATCH %s : réponse illisible", path)
	}
	return *out.Domain, nil
}
