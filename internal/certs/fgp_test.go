package certs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func certPilote(t *testing.T) (emis, certificat) {
	t.Helper()
	e := lePKI(t).feuille(t, optsFeuille{cn: hostPilote})
	cs, _, err := parseAcme(acmeJSON(t, "letsencrypt", entree{main: hostPilote, cert: e.chaine, key: e.cle}), "preprod")
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %d", err, len(cs))
	}
	return e, cs[0]
}

func TestPoserCorpsExact(t *testing.T) {
	f := demarrerFGP(t)
	e, c := certPilote(t)
	d, err := fgpEcrivain{cfg: cfgTest(t, f)}.poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, c.chaine, c.cle)
	if err != nil {
		t.Fatal(err)
	}
	if !d.SSL || !d.Validity.Equal(e.leaf.NotAfter) {
		t.Errorf("réponse relue : ssl %v, validité %v", d.SSL, d.Validity)
	}
	appels := f.liste()
	if len(appels) != 1 {
		t.Fatalf("%d appels", len(appels))
	}
	a := appels[0]
	if a.Method != http.MethodPatch || a.Path != "/v1/apps/waf-pilote/domains/"+idPilote {
		t.Errorf("%s %s", a.Method, a.Path)
	}
	if a.Key != testCleFGP || a.Blob != testBlob || a.ContentType != "application/json" {
		t.Errorf("en-têtes %q %q %q", a.Key, a.Blob, a.ContentType)
	}
	var corps map[string]map[string]any
	if err := json.Unmarshal(a.Body, &corps); err != nil {
		t.Fatal(err)
	}
	if len(corps) != 1 || len(corps["domain"]) != 2 {
		t.Fatalf("corps hors de {domain: {tlscert, tlskey}} : %d clés", len(corps["domain"]))
	}
	if corps["domain"]["tlscert"] != string(e.chaine) || corps["domain"]["tlskey"] != string(e.cle) {
		t.Error("tlscert ou tlskey ne reprend pas la chaîne et la clé d'acme.json")
	}
	if !strings.HasPrefix(corps["domain"]["tlscert"].(string), "-----BEGIN CERTIFICATE-----") {
		t.Error("tlscert hors du filtre du blob")
	}
}

// Une redirection n'est jamais suivie : le corps porte la clé privée.
func TestPoserSansRedirection(t *testing.T) {
	ailleurs := 0
	cible := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ailleurs++ }))
	defer cible.Close()
	f := demarrerFGP(t)
	f.reponse = func(w http.ResponseWriter, a appelFGP) bool {
		http.Redirect(w, &http.Request{Method: a.Method}, cible.URL+a.Path, http.StatusPermanentRedirect)
		return true
	}
	cfg := cfgTest(t, f)
	_, c := certPilote(t)
	_, err := fgpEcrivain{cfg: cfg}.poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, c.chaine, c.cle)
	var fe *ErreurFGP
	if !errors.As(err, &fe) || fe.Status != http.StatusPermanentRedirect {
		t.Fatalf("erreur %v, 308 attendu", err)
	}
	if ailleurs != 0 {
		t.Error("redirection suivie")
	}
}

func TestPoserErreurs(t *testing.T) {
	e, c := certPilote(t)
	cas := []struct {
		nom, attendu string
		rep          func(w http.ResponseWriter, a appelFGP) bool
	}{
		{"refus du proxy", "FGP refuse PATCH", func(w http.ResponseWriter, a appelFGP) bool {
			w.Header().Set("X-FGP-Source", "proxy")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(a.Body)
			return true
		}},
		{"refus de Scalingo", "Scalingo répond 422", func(w http.ResponseWriter, a appelFGP) bool {
			w.Header().Set("X-FGP-Source", "upstream")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write(a.Body)
			return true
		}},
		{"réponse illisible", "réponse illisible", func(w http.ResponseWriter, a appelFGP) bool {
			_, _ = w.Write(append([]byte("{"), a.Body...))
			return true
		}},
		{"réponse sans domaine", "réponse illisible", func(w http.ResponseWriter, a appelFGP) bool {
			_, _ = w.Write([]byte(`{"errors": {}}`))
			return true
		}},
		{"réponse trop grosse", "plus de", func(w http.ResponseWriter, a appelFGP) bool {
			_, _ = w.Write([]byte(strings.Repeat(" ", maxReponse+1)))
			return true
		}},
	}
	for _, k := range cas {
		t.Run(k.nom, func(t *testing.T) {
			f := demarrerFGP(t)
			f.reponse = k.rep
			_, err := fgpEcrivain{cfg: cfgTest(t, f)}.poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, c.chaine, c.cle)
			if err == nil || !strings.Contains(err.Error(), k.attendu) {
				t.Fatalf("erreur %v, %q attendu", err, k.attendu)
			}
			sansSecret(t, k.nom, []string{err.Error()}, append(secrets(e.cle), testCleFGP, testBlob))
		})
	}
}

func TestPoserInjoignable(t *testing.T) {
	e, c := certPilote(t)
	f := demarrerFGP(t)
	cfg := cfgTest(t, f)
	f.srv.Close()
	_, err := fgpEcrivain{cfg: cfg}.poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, c.chaine, c.cle)
	if !errors.Is(err, ErrInjoignable) {
		t.Fatalf("erreur %v", err)
	}
	sansSecret(t, "injoignable", []string{err.Error()}, append(secrets(e.cle), testCleFGP, testBlob))
}

// Le client n'appelle que PATCH /v1/apps/<app>/domains/<id> : un id ou une app
// hors motif ne part jamais, même avec un blob qui l'autoriserait.
func TestPoserRouteRefusee(t *testing.T) {
	_, c := certPilote(t)
	f := demarrerFGP(t)
	cfg := cfgTest(t, f)
	for _, k := range []struct{ app, id string }{
		{"waf-pilote", "../variables"},
		{"waf-pilote", "a/b"},
		{"waf-pilote", "%2e%2e"},
		{"waf-pilote", "x?y=1"},
		{"waf-pilote", ""},
		{"waf-pilote", strings.Repeat("a", 101)},
		{"../waf-pilote", idPilote},
		{"Waf-Pilote", idPilote},
	} {
		cfg.Ecriture["osc-fr1"][k.app] = testBlob
		if _, err := (fgpEcrivain{cfg: cfg}).poser(context.Background(), "osc-fr1", k.app, k.id, c.chaine, c.cle); err == nil || !strings.Contains(err.Error(), "hors de la route") {
			t.Errorf("%s / %s : %v", k.app, k.id, err)
		}
	}
	if n := len(f.liste()); n != 0 {
		t.Errorf("%d appel(s) parti(s)", n)
	}
}

func TestPoserSansBlob(t *testing.T) {
	_, c := certPilote(t)
	f := demarrerFGP(t)
	cfg := cfgTest(t, f)
	for _, k := range []struct{ region, app string }{{"osc-secnum-fr1", "waf-pilote"}, {"osc-fr1", "autre-app"}} {
		if _, err := (fgpEcrivain{cfg: cfg}).poser(context.Background(), k.region, k.app, idPilote, c.chaine, c.cle); !errors.Is(err, ErrSansBlob) {
			t.Errorf("%s/%s : %v", k.region, k.app, err)
		}
	}
	if _, err := (fgpEcrivain{cfg: cfg}).poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, []byte("x"), c.cle); err == nil {
		t.Error("chaîne hors PEM envoyée")
	}
	if _, err := (fgpEcrivain{cfg: cfg}).poser(context.Background(), "osc-fr1", "waf-pilote", idPilote, c.chaine, nil); err == nil {
		t.Error("clé absente envoyée")
	}
	if n := len(f.liste()); n != 0 {
		t.Errorf("%d appel(s) parti(s)", n)
	}
}

func TestValidite(t *testing.T) {
	var d struct {
		A, B, C, D Validite
	}
	if err := json.Unmarshal([]byte(`{"A": null, "B": "", "C": "2027-02-11T19:57:21.000+02:00"}`), &d); err != nil {
		t.Fatal(err)
	}
	if !d.A.IsZero() || !d.B.IsZero() || !d.D.IsZero() {
		t.Error("null, vide ou absent : validité non nulle")
	}
	if !d.C.Equal(time.Date(2027, 2, 11, 17, 57, 21, 0, time.UTC)) {
		t.Errorf("validité %v", d.C)
	}
	if err := json.Unmarshal([]byte(`{"A": "demain"}`), &d); err == nil {
		t.Error("validité illisible acceptée")
	}
}
