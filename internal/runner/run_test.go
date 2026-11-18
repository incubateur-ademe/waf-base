package runner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

const pageRefusScalingo = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>
    Access denied - Scalingo
  </title>
</head>
<body><h1>Access denied</h1></body>
</html>`

func TestOriginCheck(t *testing.T) {
	cases := []struct {
		nom      string
		platform string
		status   int
		corps    string
		erreur   bool
	}{
		{"refus du firewall Scalingo", "scalingo", 403, pageRefusScalingo, true},
		{"titre en minuscules", "scalingo", 403, "<title>access denied - scalingo</title>", true},
		{"403 de l'app qui cite Scalingo", "scalingo", 403, "<html><title>Forbidden</title><p>Hébergé chez Scalingo</p></html>", false},
		{"403 de l'app sans titre", "scalingo", 403, "forbidden", false},
		{"origine en 200", "scalingo", 200, "ok", false},
		{"origine en 502", "scalingo", 502, "bad gateway", false},
		{"jeton refusé par Koyeb", "koyeb", 403, "forbidden", true},
		{"page Scalingo hors Scalingo", "coolify", 403, pageRefusScalingo, false},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			in := &render.Input{Platform: c.platform, HostHeader: "visitor", Hosts: []string{"site.example.org"}}
			host, err := hostVuParOrigine(in, c.status, c.corps)
			if (err != nil) != c.erreur {
				t.Fatalf("erreur = %v, attendu une erreur : %v", err, c.erreur)
			}
			if host != "site.example.org" {
				t.Fatalf("Host envoyé à l'origine = %q, attendu le host du visiteur", host)
			}
		})
	}
	t.Run("canonical autre que le premier host", func(t *testing.T) {
		in := &render.Input{Platform: "scalingo", HostHeader: "visitor", Hosts: []string{"www.site.example.org", "site.example.org"}, Canonical: "site.example.org"}
		host, err := hostVuParOrigine(in, 200, "ok")
		if err != nil {
			t.Fatal(err)
		}
		if host != "site.example.org" {
			t.Fatalf("Host envoyé à l'origine = %q, attendu le canonique", host)
		}
	})
}

func hostVuParOrigine(in *render.Input, status int, corps string) (string, error) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.WriteHeader(status)
		_, _ = w.Write([]byte(corps))
	}))
	defer srv.Close()
	in.Upstream = srv.URL
	err := originCheck(in, func(string, ...any) {})
	return host, err
}

func TestInputsCanonical(t *testing.T) {
	pol, err := policy.Load("../../policy")
	if err != nil {
		t.Fatal(err)
	}
	p := Paths{Etc: t.TempDir()}
	if err := os.Mkdir(filepath.Join(p.Etc, "tenant"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		nom, valeur, attendu, erreur string
		absente                      bool
	}{
		{nom: "absente", absente: true},
		{nom: "vide, null côté Coolify", valeur: ""},
		{nom: "un des hosts", valeur: "www.tacct.ademe.fr", attendu: "www.tacct.ademe.fr"},
		{nom: "espaces autour", valeur: " tacct.ademe.fr ", attendu: "tacct.ademe.fr"},
		{nom: "hors des hosts", valeur: "autre.ademe.fr", erreur: "WAF_CANONICAL_HOST"},
		{nom: "suffixe d'un host", valeur: "ademe.fr", erreur: "WAF_CANONICAL_HOST"},
	}
	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			for k, v := range map[string]string{
				"WAF_TENANT": "tacct", "WAF_HOSTS": "tacct.ademe.fr,www.tacct.ademe.fr",
				"UPSTREAM": "https://tacct.osc-fr1.scalingo.io", "WAF_PLATFORM": "scalingo", "WAF_HOST_HEADER": "upstream",
				"WAF_CEILINGS": "", "WAF_CRS_PLUGINS": "", "WAF_DETECTION_UNTIL": "", "WAF_FORCE_DETECTION": "",
				"WAF_UNINSPECTED_PATHS": "", "WAF_CANONICAL_HOST": c.valeur,
			} {
				t.Setenv(k, v)
			}
			if c.absente {
				os.Unsetenv("WAF_CANONICAL_HOST")
			}
			in, err := Inputs(p, pol, nil, time.Now())
			if c.erreur != "" {
				if err == nil || !strings.Contains(err.Error(), c.erreur) {
					t.Fatalf("erreur = %v, attendu %q", err, c.erreur)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if in.Canonical != c.attendu {
				t.Fatalf("Canonical = %q, attendu %q", in.Canonical, c.attendu)
			}
		})
	}
}
