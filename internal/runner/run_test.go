package runner

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
			var host string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host = r.Host
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.corps))
			}))
			defer srv.Close()
			in := &render.Input{Upstream: srv.URL, Platform: c.platform, HostHeader: "visitor", Hosts: []string{"site.example.org"}}
			err := originCheck(in, func(string, ...any) {})
			if (err != nil) != c.erreur {
				t.Fatalf("erreur = %v, attendu une erreur : %v", err, c.erreur)
			}
			if host != "site.example.org" {
				t.Fatalf("Host envoyé à l'origine = %q, attendu le host du visiteur", host)
			}
		})
	}
}
