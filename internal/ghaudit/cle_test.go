package ghaudit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func pemOf(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func TestParseKey(t *testing.T) {
	k := testKey(t)
	pkcs1 := pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k))
	der8, _ := x509.MarshalPKCS8PrivateKey(k)
	pkcs8 := pemOf("PRIVATE KEY", der8)
	for name, s := range map[string]string{
		"PKCS#1":        pkcs1,
		"PKCS#8":        pkcs8,
		"une ligne \\n": strings.ReplaceAll(strings.TrimSpace(pkcs1), "\n", `\n`),
		"blancs autour": "\n  " + pkcs1 + "\n\n",
	} {
		got, err := ParseKey(s)
		if err != nil || !got.Equal(k) {
			t.Errorf("%s : %v", name, err)
		}
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	enc := strings.Replace(pkcs1, "-----BEGIN RSA PRIVATE KEY-----\n", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n", 1)
	corrupt := strings.Replace(pkcs1, pkcs1[100:110], "AAAAAAAAAA", 1)
	for name, s := range map[string]string{
		"vide":          "",
		"pas de PEM":    "clé",
		"deux blocs":    pkcs1 + pkcs1,
		"chiffrée":      enc,
		"1024 bits":     pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(small)),
		"EC":            pemOf("PRIVATE KEY", ecDER),
		"type inconnu":  pemOf("EC PRIVATE KEY", ecDER),
		"PKCS#1 abîmée": corrupt,
	} {
		_, err := ParseKey(s)
		if err == nil {
			t.Errorf("%s : clé acceptée", name)
			continue
		}
		if strings.Contains(err.Error(), "MII") || len(err.Error()) > 80 {
			t.Errorf("%s : erreur qui cite la clé : %v", name, err)
		}
	}
}

func TestFromEnv(t *testing.T) {
	pkcs1 := pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(testKey(t)))
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	_, err := FromEnv(env(nil))
	if err == nil || err.Error() != "variables manquantes : WAF_OPS_GITHUB_APP_ID, WAF_OPS_GITHUB_APP_KEY" {
		t.Fatalf("%v", err)
	}
	_, err = FromEnv(env(map[string]string{EnvAppID: "abc", EnvAppKey: pkcs1}))
	if err == nil || !strings.HasPrefix(err.Error(), EnvAppID) {
		t.Fatalf("%v", err)
	}
	_, err = FromEnv(env(map[string]string{EnvAppID: "123456", EnvAppKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIsecret\n-----END RSA PRIVATE KEY-----"}))
	if err == nil || strings.Contains(err.Error(), "MIIsecret") || !strings.HasPrefix(err.Error(), EnvAppKey) {
		t.Fatalf("%v", err)
	}
	c, err := FromEnv(env(map[string]string{EnvAppID: " 123456 ", EnvAppKey: pkcs1}))
	if err != nil || c.AppID != "123456" || c.API != DefaultAPI || c.OpsOrg != DefaultOpsOrg || c.OpsTeam != DefaultOpsTeam {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestJWTAppIDNumerique(t *testing.T) {
	f := newFake(t)
	tok, err := appJWT("123456", testKey(t), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Split(tok, ".")[1]
	if !strings.Contains(decodeB64(t, raw), `"iss":123456`) {
		t.Fatalf("iss numérique attendu : %s", decodeB64(t, raw))
	}
	tok, _ = appJWT(testAppID, testKey(t), f.now)
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if !f.checkJWT(r) {
		t.Fatal("JWT refusé par le faux GitHub")
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	b, err := decodeRawURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConfigRefusee(t *testing.T) {
	f := newFake(t)
	srv, cfg := f.start()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	host := strings.TrimPrefix(srv.URL, "https://")
	for name, mut := range map[string]func(*Config){
		"API http":     func(c *Config) { c.API = "http://" + host },
		"API à chemin": func(c *Config) { c.API = srv.URL + "/x" },
		"API avec id":  func(c *Config) { c.API = "https://u:p@" + host },
		"sans clé":     func(c *Config) { c.Key = nil },
		"clé courte":   func(c *Config) { c.Key = small },
		"AppID":        func(c *Config) { c.AppID = "../x" },
		"équipe":       func(c *Config) { c.OpsTeam = "Sec Ops" },
	} {
		c := cfg
		mut(&c)
		_, _, err := Audit(context.Background(), c, apps(pilote))
		if err == nil || !strings.HasPrefix(err.Error(), "App GitHub : ") {
			t.Errorf("%s : %v", name, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("appels malgré une config refusée : %q", f.calls)
	}
}

func TestRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		a            auth
		q            url.Values
		ok           bool
	}{
		{"GET", "/repos/o/r", authInstallation, nil, true},
		{"GET", "/repos/o/r/branches/release%2Fprod/protection", authInstallation, nil, true},
		{"GET", "/repos/o/r/collaborators", authInstallation, url.Values{"affiliation": {"all"}}, true},
		{"GET", "/repos/o/r/collaborators", authInstallation, url.Values{"permission": {"admin"}}, false},
		{"GET", "/repos/o/r", authApp, nil, false},
		{"GET", "/repos/o/r/installation", authInstallation, nil, false},
		{"POST", "/repos/o/r", authInstallation, nil, false},
		{"PUT", "/repos/o/r/branches/main/protection", authInstallation, nil, false},
		{"DELETE", "/repos/o/r/branches/main/protection", authInstallation, nil, false},
		{"GET", "/repos/o/r/contents/waf", authInstallation, nil, false},
		{"GET", "/repos/o/r/branches/../../user", authInstallation, nil, false},
		{"GET", "/repos/o/r/branches/a/b", authInstallation, nil, false},
		{"GET", "/repos/o/r/git/trees/main", authInstallation, nil, false},
		{"GET", "/user", authInstallation, nil, false},
		{"POST", "/app/installations/7/access_tokens", authApp, nil, true},
		{"POST", "/app/installations/7/access_tokens", authInstallation, nil, false},
	}
	for _, c := range cases {
		err := allowed(c.method, c.path, c.a, c.q)
		if (err == nil) != c.ok {
			t.Errorf("%s %s : %v", c.method, c.path, err)
		}
	}
}

// Une route refusée n'atteint jamais le serveur, une redirection n'est pas
// suivie, une réponse trop longue est refusée, un corps d'erreur n'est pas repris.
func TestClientGardes(t *testing.T) {
	var hits []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/repos/o/redir":
			http.Redirect(w, r, "/repos/o/cible", http.StatusFound)
		case "/repos/o/gros":
			w.Write([]byte(`"` + strings.Repeat("a", maxBody) + `"`))
		case "/repos/o/erreur":
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"` + testToken + `"}`))
		case "/repos/o/illisible":
			w.Write([]byte(`{"token": ` + testToken))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	c := &client{api: srv.URL, http: newHTTPClient(srv.Client())}
	ctx := context.Background()
	var out any
	if err := c.do(ctx, "GET", "/user", nil, authInstallation, testToken, nil, &out); err == nil || len(hits) != 0 {
		t.Fatalf("route hors liste : %v, %q", err, hits)
	}
	err := c.do(ctx, "GET", "/repos/o/redir", nil, authInstallation, testToken, nil, &out)
	if !isStatus(err, http.StatusFound) || strings.Join(hits, ",") != "/repos/o/redir" {
		t.Fatalf("redirection : %v, %q", err, hits)
	}
	if err := c.do(ctx, "GET", "/repos/o/gros", nil, authInstallation, testToken, nil, &out); err == nil || !strings.Contains(err.Error(), "plus de") {
		t.Fatalf("taille : %v", err)
	}
	for _, p := range []string{"/repos/o/erreur", "/repos/o/illisible"} {
		err := c.do(ctx, "GET", p, nil, authInstallation, testToken, nil, &out)
		if err == nil || strings.Contains(err.Error(), testToken) {
			t.Fatalf("%s : %v", p, err)
		}
	}
	if newHTTPClient(nil).Timeout != defaultTimeout {
		t.Fatal("délai par défaut absent")
	}
	slow := &http.Client{Timeout: time.Second}
	if newHTTPClient(slow).Timeout != time.Second || slow.CheckRedirect != nil {
		t.Fatal("client de base modifié")
	}
}

func decodeRawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
