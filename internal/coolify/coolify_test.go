package coolify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRoutes(t *testing.T) {
	ok := []struct{ m, p string }{
		{"GET", "/api/v1/applications"},
		{"GET", "/api/v1/applications/abc123"},
		{"GET", "/api/v1/applications/abc123/envs"},
		{"GET", "/api/v1/applications/abc123/destinations"},
		{"GET", "/api/v1/destinations/d1"},
		{"GET", "/api/v1/github-apps"},
		{"GET", "/api/v1/team/envs"},
		{"POST", "/api/v1/applications/private-github-app"},
		{"PATCH", "/api/v1/applications/abc123"},
		{"PATCH", "/api/v1/applications/abc123/envs/bulk"},
		{"DELETE", "/api/v1/applications/abc123/envs/env42"},
	}
	for _, r := range ok {
		if !Allowed(r.m, r.p) {
			t.Errorf("%s %s refusée", r.m, r.p)
		}
	}
	ko := []struct{ m, p string }{
		{"DELETE", "/api/v1/applications/abc123"},
		{"POST", "/api/v1/deploy"},
		{"GET", "/api/v1/deploy"},
		{"POST", "/api/v1/applications/abc123/start"},
		{"PATCH", "/api/v1/team/envs/12"},
		{"POST", "/api/v1/team/envs"},
		{"DELETE", "/api/v1/team/envs/12"},
		{"DELETE", "/api/v1/applications/abc123/envs"},
		{"GET", "/api/v1/applications/../servers"},
		{"POST", "/api/v1/servers/s1/envs"},
	}
	for _, r := range ko {
		if Allowed(r.m, r.p) {
			t.Errorf("%s %s acceptée", r.m, r.p)
		}
	}
}

func TestJetonEnEnTeteSeulement(t *testing.T) {
	const token = "1|jeton-de-test-tres-secret"
	var auth, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		query = r.URL.RawQuery
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"refus pour ` + token + `","errors":{"x":["` + strings.Repeat("a", 1000) + `"]}}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	err = c.UpdateApplication(context.Background(), "abc", map[string]any{"x": 1})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 422 {
		t.Fatalf("erreur = %v", err)
	}
	if auth != "Bearer "+token || query != "" {
		t.Fatalf("Authorization = %q, query = %q", auth, query)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("jeton dans l'erreur : %v", err)
	}
	if len(he.Body) > maxErrLen+4 {
		t.Fatalf("corps non tronqué : %d octets", len(he.Body))
	}
}

func erreurHTTP(t *testing.T, token, body string) (*HTTPError, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := New(srv.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	err = c.UpdateApplication(context.Background(), "abc", map[string]any{"x": 1})
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("erreur = %v", err)
	}
	return he, err
}

func TestJetonAChevalDeLaTroncature(t *testing.T) {
	const token = "1|jeton-de-test-tres-secret"
	for _, start := range []int{285, 290, 295, 299} {
		body := strings.Repeat("a", start-1) + "  \n\t " + token + " " + strings.Repeat("b", 500)
		he, err := erreurHTTP(t, token, body)
		if strings.Contains(err.Error(), token[:8]) {
			t.Fatalf("jeton coupé à l'octet %d, préfixe dans l'erreur : %v", start, err)
		}
		if len(he.Body) > maxErrLen+len("…") {
			t.Fatalf("corps non tronqué : %d octets", len(he.Body))
		}
	}
}

func TestTroncatureSurUneRune(t *testing.T) {
	he, _ := erreurHTTP(t, "1|jeton-de-test-tres-secret", strings.Repeat("a", maxErrLen-1)+strings.Repeat("é", 50))
	if !utf8.ValidString(he.Body) {
		t.Fatalf("rune coupée : %q", he.Body[len(he.Body)-8:])
	}
	if !strings.HasSuffix(he.Body, "…") {
		t.Fatalf("troncature non signalée : %q", he.Body)
	}
}

func TestURL(t *testing.T) {
	for _, u := range []string{"ftp://x", "https://x/api", "https://u:p@x", "x"} {
		if _, err := New(u, "t"); err == nil {
			t.Errorf("%s acceptée", u)
		}
	}
	if _, err := New("https://ops.example.org/", ""); err == nil {
		t.Error("jeton vide accepté")
	}
}

func TestStr(t *testing.T) {
	var e struct {
		A Str `json:"a"`
		B Str `json:"b"`
		C Str `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":null,"b":"x"}`), &e); err != nil {
		t.Fatal(err)
	}
	if !e.A.Set || !e.A.Null || !e.B.Set || e.B.Value != "x" || e.C.Set {
		t.Fatalf("%+v", e)
	}
}
