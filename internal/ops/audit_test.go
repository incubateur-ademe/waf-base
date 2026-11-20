package ops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/provision"
)

const secretValue = "valeur-de-variable-qui-ne-doit-jamais-sortir"

func ev(id, typ string, at time.Time, data string) string {
	return fmt.Sprintf(`{"id":%q,"type":%q,"created_at":%q,"app_name":"waf-pilote","user":{"email":"x@example.org"},"type_data":%s}`,
		id, typ, at.UTC().Format(time.RFC3339Nano), data)
}

func TestFGPEvents(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	pages := map[string]string{
		"1": `{"events":[` + ev("e4", "delete_app_firewall_rule", t0.Add(4*time.Hour), `{"cidr":"1.2.3.4/32","label":"waf\n-1","rule_id":"r"}`) + `,` +
			ev("e3", "new_variable", t0.Add(3*time.Hour), `{"name":"SCALINGO_FORBIDDEN_PAGE_URL","value":"`+secretValue+`"}`) + `],"meta":{"pagination":{"next_page":2}}}`,
		"2": `{"events":[` + ev("e2", "edit_domain", t0.Add(2*time.Hour), `{"hostname":"a.example.org","ssl":true,"old_ssl":false}`) + `,` +
			ev("e1", "new_domain", t0, `{"hostname":"b.example.org"}`) + `],"meta":{"pagination":{"next_page":3}}}`,
	}
	var paths []string
	c := fgpServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get("X-FGP-Key") != testKey || r.Header.Get("X-FGP-Blob") != testBlob || r.URL.Query().Get("per_page") != "100" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, pages[r.URL.Query().Get("page")])
	})
	evs, tronque, err := c.Events(context.Background(), "osc-fr1", "waf-pilote", t0)
	if err != nil || tronque {
		t.Fatalf("%v %v", err, tronque)
	}
	if len(evs) != 3 || evs[0].ID != "e4" || evs[2].ID != "e2" {
		t.Fatalf("événements : %+v (e1, à la date du curseur, exclu)", evs)
	}
	if strings.Join(paths, ",") != "/v1/apps/waf-pilote/events?page=1&per_page=100,/v1/apps/waf-pilote/events?page=2&per_page=100" {
		t.Fatalf("appels : %v", paths)
	}
	if evs[0].Detail != "1.2.3.4/32 (waf?-1)" {
		t.Fatalf("détail non nettoyé : %q", evs[0].Detail)
	}
	if b, _ := json.Marshal(evs); strings.Contains(string(b), secretValue) {
		t.Fatalf("valeur de variable copiée : %s", b)
	}
	if len(evs[1].Noms) != 1 || evs[1].Noms[0] != forbiddenPage {
		t.Fatalf("noms : %v", evs[1].Noms)
	}

	full := func(page int) string {
		var l []string
		for i := 0; i < 100; i++ {
			l = append(l, ev(fmt.Sprintf("p%d-%d", page, i), "deployment", t0.Add(time.Duration(3000-page*100-i)*time.Minute), `{}`))
		}
		return `{"events":[` + strings.Join(l, ",") + `],"meta":{"pagination":{"next_page":` + fmt.Sprint(page+1) + `}}}`
	}
	n := 0
	c = fgpServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		var p int
		fmt.Sscan(r.URL.Query().Get("page"), &p)
		fmt.Fprint(w, full(p))
	})
	evs, tronque, err = c.Events(context.Background(), "osc-fr1", "waf-pilote", t0.Add(-time.Hour))
	if err != nil || !tronque || n != maxEventPages || len(evs) != maxEventPages*100 {
		t.Fatalf("troncature : %v %v %d appels %d événements", err, tronque, n, len(evs))
	}

	c = fgpServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"meta":{}}`) })
	if _, _, err := c.Events(context.Background(), "osc-fr1", "waf-pilote", t0); err == nil {
		t.Fatal("réponse sans events acceptée")
	}
	if _, _, err := c.Events(context.Background(), "osc-fr1", "../x", t0); err == nil {
		t.Fatal("nom d'app invalide accepté")
	}
}

func TestEventsRoute(t *testing.T) {
	c := fgpServer(t, func(w http.ResponseWriter, r *http.Request) { t.Fatalf("appel inattendu : %s", r.URL) })
	for _, p := range []string{"/v1/apps/x/events", "/v1/apps/x/events?page=1&per_page=100&x=1", "/v1/apps/x/events?page=21&per_page=100", "/v1/apps/x/events?page=0&per_page=100", "/v1/apps/x/variables?page=1&per_page=100"} {
		if err := c.get(context.Background(), "osc-fr1", p, &struct{}{}); err == nil || !strings.Contains(err.Error(), "hors de la liste") {
			t.Fatalf("%s : %v", p, err)
		}
	}
}

func TestNomsVariables(t *testing.T) {
	var v any
	_ = json.Unmarshal([]byte(`{"new_vars":[{"name":"A","value":"`+secretValue+`"}],"updated_vars":[{"name":"B","value":{"name":"`+secretValue+`"}}],"deleted_vars":[{"name":"C"}]}`), &v)
	got := nomsVariables(v, 0)
	if strings.Contains(strings.Join(got, ","), secretValue) || len(got) != 3 {
		t.Fatalf("noms : %v", got)
	}
}

func TestClasser(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 54, 14, 0, time.UTC)
	cases := []struct {
		e     Evenement
		ecart bool
		msg   string
	}{
		{Evenement{Type: "new_app_firewall_rule", A: at, Detail: "1.2.3.4/32 (x)"}, true, "règle du firewall ajoutée 1.2.3.4/32 (x) le 2026-11-20T09:54:14Z"},
		{Evenement{Type: "delete_app_firewall_rule", A: at, Detail: "1.2.3.4/32"}, true, "règle du firewall retirée"},
		{Evenement{Type: "edit_app_firewall_rule", A: at}, true, "modifiée"},
		{Evenement{Type: "new_domain", A: at, Detail: "a.example.org"}, true, "domaine a.example.org ajouté"},
		{Evenement{Type: "delete_domain", A: at, Detail: "a.example.org"}, true, "retiré"},
		{Evenement{Type: "edit_domain", A: at, Detail: "a.example.org"}, false, "modifié"},
		{Evenement{Type: "new_variable", A: at, Noms: []string{"scalingo_forbidden_page_url"}}, true, forbiddenPage + " posée"},
		{Evenement{Type: "edit_variables", A: at, Noms: []string{"X", forbiddenPage}}, true, "posée ou modifiée"},
		{Evenement{Type: "delete_variable", A: at, Noms: []string{forbiddenPage}}, false, "retirée"},
		{Evenement{Type: "new_variable", A: at, Noms: []string{"DATABASE_URL"}}, false, ""},
		{Evenement{Type: "deployment", A: at}, false, ""},
	}
	for _, c := range cases {
		ecart, msg := classer(c.e)
		if ecart != c.ecart || (c.msg == "" && msg != "") || !strings.Contains(msg, c.msg) {
			t.Fatalf("%s : %v %q", c.e.Type, ecart, msg)
		}
	}
}

type fakeOrigine struct {
	ecarts     []string
	incertains int
	calls      []string
}

func (f *fakeOrigine) Sonder(_ context.Context, app, region string, hosts []string) ([]string, []string, int) {
	f.calls = append(f.calls, app+" "+region+" "+strings.Join(hosts, ","))
	return f.ecarts, nil, f.incertains
}

func TestAudit(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cfg := testCfg(t)
	d, s := pilotDeps(t, ipPP+"/32")
	o := &fakeOrigine{}
	d.Origine, d.Now = o, func() time.Time { return now }
	s.events = map[string][]Evenement{"waf-pilote": {
		{Type: "delete_app_firewall_rule", A: now.Add(-10 * time.Minute), Detail: "78.232.54.148/32 (waf-1)"},
		{Type: "edit_domain", A: now.Add(-20 * time.Minute), Detail: "waf-pilote.incubateur.ademe.dev"},
		{Type: "deployment", A: now.Add(-30 * time.Minute)},
		{Type: "new_domain", A: now.Add(-3 * time.Hour), Detail: "vieux.example.org"},
	}}

	r, cur, err := Audit(context.Background(), cfg, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Apps != 1 || len(r.Ecarts) != 1 || !strings.Contains(r.Ecarts[0], "waf-pilote : waf-pilote (osc-fr1) : règle du firewall retirée 78.232.54.148/32 (waf-1)") {
		t.Fatalf("écarts : %v (nouveau domaine d'il y a 3 h hors des 2 h relues sans curseur)", r.Ecarts)
	}
	notes := strings.Join(r.Notes, "\n")
	for _, w := range []string{"sans curseur, relue depuis 2026-11-20T10:00:00Z", "domaine waf-pilote.incubateur.ademe.dev modifié", "1 autre(s) événement(s)"} {
		if !strings.Contains(notes, w) {
			t.Fatalf("note %q absente : %v", w, r.Notes)
		}
	}
	if got := cur["osc-fr1/waf-pilote"]; !got.Equal(now.Add(-10 * time.Minute)) {
		t.Fatalf("curseur : %v", cur)
	}
	if strings.Join(o.calls, ";") != "waf-pilote osc-fr1 waf-pilote.incubateur.ademe.dev" {
		t.Fatalf("sondes : %v", o.calls)
	}

	// Passage suivant : rien de neuf depuis le curseur, l'écart disparaît.
	r, cur2, err := Audit(context.Background(), cfg, d, cur)
	if err != nil || len(r.Ecarts) != 0 || !cur2["osc-fr1/waf-pilote"].Equal(cur["osc-fr1/waf-pilote"]) {
		t.Fatalf("second passage : %v %v %v", r.Ecarts, cur2, err)
	}

	// Sonde en écart, Activity en erreur : le curseur ne bouge pas.
	o.ecarts = []string{"origine https://waf-pilote.osc-fr1.scalingo.io/ : HTTP 200 au lieu du 403 du firewall"}
	s.err["waf-pilote"] = &FGPError{Path: "/v1/apps/waf-pilote/events?page=1&per_page=100", Status: 403, Source: "proxy"}
	old := map[string]time.Time{"osc-fr1/waf-pilote": now.Add(-time.Hour), "osc-fr1/partie": now.Add(-40 * 24 * time.Hour), "osc-fr1/recente": now.Add(-time.Hour)}
	r, cur3, err := Audit(context.Background(), cfg, d, old)
	if err != nil || len(r.Ecarts) != 2 || !strings.Contains(r.Ecarts[0], "Activity de waf-pilote (osc-fr1) : FGP refuse") || !strings.Contains(r.Ecarts[1], "HTTP 200") {
		t.Fatalf("écarts : %v %v", r.Ecarts, err)
	}
	if !cur3["osc-fr1/waf-pilote"].Equal(old["osc-fr1/waf-pilote"]) || len(cur3) != 1 {
		t.Fatalf("curseurs : %v (waf-pilote inchangé, apps hors périmètre oubliées)", cur3)
	}

	// Cible illisible : tous les curseurs restent, même vieux d'un mois.
	team := d.Coolify
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "LOCK_WAF_PILOTE", "x", false)}}
	r, cur4, err := Audit(context.Background(), cfg, d, old)
	if err != nil || len(cur4) != 3 || len(r.Ecarts) != 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "UPSTREAM_WAF_PILOTE absente") {
		t.Fatalf("cible illisible : %v %v %v (l'écart d'UPSTREAM est porté par le contrôle, ici une note)", cur4, r.Ecarts, err)
	}
	d.Coolify = team

	// Sans verrou : pas de sonde.
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "UPSTREAM_WAF_PILOTE", "https://waf-pilote.osc-fr1.scalingo.io", false)}}
	delete(s.err, "waf-pilote")
	o.calls = nil
	r, _, _ = Audit(context.Background(), cfg, d, cur)
	if len(o.calls) != 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "sans LOCK_WAF_PILOTE, origine non sondée") {
		t.Fatalf("sonde sans verrou : %v %v", o.calls, r.Notes)
	}
}

const pageRefus = `<!DOCTYPE html><html><head><title>Access denied - Scalingo</title></head><body>403</body></html>`

var sondeNoms = []string{"waf-pilote.osc-fr1.scalingo.io", "autre.osc-fr1.scalingo.io", "waf-pilote.incubateur.ademe.dev"}

func sondeServer(t *testing.T, h http.HandlerFunc) (Sonde, *[]string) {
	t.Helper()
	p := newPKI(t)
	return sondeServerCerts(t, h, p, func(*tls.ClientHelloInfo) tls.Certificate {
		return p.leafNoms(t, time.Now().Add(60*24*time.Hour), sondeNoms...)
	})
}

func sondeServerCerts(t *testing.T, h http.HandlerFunc, p pki, cert func(*tls.ClientHelloInfo) tls.Certificate) (Sonde, *[]string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	// Sans SNI, Go sert Certificates[0] sans appeler GetCertificate : le
	// certificat choisi pour un SNI vide doit y être, pas celui d'httptest.
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert(&tls.ClientHelloInfo{})}, GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := cert(hi)
		return &c, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	var dials []string
	return Sonde{
		Resolve: func(_ context.Context, host string) ([]string, error) {
			if host != "waf-pilote.osc-fr1.scalingo.io" {
				return nil, errors.New("inconnu")
			}
			return []string{"192.0.2.10"}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials = append(dials, addr)
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		TLS: &tls.Config{RootCAs: p.roots},
	}, &dials
}

func TestSonde(t *testing.T) {
	var seen []string
	s, dials := sondeServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.Host+" "+r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, pageRefus)
	})
	ecarts, notes, _ := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
	if len(ecarts) != 0 || len(notes) != 0 {
		t.Fatalf("%v %v", ecarts, notes)
	}
	if len(seen) != 3 || seen[0] != "GET waf-pilote.osc-fr1.scalingo.io /" || !strings.HasPrefix(seen[1], "POST waf-pilote.osc-fr1.scalingo.io /sonde-waf-ops-") ||
		seen[2] != "GET waf-pilote.incubateur.ademe.dev /" {
		t.Fatalf("appels : %v", seen)
	}
	if (*dials)[0] != "waf-pilote.osc-fr1.scalingo.io:443" || (*dials)[2] != "192.0.2.10:443" {
		t.Fatalf("connexions : %v", *dials)
	}

	cases := []struct {
		nom string
		h   http.HandlerFunc
		msg string
	}{
		{"origine ouverte", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "app") }, "HTTP 200 au lieu du 403"},
		{"redirection non suivie", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://ailleurs.example.org/", 302)
		}, "HTTP 302"},
		{"page 403 personnalisée", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(403)
			fmt.Fprint(w, "<title>Interdit</title>")
		}, "403 sans la page du routeur"},
		{"403 en JSON", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			fmt.Fprint(w, pageRefus)
		}, "403 sans la page du routeur"},
	}
	for _, c := range cases {
		s, _ := sondeServer(t, c.h)
		ecarts, _, _ := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
		if len(ecarts) != 3 || !strings.Contains(ecarts[0], c.msg) || !strings.Contains(ecarts[2], "host waf-pilote.incubateur.ademe.dev envoyé au routeur 192.0.2.10") {
			t.Fatalf("%s : %v", c.nom, ecarts)
		}
	}

	s, _ = sondeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, pageRefus)
	})
	ecarts, _, _ = s.Sonder(context.Background(), "autre", "osc-fr1", []string{"x.example.org"})
	if len(ecarts) != 1 || !strings.Contains(ecarts[0], "IP du routeur de autre.osc-fr1.scalingo.io introuvable") {
		t.Fatalf("routeur introuvable : %v", ecarts)
	}

	// Sans réglage de test, le certificat de *.scalingo.io est vérifié ; à
	// l'IP du routeur, seule la signature du 403 compte.
	if c := (Sonde{}).client("", ""); c.Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("la sonde de production ne vérifie pas le certificat")
	}
	if tc := (Sonde{}).client("192.0.2.10", "waf-pilote.osc-fr1.scalingo.io").Transport.(*http.Transport).TLSClientConfig; tc.ServerName != "waf-pilote.osc-fr1.scalingo.io" || tc.InsecureSkipVerify || tc.VerifyConnection != nil {
		t.Fatalf("sonde à l'IP du routeur : %+v", tc)
	}
	s.TLS = nil
	ecarts, _, _ = s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
	if len(ecarts) != 3 || !strings.Contains(ecarts[0], "certificat refusé") || !strings.Contains(ecarts[2], "certificat refusé") {
		t.Fatalf("autorité de test acceptée sans réglage : %v", ecarts)
	}
}

type horloge struct{ t time.Time }

func (h *horloge) now() time.Time { return h.t }

func TestRunnerTaches(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32")
	h := &horloge{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	d.Now = h.now
	p := &fakePulse{}
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	runs := 0
	var vus []map[string]time.Time
	ecarts := []string{"waf-pilote : règle du firewall retirée"}
	var terr error
	tache := Tache{Nom: "audit", Periode: time.Hour, Delai: time.Minute, Run: func(ctx context.Context, c map[string]time.Time) (Rapport, map[string]time.Time, error) {
		runs++
		vus = append(vus, c)
		if terr != nil {
			return Rapport{Apps: 1, Ecarts: ecarts}, nil, terr
		}
		return Rapport{Apps: 1, Ecarts: ecarts}, map[string]time.Time{"osc-fr1/waf-pilote": h.t}, nil
	}}
	o := &Runner{Cfg: cfg, Deps: d, Pulse: p, Logf: logf, Taches: []Tache{tache}}

	o.Passage(context.Background())
	if runs != 1 || p.bodies[0] != "waf-ops-ko: audit : waf-pilote : règle du firewall retirée" {
		t.Fatalf("premier passage : %d %v", runs, p.bodies)
	}
	h.t = h.t.Add(5 * time.Minute)
	o.Passage(context.Background())
	if runs != 1 || p.bodies[1] != p.bodies[0] {
		t.Fatalf("l'écart de l'audit doit rester dans le pulse jusqu'à l'audit suivant : %d %v", runs, p.bodies)
	}

	// Redémarrage : l'état relu garde le rythme et les curseurs.
	o = &Runner{Cfg: cfg, Deps: d, Pulse: p, Logf: logf, Taches: []Tache{tache}}
	h.t = h.t.Add(50 * time.Minute)
	o.Passage(context.Background())
	if runs != 1 || !strings.HasPrefix(p.bodies[2], "waf-ops-ko: audit") {
		t.Fatalf("audit relancé après redémarrage avant sa période : %d %v", runs, p.bodies)
	}
	h.t = h.t.Add(5 * time.Minute)
	ecarts = nil
	o.Passage(context.Background())
	if runs != 2 || p.bodies[3] != PulseOK || !vus[1]["osc-fr1/waf-pilote"].Equal(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("audit après une heure : %d %v %v", runs, p.bodies, vus)
	}

	// Échec : KO, curseurs gardés, relance au bout de 15 minutes.
	h.t = h.t.Add(time.Hour)
	terr = errors.New("variables d'équipe Coolify : HTTP 500")
	o.Passage(context.Background())
	if runs != 3 || p.bodies[4] != "waf-ops-ko: audit en échec : variables d'équipe Coolify : HTTP 500" {
		t.Fatalf("échec : %d %v", runs, p.bodies)
	}
	e, err := LireEtat(cfg.State)
	if err != nil || !e.Taches["audit"].Curseurs["osc-fr1/waf-pilote"].Equal(time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("curseurs après échec : %+v %v", e.Taches["audit"], err)
	}
	if e.Taches["audit"].Erreur == "" {
		t.Fatalf("erreur non gardée : %+v", e.Taches["audit"])
	}
	h.t = h.t.Add(10 * time.Minute)
	o.Passage(context.Background())
	if runs != 3 {
		t.Fatal("relance avant 15 minutes")
	}
	h.t = h.t.Add(5 * time.Minute)
	terr = nil
	o.Passage(context.Background())
	if runs != 4 || p.bodies[6] != PulseOK {
		t.Fatalf("relance : %d %v", runs, p.bodies)
	}

	// Arrêt pendant la tâche : ni pulse ni état.
	before, _ := os.ReadFile(filepath.Join(cfg.State, etatFile))
	ctx, cancel := context.WithCancel(context.Background())
	tache.Run = func(context.Context, map[string]time.Time) (Rapport, map[string]time.Time, error) {
		cancel()
		return Rapport{Ecarts: []string{"faux écart d'arrêt"}}, nil, context.Canceled
	}
	o.Taches = []Tache{tache}
	h.t = h.t.Add(2 * time.Hour)
	n := len(p.bodies)
	o.Passage(ctx)
	after, _ := os.ReadFile(filepath.Join(cfg.State, etatFile))
	if len(p.bodies) != n || string(before) != string(after) || strings.Contains(strings.Join(logs, "\n"), "faux écart") {
		t.Fatalf("passage coupé pendant la tâche : %v", p.bodies[n:])
	}

	// Délai dépassé : erreur lisible, pas l'erreur brute du contexte.
	tache.Delai = 10 * time.Millisecond
	tache.Run = func(ctx context.Context, c map[string]time.Time) (Rapport, map[string]time.Time, error) {
		<-ctx.Done()
		return Rapport{}, c, ctx.Err()
	}
	o.Taches = []Tache{tache}
	o.Passage(context.Background())
	if last := p.bodies[len(p.bodies)-1]; last != "waf-ops-ko: audit en échec : délai de 10ms dépassé : context deadline exceeded" {
		t.Fatalf("délai : %q", last)
	}
}

func TestEtatIllisible(t *testing.T) {
	cfg := testCfg(t)
	if err := os.MkdirAll(cfg.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.State, etatFile), []byte("{pas du json "+secretValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LireEtat(cfg.State); err == nil || strings.Contains(err.Error(), secretValue) {
		t.Fatalf("état illisible : %v", err)
	}
	d, _ := pilotDeps(t, ipPP+"/32")
	var logs []string
	o := &Runner{Cfg: cfg, Deps: d, Pulse: &fakePulse{}, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	o.Passage(context.Background())
	if !strings.Contains(strings.Join(logs, "\n"), "état illisible, repris à vide") {
		t.Fatalf("logs : %v", logs)
	}
	if e, err := LireEtat(cfg.State); err != nil || e.Controle.Apps != 1 {
		t.Fatalf("état réécrit : %+v %v", e, err)
	}
}

func TestMainAudit(t *testing.T) {
	var out, errw bytes.Buffer
	e := fullEnv()
	delete(e, "WAF_OPS_FGP")
	if err := Main(context.Background(), []string{"audit"}, env(e), &out, &errw); err == nil || !strings.Contains(err.Error(), "WAF_OPS_FGP") {
		t.Fatalf("audit sans blob : %v", err)
	}
}

func TestAuditCurseurDesordre(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, s := pilotDeps(t, ipPP+"/32")
	d.Origine, d.Now = &fakeOrigine{}, func() time.Time { return now }
	s.events = map[string][]Evenement{"waf-pilote": {
		{Type: "deployment", A: now.Add(-30 * time.Minute)},
		{Type: "deployment", A: now.Add(-10 * time.Minute)},
		{Type: "deployment", A: now.Add(-20 * time.Minute)},
	}}
	_, cur, err := Audit(context.Background(), testCfg(t), d, nil)
	if err != nil || !cur["osc-fr1/waf-pilote"].Equal(now.Add(-10*time.Minute)) {
		t.Fatalf("curseur sur des événements dans le désordre : %v %v", cur, err)
	}
}

func TestAuditUpstreamSansHost(t *testing.T) {
	cfg := testCfg(t)
	inv := strings.Replace(testInventory, "    hosts: [waf-pilote.incubateur.ademe.dev]\n", "    hosts: [waf-pilote.incubateur.ademe.dev]\n    host_header: upstream\n", 1)
	if inv == testInventory {
		t.Fatal("inventaire de test inchangé")
	}
	if err := os.WriteFile(cfg.Inventaire, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ := pilotDeps(t, ipPP+"/32")
	o := &fakeOrigine{}
	d.Origine = o
	if _, _, err := Audit(context.Background(), cfg, d, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.calls, ";") != "waf-pilote osc-fr1 " {
		t.Fatalf("host d'une app upstream envoyé au routeur : %v", o.calls)
	}
}

func TestTacheHorlogeReculee(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tache := Tache{Periode: time.Hour}
	if !tache.due(EtatTache{A: now.Add(3 * time.Hour)}, true, now) {
		t.Fatal("tâche datée dans le futur jamais relancée")
	}
	if tache.due(EtatTache{A: now.Add(-time.Minute)}, true, now) {
		t.Fatal("tâche relancée avant sa période")
	}
}

func TestAuditTronque(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, s := pilotDeps(t, ipPP+"/32")
	d.Origine, d.Now = &fakeOrigine{}, func() time.Time { return now }
	s.events = map[string][]Evenement{"waf-pilote": {
		{Type: "deployment", A: now.Add(-time.Minute)},
		{Type: "deployment", A: now.Add(-50 * time.Minute)},
	}}
	s.tronque = map[string]bool{"waf-pilote": true}
	r, cur, err := Audit(context.Background(), testCfg(t), d, map[string]time.Time{"osc-fr1/waf-pilote": now.Add(-3 * time.Hour)})
	if err != nil || len(r.Ecarts) != 1 || !strings.Contains(r.Ecarts[0], "plus de 2 événements, fenêtre du 2026-11-20T09:00:00Z au 2026-11-20T11:10:00Z non lue, à relire dans le dashboard Scalingo") {
		t.Fatalf("troncature : %v %v", r.Ecarts, err)
	}
	if !cur["osc-fr1/waf-pilote"].Equal(now.Add(-time.Minute)) {
		t.Fatalf("curseur : %v", cur)
	}
}

type coupeOrigine struct{ cancel func() }

func (c coupeOrigine) Sonder(context.Context, string, string, []string) ([]string, []string, int) {
	c.cancel()
	return []string{"origine : sans réponse : délai dépassé"}, nil, 1
}

func TestAuditCoupe(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, s := pilotDeps(t, ipPP+"/32")
	d.Now = func() time.Time { return now }
	s.events = map[string][]Evenement{"waf-pilote": {{Type: "new_domain", A: now.Add(-time.Minute), Detail: "x.example.org"}}}
	ctx, cancel := context.WithCancel(context.Background())
	d.Origine = coupeOrigine{cancel: cancel}
	old := map[string]time.Time{"osc-fr1/waf-pilote": now.Add(-time.Hour), "osc-fr1/autre": now.Add(-time.Hour)}
	r, cur, err := Audit(ctx, testCfg(t), d, old)
	if err == nil || !strings.Contains(err.Error(), "audit coupé après 0 app(s) sur 1") || !errors.Is(err, context.Canceled) {
		t.Fatalf("erreur : %v", err)
	}
	if len(r.Ecarts) != 0 || r.Apps != 0 {
		t.Fatalf("écarts d'une app coupée gardés : %+v", r)
	}
	if len(cur) != 2 || !cur["osc-fr1/waf-pilote"].Equal(old["osc-fr1/waf-pilote"]) {
		t.Fatalf("curseurs : %v", cur)
	}
}

func TestFGPContexteTermine(t *testing.T) {
	c := fgpServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(50 * time.Millisecond) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := c.FirewallRules(ctx, "osc-fr1", "waf-pilote")
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrFGPInjoignable) {
		t.Fatalf("contexte terminé rendu en FGP injoignable : %v", err)
	}
}

func TestEtatIllisibleAlerte(t *testing.T) {
	cfg := testCfg(t)
	if err := os.MkdirAll(cfg.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.State, etatFile), []byte("{tronqué"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ := pilotDeps(t, ipPP+"/32")
	h := &horloge{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	d.Now = h.now
	p := &fakePulse{}
	o := &Runner{Cfg: cfg, Deps: d, Pulse: p, Logf: func(string, ...any) {}}
	o.Passage(context.Background())
	if !strings.Contains(p.bodies[0], "waf-ops-ko: état illisible au démarrage (etat.json.illisible-20261120T120000Z)") {
		t.Fatalf("pulse : %v", p.bodies)
	}
	if b, err := os.ReadFile(filepath.Join(cfg.State, "etat.json.illisible-20261120T120000Z")); err != nil || string(b) != "{tronqué" {
		t.Fatalf("fichier illisible non gardé : %v", err)
	}
	h.t = h.t.Add(55 * time.Minute)
	o.Passage(context.Background())
	h.t = h.t.Add(5 * time.Minute)
	o.Passage(context.Background())
	if !strings.HasPrefix(p.bodies[1], "waf-ops-ko: état illisible") || p.bodies[2] != PulseOK {
		t.Fatalf("alerte d'état : %v", p.bodies)
	}
}

func TestLogsEcartsGardes(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32")
	h := &horloge{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	d.Now = h.now
	var logs []string
	tache := Tache{Nom: "audit", Periode: time.Hour, Delai: time.Minute, Run: func(context.Context, map[string]time.Time) (Rapport, map[string]time.Time, error) {
		return Rapport{Ecarts: []string{"x"}}, nil, nil
	}}
	o := &Runner{Cfg: cfg, Deps: d, Pulse: &fakePulse{}, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }, Taches: []Tache{tache}}
	o.Passage(context.Background())
	n := len(logs)
	h.t = h.t.Add(5 * time.Minute)
	o.Passage(context.Background())
	if !strings.Contains(strings.Join(logs[n:], "\n"), "audit du 2026-11-20T12:00:00Z : 1 écart(s) gardé(s) dans le pulse") {
		t.Fatalf("logs : %v", logs[n:])
	}
}

func TestAuditInventairePerime(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32")
	d.Origine = &fakeOrigine{}
	if _, err := Controle(context.Background(), cfg, d); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.Inventaire); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(filepath.Join(cfg.State, inventoryCache), old, old); err != nil {
		t.Fatal(err)
	}
	r, _, err := Audit(context.Background(), cfg, d, nil)
	if err != nil || len(r.Ecarts) != 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "inventaire non rafraîchi depuis 24 h") {
		t.Fatalf("écart d'inventaire doublé par l'audit : %v %v", r.Ecarts, err)
	}
}

type fakeCerts struct {
	calls []string
	err   error
}

func (f *fakeCerts) Feuille(_ context.Context, ip, host string) (*x509.Certificate, error) {
	f.calls = append(f.calls, ip+" "+host)
	if f.err != nil {
		return nil, f.err
	}
	return &x509.Certificate{NotAfter: time.Now().Add(60 * 24 * time.Hour)}, nil
}

func TestAuditBranchement(t *testing.T) {
	cfg := testCfg(t)
	d, _ := pilotDeps(t, ipPP+"/32")
	d.Origine = &fakeOrigine{}
	res := fakeResolver{"waf-pilote.incubateur.ademe.dev": {ipPP}, "koyo.example.org": {"192.0.2.9"}}
	certs := &fakeCerts{}
	d.DNS, d.Certs = res, certs
	r, _, err := Audit(context.Background(), cfg, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(certs.calls, ";") != ipPP+" koyo.example.org;"+ipPP+" waf-pilote.incubateur.ademe.dev" {
		t.Fatalf("certificats : %v (brouillon, pas en service, et tacct, en prod, hors champ)", certs.calls)
	}
	if len(r.Ecarts) != 1 || !strings.Contains(r.Ecarts[0], "koyo : DNS : koyo.example.org résout vers 192.0.2.9") ||
		!strings.Contains(strings.Join(r.Notes, "\n"), "WAF_OPS_PROVISION absente") {
		t.Fatalf("rapport : %v %v", r.Ecarts, r.Notes)
	}

	// Plan branché, et contrôle sans réponse : écarts gardés, audit en échec.
	cfg.Provision = &Provision{Project: "p", GithubApp: "g", VMs: map[string]ProvisionVM{"preprod": {Server: "s", Destination: "d"}}}
	d.Provision = fakeAPI{}
	computePlan = func(context.Context, provision.API, provision.Config, []inventory.App) (*provision.Plan, error) {
		return nil, &coolify.HTTPError{Method: "GET", Path: "/api/v1/applications", Status: 502}
	}
	t.Cleanup(func() { computePlan = provision.Compute })
	r, _, err = Audit(context.Background(), cfg, d, nil)
	if err == nil || !strings.Contains(err.Error(), "1 contrôle(s) sans réponse, audit relancé dans 15m0s") ||
		!strings.Contains(strings.Join(r.Ecarts, "\n"), "provision : plan de la VM preprod impossible : Coolify GET /api/v1/applications : HTTP 502") {
		t.Fatalf("plan : %v %v", r.Ecarts, err)
	}

	// Coupure pendant les DNS : l'app en cours est nommée, ses écarts écartés.
	ctx, cancel := context.WithCancel(context.Background())
	d.DNS = coupeResolver{cancel: cancel}
	r, _, err = Audit(ctx, cfg, d, nil)
	if err == nil || !strings.Contains(err.Error(), "audit coupé pendant les DNS et certificats de koyo") ||
		strings.Contains(strings.Join(r.Ecarts, ""), "DNS") || !strings.Contains(strings.Join(r.Notes, "\n"), "koyo : audit coupé pendant ses DNS et certificats") {
		t.Fatalf("coupure : %v %v %v", r.Ecarts, r.Notes, err)
	}
}

type coupeResolver struct{ cancel func() }

func (c coupeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	c.cancel()
	return nil, &net.DNSError{Err: "timeout", IsTimeout: true}
}

func TestSondeRouteurSNI(t *testing.T) {
	p := newPKI(t)
	var snis, hosts []string
	refus := func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, pageRefus)
	}
	origine := p.leafNoms(t, time.Now().Add(60*24*time.Hour), "waf-pilote.osc-fr1.scalingo.io")
	s, _ := sondeServerCerts(t, refus, p, func(hi *tls.ClientHelloInfo) tls.Certificate {
		snis = append(snis, hi.ServerName)
		return origine
	})
	snis = nil
	ecarts, _, _ := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev", "10.9.8.7"})
	if len(ecarts) != 0 {
		t.Fatalf("écarts : %v", ecarts)
	}
	if strings.Join(snis, ",") != strings.Repeat("waf-pilote.osc-fr1.scalingo.io,", 3)+"waf-pilote.osc-fr1.scalingo.io" {
		t.Fatalf("SNI : %v (l'origine pour chaque appel, hosts du visiteur compris)", snis)
	}
	if len(hosts) != 4 || hosts[2] != "waf-pilote.incubateur.ademe.dev" || hosts[3] != "10.9.8.7" {
		t.Fatalf("Host : %v", hosts)
	}

	tiers := newPKI(t)
	for nom, cert := range map[string]tls.Certificate{
		"autorité inconnue": tiers.leafNoms(t, time.Now().Add(60*24*time.Hour), "waf-pilote.osc-fr1.scalingo.io"),
		"autre nom":         p.leafNoms(t, time.Now().Add(60*24*time.Hour), "waf-pilote.incubateur.ademe.dev"),
	} {
		s, _ := sondeServerCerts(t, refus, p, func(*tls.ClientHelloInfo) tls.Certificate { return cert })
		ecarts, _, _ := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
		if len(ecarts) != 3 || !strings.Contains(ecarts[2], "host waf-pilote.incubateur.ademe.dev envoyé au routeur 192.0.2.10 : sans réponse : certificat refusé") {
			t.Fatalf("%s : %v", nom, ecarts)
		}
	}
}
