package ops

import (
	"bytes"
	"context"
	"crypto/tls"
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
			l = append(l, ev(fmt.Sprintf("p%d-%d", page, i), "deployment", t0.Add(time.Duration(1000-page*100-i)*time.Minute), `{}`))
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
	for _, p := range []string{"/v1/apps/x/events", "/v1/apps/x/events?page=1&per_page=100&x=1", "/v1/apps/x/events?page=10&per_page=100", "/v1/apps/x/variables?page=1&per_page=100"} {
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
	ecarts []string
	calls  []string
}

func (f *fakeOrigine) Sonder(_ context.Context, app, region string, hosts []string) ([]string, []string) {
	f.calls = append(f.calls, app+" "+region+" "+strings.Join(hosts, ","))
	return f.ecarts, nil
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
	if !cur3["osc-fr1/waf-pilote"].Equal(old["osc-fr1/waf-pilote"]) || len(cur3) != 2 {
		t.Fatalf("curseurs : %v (waf-pilote inchangé, recente gardé, partie oublié)", cur3)
	}

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

func sondeServer(t *testing.T, h http.HandlerFunc) (Sonde, *[]string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
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
		TLS: &tls.Config{InsecureSkipVerify: true},
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
	ecarts, notes := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
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
		ecarts, _ := s.Sonder(context.Background(), "waf-pilote", "osc-fr1", []string{"waf-pilote.incubateur.ademe.dev"})
		if len(ecarts) != 3 || !strings.Contains(ecarts[0], c.msg) || !strings.Contains(ecarts[2], "host waf-pilote.incubateur.ademe.dev envoyé au routeur 192.0.2.10") {
			t.Fatalf("%s : %v", c.nom, ecarts)
		}
	}

	s, _ = sondeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, pageRefus)
	})
	ecarts, _ = s.Sonder(context.Background(), "autre", "osc-fr1", []string{"x.example.org"})
	if len(ecarts) != 1 || !strings.Contains(ecarts[0], "IP du routeur de autre.osc-fr1.scalingo.io introuvable") {
		t.Fatalf("routeur introuvable : %v", ecarts)
	}

	// Sans réglage de test, le certificat est vérifié.
	if c := (Sonde{}).client(""); c.Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("la sonde de production ne vérifie pas le certificat")
	}
	s.TLS = nil
	ecarts, _ = s.Sonder(context.Background(), "waf-pilote", "osc-fr1", nil)
	if len(ecarts) != 2 || !strings.Contains(ecarts[0], "certificat refusé") {
		t.Fatalf("certificat de test accepté sans réglage : %v", ecarts)
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
		return Rapport{Apps: 1, Ecarts: ecarts}, map[string]time.Time{"osc-fr1/waf-pilote": h.t}, terr
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
	if last := p.bodies[len(p.bodies)-1]; last != "waf-ops-ko: audit en échec : délai de 10ms dépassé" {
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
