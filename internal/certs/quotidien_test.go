package certs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	vmsTest  = []VM{{Name: "1", Stage: "prod"}, {Name: "preprod", Stage: "preprod"}}
	appPilot = App{Name: "waf-pilote", Stage: "preprod", Hosts: []string{hostPilote}, Scalingo: "waf-pilote", Region: "osc-fr1"}
)

type scenario struct {
	f      *fauxFGP
	cfg    Config
	lec    *fauxLecteur
	cop    fauxCopieur
	pilote emis
	prod   emis
}

func nouveauScenario(t *testing.T) *scenario {
	t.Helper()
	p := lePKI(t)
	s := &scenario{f: demarrerFGP(t)}
	s.cfg = cfgTest(t, s.f)
	s.pilote = p.feuille(t, optsFeuille{cn: hostPilote})
	s.prod = p.feuille(t, optsFeuille{cn: hostPilote, notAfter: maintenant.Add(60 * 24 * time.Hour)})
	s.cop = fauxCopieur{
		contenu: map[string][]byte{
			"preprod": acmeJSON(t, "letsencrypt", entree{main: hostPilote, cert: s.pilote.chaine, key: s.pilote.cle}),
			"1":       acmeJSON(t, "letsencrypt", entree{main: hostPilote, cert: s.prod.chaine, key: s.prod.cle}),
		},
		err: map[string]error{},
	}
	s.lec = &fauxLecteur{doms: map[string][]Domain{
		"osc-fr1/waf-pilote": {
			{ID: idPilote, Name: hostPilote, SSL: true, TLSCert: "/CN=" + hostPilote, Validity: Validite{maintenant.Add(40 * 24 * time.Hour)}},
			{ID: "dom-autre", Name: "autre.example.org", SSL: true, TLSCert: "/CN=autre.example.org", Validity: Validite{maintenant.Add(2 * 24 * time.Hour)}},
		},
	}, err: map[string]error{}}
	return s
}

func (s *scenario) lancer(t *testing.T, apps ...App) ([]string, []string) {
	t.Helper()
	ecarts, notes, err := Quotidien(context.Background(), s.cfg, vmsTest, apps, Deps{Lecteur: s.lec, Now: func() time.Time { return maintenant }, copieur: s.cop})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("écarts %q", ecarts)
	t.Logf("notes %q", notes)
	sansSecret(t, "sorties", append(append([]string{}, ecarts...), notes...), append(secrets(s.pilote.cle, s.prod.cle), testCleFGP, testBlob))
	return ecarts, notes
}

func contient(l []string, sub string) bool {
	for _, s := range l {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestQuotidienPousse(t *testing.T) {
	s := nouveauScenario(t)
	ecarts, notes := s.lancer(t, appPilot)
	if len(ecarts) != 0 {
		t.Errorf("écarts %q", ecarts)
	}
	appels := s.f.liste()
	if len(appels) != 1 || appels[0].Path != "/v1/apps/waf-pilote/domains/"+idPilote {
		t.Fatalf("appels %v", appels)
	}
	var corps struct {
		Domain struct{ TLSCert, TLSKey string } `json:"domain"`
	}
	_ = json.Unmarshal(appels[0].Body, &corps)
	if corps.Domain.TLSCert != string(s.pilote.chaine) || corps.Domain.TLSKey != string(s.pilote.cle) {
		t.Error("certificat poussé autre que celui d'acme.json de preprod")
	}
	if !contient(notes, "waf-pilote : "+hostPilote+" : certificat de preprod poussé sur waf-pilote (osc-fr1), expire le 2027-02-08") {
		t.Errorf("note de poussée absente : %q", notes)
	}
	if contient(notes, "autre.example.org") {
		t.Error("un domaine hors des hosts de l'app apparaît")
	}
	for _, vm := range []string{"1", "preprod"} {
		dir := filepath.Join(s.cfg.State, "acme", vm)
		for _, p := range []string{filepath.Join(s.cfg.State, "acme"), dir} {
			st, err := os.Stat(p)
			if err != nil || st.Mode().Perm() != 0o700 {
				t.Errorf("%s : %v %v", p, err, st.Mode())
			}
		}
		st, err := os.Stat(filepath.Join(dir, "acme-2026-11-20.json"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("copie de %s : %v %v", vm, err, st.Mode())
		}
		b, _ := os.ReadFile(filepath.Join(dir, "acme-2026-11-20.json"))
		if string(b) != string(s.cop.contenu[vm]) {
			t.Errorf("copie de %s différente d'acme.json", vm)
		}
	}
}

func TestQuotidienAJour(t *testing.T) {
	s := nouveauScenario(t)
	s.lec.doms["osc-fr1/waf-pilote"][0].Validity = Validite{s.pilote.leaf.NotAfter.In(time.FixedZone("CET", 3600))}
	ecarts, notes := s.lancer(t, appPilot)
	if len(ecarts) != 0 || len(s.f.liste()) != 0 {
		t.Errorf("écarts %q, %d appel(s)", ecarts, len(s.f.liste()))
	}
	if !contient(notes, "certificat à jour") {
		t.Errorf("notes %q", notes)
	}
	// Même fin de validité, autre sujet : un autre certificat, poussé.
	s.lec.doms["osc-fr1/waf-pilote"][0].TLSCert = "/C=FR/CN=autre.example.org"
	s.lancer(t, appPilot)
	if len(s.f.liste()) != 1 {
		t.Errorf("sujet différent : %d appel(s)", len(s.f.liste()))
	}
}

// TACCT : aucun domaine Scalingo de l'app n'est un de ses hosts.
func TestQuotidienSansDomaine(t *testing.T) {
	s := nouveauScenario(t)
	tacct := App{Name: "tacct", Stage: "prod", Hosts: []string{"tacct.ademe.fr"}, Scalingo: "tacct-prod", Region: "osc-secnum-fr1"}
	s.lec.doms["osc-secnum-fr1/tacct-prod"] = []Domain{{ID: "x", Name: "autre.example.org", SSL: true, Validity: Validite{maintenant.Add(24 * time.Hour)}}}
	ecarts, notes := s.lancer(t, tacct)
	if len(ecarts) != 0 || len(s.f.liste()) != 0 {
		t.Errorf("écarts %q, %d appel(s)", ecarts, len(s.f.liste()))
	}
	if !contient(notes, "tacct : aucun de ses hosts sur tacct-prod (osc-secnum-fr1), rien à pousser") {
		t.Errorf("notes %q", notes)
	}
}

func TestQuotidienExpirations(t *testing.T) {
	s := nouveauScenario(t)
	court := lePKI(t).feuille(t, optsFeuille{cn: hostPilote, notAfter: maintenant.Add(10 * 24 * time.Hour)})
	s.cop.contenu["preprod"] = acmeJSON(t, "letsencrypt", entree{cert: court.chaine, key: court.cle})
	s.lec.doms["osc-fr1/waf-pilote"][0].Validity = Validite{maintenant.Add(5 * 24 * time.Hour)}
	ecarts, _ := s.lancer(t, appPilot)
	if !contient(ecarts, "waf-pilote : certificat de "+hostPilote+" dans acme.json de preprod expire le 2026-11-30") {
		t.Errorf("écarts %q", ecarts)
	}
	if len(s.f.liste()) != 1 {
		t.Errorf("le certificat plus récent n'est pas poussé : %d appel(s)", len(s.f.liste()))
	}
	// Sans blob, le certificat de Scalingo à 5 jours est un écart à part.
	s.cfg.Ecriture = map[string]map[string]string{"osc-fr1": {"x": testBlob}}
	ecarts, _ = s.lancer(t, appPilot)
	for _, want := range []string{
		"waf-pilote : aucun blob FGP d'écriture pour waf-pilote (osc-fr1), certificat non poussé",
		"waf-pilote : certificat de " + hostPilote + " sur waf-pilote (osc-fr1) expire le 2026-11-25",
	} {
		if !contient(ecarts, want) {
			t.Errorf("écart %q absent de %q", want, ecarts)
		}
	}
	if len(s.f.liste()) != 1 || len(ecarts) != 3 {
		t.Errorf("poussée sans blob : %d appel(s), écarts %q", len(s.f.liste()), ecarts)
	}
}

func TestQuotidienPlusRecentSurScalingo(t *testing.T) {
	s := nouveauScenario(t)
	s.lec.doms["osc-fr1/waf-pilote"][0].Validity = Validite{s.pilote.leaf.NotAfter.Add(time.Hour)}
	ecarts, notes := s.lancer(t, appPilot)
	if len(ecarts) != 0 || len(s.f.liste()) != 0 {
		t.Errorf("écarts %q, %d appel(s)", ecarts, len(s.f.liste()))
	}
	if !contient(notes, "après celui d'acme.json, pas de poussée") {
		t.Errorf("notes %q", notes)
	}
	// Plus récent mais sous 21 jours : écart, toujours sans poussée.
	court := lePKI(t).feuille(t, optsFeuille{cn: hostPilote, notAfter: maintenant.Add(10 * 24 * time.Hour)})
	s.cop.contenu["preprod"] = acmeJSON(t, "letsencrypt", entree{cert: court.chaine, key: court.cle})
	s.lec.doms["osc-fr1/waf-pilote"][0].Validity = Validite{maintenant.Add(15 * 24 * time.Hour)}
	ecarts, _ = s.lancer(t, appPilot)
	if !contient(ecarts, "certificat de "+hostPilote+" sur waf-pilote (osc-fr1) expire le 2026-12-05") || len(s.f.liste()) != 0 {
		t.Errorf("écarts %q, %d appel(s)", ecarts, len(s.f.liste()))
	}
}

const ecartScalingo5j = "waf-pilote : certificat de " + hostPilote + " sur waf-pilote (osc-fr1) expire le 2026-11-25"

func scalingoA5Jours(s *scenario) {
	s.lec.doms["osc-fr1/waf-pilote"][0].Validity = Validite{maintenant.Add(5 * 24 * time.Hour)}
}

// acme.json lu, mais sans certificat utilisable : un écart, pas une note de
// copie manquante.
func TestQuotidienAcmeSansCertificat(t *testing.T) {
	for nom, raw := range map[string][]byte{
		"null":   []byte(`{"letsencrypt": {"Account": {}, "Certificates": null}}`),
		"base64": acmeJSON(t, "letsencrypt", entree{main: hostPilote, certB64: "%%%", keyB64: "%%%"}),
	} {
		t.Run(nom, func(t *testing.T) {
			s := nouveauScenario(t)
			s.cop.contenu["preprod"] = raw
			s.lec.doms["osc-fr1/waf-pilote"][0].SSL = false
			ecarts, notes := s.lancer(t, appPilot)
			if !contient(ecarts, "waf-pilote : aucun certificat pour "+hostPilote+" dans acme.json du stage preprod") {
				t.Errorf("écarts %q", ecarts)
			}
			if contient(notes, "pas de copie") {
				t.Errorf("notes %q", notes)
			}
		})
	}
}

func TestQuotidienStages(t *testing.T) {
	s := nouveauScenario(t)
	prod := appPilot
	prod.Name, prod.Stage = "pilote-prod", "prod"
	s.lancer(t, prod)
	appels := s.f.liste()
	if len(appels) != 1 {
		t.Fatalf("%d appel(s)", len(appels))
	}
	if !strings.Contains(string(appels[0].Body), jsonChaine(s.prod.chaine)) {
		t.Error("une app de prod reçoit le certificat de la VM de preprod")
	}
	sansStage := appPilot
	sansStage.Stage = "inconnu"
	ecarts, _ := s.lancer(t, sansStage)
	if !contient(ecarts, "aucune VM du stage inconnu") {
		t.Errorf("écarts %q", ecarts)
	}
}

func jsonChaine(b []byte) string {
	j, _ := json.Marshal(string(b))
	return strings.Trim(string(j), `"`)
}

func TestQuotidienCopieEchouee(t *testing.T) {
	s := nouveauScenario(t)
	s.cop.err["preprod"] = ErrNonForcee
	scalingoA5Jours(s)
	ecarts, notes := s.lancer(t, appPilot)
	if !contient(ecarts, "vm preprod : acme.json non copié : clé sans commande forcée") || !contient(ecarts, ecartScalingo5j) {
		t.Errorf("écarts %q", ecarts)
	}
	if !contient(notes, "pas de copie d'acme.json de preprod ce jour, poussée sautée") {
		t.Errorf("notes %q", notes)
	}
	if len(s.f.liste()) != 0 {
		t.Error("poussée sans copie fraîche")
	}
	if _, err := os.Stat(filepath.Join(s.cfg.State, "acme", "preprod")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dossier de copie créé sans copie : %v", err)
	}
}

func TestQuotidienAcmeIllisible(t *testing.T) {
	s := nouveauScenario(t)
	s.cop.contenu["preprod"] = []byte(`{"letsencrypt": {"Certificates": [{"key": "` + string(s.pilote.cle) + `"`)
	ecarts, _ := s.lancer(t, appPilot)
	if !contient(ecarts, "vm preprod : acme.json : JSON illisible") {
		t.Errorf("écarts %q", ecarts)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.State, "acme", "preprod")); !errors.Is(err, os.ErrNotExist) {
		t.Error("un acme.json illisible remplace une copie")
	}
}

func TestQuotidienChaineRefusee(t *testing.T) {
	s := nouveauScenario(t)
	e := nouvellePKI(t, "Staging").feuille(t, optsFeuille{cn: hostPilote})
	s.cop.contenu["preprod"] = acmeJSON(t, "letsencrypt", entree{cert: e.chaine, key: e.cle})
	scalingoA5Jours(s)
	ecarts, _ := s.lancer(t, appPilot)
	if !contient(ecarts, ecartScalingo5j) || !contient(ecarts, "aucun certificat valide pour "+hostPilote+" (le plus récent : autorité inconnue) dans acme.json du stage preprod") {
		t.Errorf("écarts %q", ecarts)
	}
	if len(s.f.liste()) != 0 {
		t.Error("certificat d'une AC inconnue poussé")
	}
}

func TestQuotidienRefusEtReponse(t *testing.T) {
	s := nouveauScenario(t)
	s.f.reponse = func(w http.ResponseWriter, a appelFGP) bool {
		w.Header().Set("X-FGP-Source", "proxy")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(a.Body)
		return true
	}
	scalingoA5Jours(s)
	ecarts, notes := s.lancer(t, appPilot)
	if !contient(ecarts, ecartScalingo5j) || !contient(ecarts, "waf-pilote : certificat de "+hostPilote+" non poussé sur waf-pilote (osc-fr1) : FGP refuse PATCH") {
		t.Errorf("écarts %q", ecarts)
	}
	if !contient(notes, "détail") {
		t.Errorf("notes %q", notes)
	}
	s.f.reponse = func(w http.ResponseWriter, a appelFGP) bool {
		_, _ = w.Write([]byte(`{"domain": {"id": "x", "ssl": true, "validity": "2027-01-01T00:00:00Z"}}`))
		return true
	}
	ecarts, _ = s.lancer(t, appPilot)
	if !contient(ecarts, "qui annonce une fin de validité au 2027-01-01 au lieu du 2027-02-08") {
		t.Errorf("écarts %q", ecarts)
	}
}

func TestQuotidienLecteurEnErreur(t *testing.T) {
	s := nouveauScenario(t)
	s.lec.err["osc-fr1/waf-pilote"] = errors.New("FGP injoignable\n2026/11/20 wafgen ops: note : fausse ligne\u2028" + strings.Repeat("x", 5000))
	ecarts, _ := s.lancer(t, appPilot)
	if !contient(ecarts, "waf-pilote : domaines de waf-pilote (osc-fr1) : FGP injoignable?2026/11/20") {
		t.Errorf("écarts %q", ecarts)
	}
	for _, e := range ecarts {
		if strings.ContainsAny(e, "\n\r\u2028") || len([]rune(e)) > maxEcart {
			t.Errorf("écart sur plusieurs lignes ou trop long : %d runes", len([]rune(e)))
		}
	}
}

func TestQuotidienIDHostile(t *testing.T) {
	s := nouveauScenario(t)
	s.lec.doms["osc-fr1/waf-pilote"][0].ID = "../../variables"
	ecarts, _ := s.lancer(t, appPilot)
	if !contient(ecarts, "hors de la route du client") || len(s.f.liste()) != 0 {
		t.Errorf("écarts %q, %d appel(s)", ecarts, len(s.f.liste()))
	}
}

func TestQuotidienEntrees(t *testing.T) {
	s := nouveauScenario(t)
	d := Deps{Lecteur: s.lec, Now: func() time.Time { return maintenant }, copieur: s.cop}
	for _, vms := range [][]VM{{{Name: "../x", Stage: "prod"}}, {{Name: "1"}, {Name: "1"}}} {
		if _, _, err := Quotidien(context.Background(), s.cfg, vms, nil, d); err == nil {
			t.Errorf("VMs %v acceptées", vms)
		}
	}
	if _, _, err := Quotidien(context.Background(), s.cfg, vmsTest, nil, Deps{}); err == nil {
		t.Error("sans lecteur")
	}
	bad := appPilot
	bad.Scalingo = "a/../b"
	ecarts, _ := s.lancer(t, bad)
	if !contient(ecarts, "app Scalingo ou région invalide") || len(s.lec.appels) != 0 {
		t.Errorf("écarts %q, lectures %v", ecarts, s.lec.appels)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Quotidien(ctx, s.cfg, vmsTest, []App{appPilot}, d); !errors.Is(err, context.Canceled) {
		t.Errorf("arrêt : %v", err)
	}
}

func TestRetention(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "acme", "preprod")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("garde"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := sauver(state, "preprod", maintenant.Add(time.Duration(i)*24*time.Hour), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Second passage le même jour : la copie du jour est remplacée.
	if _, err := sauver(state, "preprod", maintenant.Add(9*24*time.Hour+time.Hour), []byte("dernier")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	var noms []string
	for _, e := range ents {
		noms = append(noms, e.Name())
	}
	sort.Strings(noms)
	want := []string{"acme-2026-11-23.json", "acme-2026-11-24.json", "acme-2026-11-25.json", "acme-2026-11-26.json", "acme-2026-11-27.json", "acme-2026-11-28.json", "acme-2026-11-29.json", "notes.txt"}
	if strings.Join(noms, " ") != strings.Join(want, " ") {
		t.Errorf("fichiers %v", noms)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "acme-2026-11-29.json")); string(b) != "dernier" {
		t.Errorf("copie du jour %q", b)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dossier en %v", st.Mode().Perm())
	}
	if _, err := sauver(state, "../etc", maintenant, []byte("x")); err == nil {
		t.Error("nom de VM hors motif accepté")
	}
	// Restes d'une écriture interrompue : le vieux part, le récent reste.
	vieux, recent := filepath.Join(dir, ".acme-2026-11-20.json.123"), filepath.Join(dir, ".acme-2026-11-21.json.456")
	for _, p := range []string{vieux, recent} {
		if err := os.WriteFile(p, []byte("cles"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(vieux, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := sauver(state, "preprod", maintenant.Add(9*24*time.Hour), []byte("dernier")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(vieux); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fichier temporaire orphelin gardé : %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("fichier temporaire récent retiré : %v", err)
	}
}

func TestPropre(t *testing.T) {
	for in, want := range map[string]string{
		"a\nb\r\nc":           "a?b??c",
		"x\x1b[31my":          "x?[31my",
		"é\u2028\u2029\u0085": "é???",
		"tout va bien":        "tout va bien",
	} {
		if got := propre(in, 100); got != want {
			t.Errorf("%q : %q, %q attendu", in, got, want)
		}
	}
	if got := propre(strings.Repeat("é", 20), 10); got != strings.Repeat("é", 9)+"…" {
		t.Errorf("borne : %q", got)
	}
}

func TestCNSujet(t *testing.T) {
	for in, want := range map[string]string{
		"/C=FR/ST=Some-State/O=Internet Widgits Pty Ltd/CN=example.com": "example.com",
		"/CN=waf-pilote.incubateur.ademe.dev":                           "waf-pilote.incubateur.ademe.dev",
		"CN=a.example.org,O=X":                                          "a.example.org",
		"/O=Sans CN":                                                    "",
		"":                                                              "",
	} {
		if got := cnSujet(in); got != want {
			t.Errorf("%q : %q, %q attendu", in, got, want)
		}
	}
}

func TestDemandeEcriture(t *testing.T) {
	d, err := DemandeEcriture("osc-fr1", "waf-pilote")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	want := `{"name":"waf-ops certificat waf-pilote","target":"https://api.osc-fr1.scalingo.com","auth":"scalingo-exchange","scopes":[{"methods":["PATCH"],"pattern":"/v1/apps/waf-pilote/domains/*","bodyFilters":[{"objectPath":"domain.tlscert","objectValue":[{"type":"stringwildcard","value":"-----BEGIN CERTIFICATE-----*"}]},{"objectPath":"domain.tlskey","objectValue":[{"type":"stringwildcard","value":"-----BEGIN PRIVATE KEY-----*"},{"type":"stringwildcard","value":"-----BEGIN *PRIVATE KEY-----*"}]}]}],"ttl":31536000}`
	if string(b) != want {
		t.Errorf("demande\n%s\nattendue\n%s", b, want)
	}
	for _, k := range [][2]string{{"fr1", "a"}, {"osc-fr1", "a/b"}, {"osc-fr1", "*"}} {
		if _, err := DemandeEcriture(k[0], k[1]); err == nil {
			t.Errorf("%v accepté", k)
		}
	}
}
