package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/provision"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	l, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if len(l) == 1 && l[0] == "panne" {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	var out []net.IPAddr
	for _, s := range l {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestControleDNS(t *testing.T) {
	app := inventory.App{Name: "a", Stage: "preprod", Hosts: []string{"ok.example.org", "v6.example.org", "ailleurs.example.org", "absent.example.org", "panne.example.org", "cf.example.org", "seul6.example.org"}}
	res := fakeResolver{
		"ok.example.org":       {ipPP},
		"v6.example.org":       {ipPP, "2001:db8::1"},
		"ailleurs.example.org": {ipPP, "80.247.13.145"},
		"panne.example.org":    {"panne"},
		"cf.example.org":       {"104.16.1.1", "2606:4700::1"},
		"seul6.example.org":    {},
	}
	ecarts, notes := ControleDNS(context.Background(), res, app, []string{ipPP})
	got := strings.Join(ecarts, "\n")
	for _, w := range []string{
		"DNS : v6.example.org résout vers 2001:db8::1, hors de les IP des VM du stage preprod",
		"DNS : ailleurs.example.org résout vers 80.247.13.145",
		"DNS : absent.example.org ne résout pas",
		"DNS : résolution de panne.example.org en échec",
		"DNS : cf.example.org résout vers 104.16.1.1 2606:4700::1",
		"DNS : seul6.example.org sans adresse IPv4",
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("écart %q absent :\n%s", w, got)
		}
	}
	if strings.Contains(got, "ok.example.org") || len(ecarts) != 6 || len(notes) != 1 {
		t.Fatalf("écarts : %v notes : %v", ecarts, notes)
	}

	app.Edge = "cloudflare"
	app.Hosts = []string{"cf.example.org", "ok.example.org", "ailleurs.example.org"}
	ecarts, _ = ControleDNS(context.Background(), res, app, []string{ipPP})
	if len(ecarts) != 1 || !strings.Contains(ecarts[0], "ailleurs.example.org résout vers 80.247.13.145, hors de les IP des VM du stage preprod ou Cloudflare") {
		t.Fatalf("app edge : %v", ecarts)
	}
	res["cf.example.org"] = []string{"::ffff:104.16.1.1"}
	if ecarts, _ = ControleDNS(context.Background(), res, inventory.App{Hosts: []string{"cf.example.org"}, Edge: "cloudflare"}, nil); len(ecarts) != 0 {
		t.Fatalf("IPv4 mappée : %v", ecarts)
	}
}

// pki : une autorité de test et des certificats feuilles signés par elle.
type pki struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca de test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return pki{ca: ca, key: key, roots: roots}
}

func (p pki) leaf(t *testing.T, host string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer sert, par SNI, le certificat de certs, sans rien d'autre que la poignée de main.
func tlsServer(t *testing.T, certs map[string]tls.Certificate) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, ok := certs[h.ServerName]
		if !ok {
			c = certs["*"]
		}
		return &c, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func TestControleCertificats(t *testing.T) {
	now := time.Now()
	p := newPKI(t)
	autre := newPKI(t)
	addr := tlsServer(t, map[string]tls.Certificate{
		"ok.example.org":      p.leaf(t, "ok.example.org", now.Add(60*24*time.Hour)),
		"bientot.example.org": p.leaf(t, "bientot.example.org", now.Add(10*24*time.Hour)),
		"inconnu.example.org": autre.leaf(t, "inconnu.example.org", now.Add(60*24*time.Hour)),
		"*":                   p.leaf(t, "defaut.example.org", now.Add(60*24*time.Hour)),
	})
	var dials []string
	c := TLSServi{Roots: p.roots, Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
		dials = append(dials, a)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	app := inventory.App{Hosts: []string{"ok.example.org", "bientot.example.org", "inconnu.example.org", "autre-nom.example.org"}}
	ecarts, _ := ControleCertificats(context.Background(), c, app, []string{ipPP}, now)
	got := strings.Join(ecarts, "\n")
	for _, w := range []string{
		"certificat de bientot.example.org sur " + ipPP + " : expire le",
		"certificat de inconnu.example.org sur " + ipPP + " : certificat refusé",
		"certificat de autre-nom.example.org sur " + ipPP + " : certificat pour un autre nom",
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("écart %q absent :\n%s", w, got)
		}
	}
	if len(ecarts) != 3 || dials[0] != ipPP+":443" {
		t.Fatalf("écarts : %v connexions : %v", ecarts, dials)
	}

	// Sans réglage de test, les racines du système : l'autorité de test est refusée.
	c.Roots = nil
	ecarts, _ = ControleCertificats(context.Background(), c, inventory.App{Hosts: []string{"ok.example.org"}}, []string{ipPP}, now)
	if len(ecarts) != 1 || !strings.Contains(ecarts[0], "certificat refusé") {
		t.Fatalf("autorité de test acceptée sans réglage : %v", ecarts)
	}
}

type fakeAPI struct{ provision.API }

func TestParseProvision(t *testing.T) {
	if p, err := parseProvision(""); p != nil || err != nil {
		t.Fatalf("variable absente : %v %v", p, err)
	}
	for _, raw := range []string{`{`, `{"project":"p","github_app":"g","vms":{}}`, `{"project":"p","github_app":"g","vms":{"1":{"server":"s"}}}`, `{"project":"p","github_app":"g","vms":{"1":{"server":"s","destination":"d"}},"token":"x"}`} {
		if _, err := parseProvision(raw); err == nil {
			t.Fatalf("%s accepté", raw)
		}
	}
}

func TestControlePlan(t *testing.T) {
	inv := inventory.Inventory{
		VMs: []inventory.VM{{Name: "1", Stage: "prod", IP: ipProd}, {Name: "preprod", Stage: "preprod", IP: ipPP}},
		Apps: []inventory.App{
			{Name: "waf-pilote", Stage: "preprod", Live: true},
			{Name: "brouillon", Stage: "preprod"},
			{Name: "nouvelle", Stage: "preprod", Live: true},
			{Name: "tacct", Stage: "prod", Live: true},
		},
	}
	p := Provision{Project: "proj", GithubApp: "gh", VMs: map[string]ProvisionVM{"preprod": {Server: "srv", Destination: "dst"}}}
	var got provision.Config
	var gotApps []string
	var gotAPI provision.API
	computePlan = func(_ context.Context, api provision.API, cfg provision.Config, apps []inventory.App) (*provision.Plan, error) {
		got, gotAPI = cfg, api
		for _, a := range apps {
			gotApps = append(gotApps, a.Name)
		}
		return &provision.Plan{Notes: []string{"WAF_BASE à remplir"}, Apps: []provision.AppPlan{
			{App: apps[0], Name: "waf-waf-pilote-preprod", Fields: []provision.Change{{Key: "health_check_enabled", Old: "false", New: "true"}}, Envs: []provision.EnvChange{{Key: "UPSTREAM", Old: "secret-avant", New: "secret-apres"}},
				Notes: []string{`UPSTREAM : valeur littérale "https://secret-origine.osc-fr1.scalingo.io" conservée`}},
			{App: apps[1], Name: "waf-brouillon-preprod", Create: true},
			{App: apps[2], Name: "waf-nouvelle-preprod", Create: true},
		}}, nil
	}
	t.Cleanup(func() { computePlan = provision.Compute })
	ecarts, notes := ControlePlan(context.Background(), fakeAPI{}, p, "https://c.example.org", "jeton", inv, map[string]bool{"preprod": true})
	if got.VM != "preprod" || got.ServerUUID != "srv" || got.DestinationUUID != "dst" || got.Environment != "production" || got.BaseRef != provision.DefaultBaseRef ||
		strings.Join(got.OtherVMs, ",") != "1" || strings.Join(gotApps, ",") != "waf-pilote,brouillon,nouvelle" {
		t.Fatalf("config : %+v apps : %v", got, gotApps)
	}
	if _, ok := gotAPI.(lectureSeule); !ok {
		t.Fatalf("API passée sans garde de lecture seule : %T", gotAPI)
	}
	all := strings.Join(append(ecarts, notes...), "\n")
	if len(ecarts) != 2 || !strings.Contains(ecarts[0], "waf-waf-pilote-preprod diffère de l'inventaire (health_check_enabled, env UPSTREAM)") ||
		!strings.Contains(ecarts[1], "waf-nouvelle-preprod à créer alors que l'app est en service") || strings.Contains(all, "secret-") {
		t.Fatalf("écarts : %v", ecarts)
	}
	if !strings.Contains(all, "waf-brouillon-preprod à créer, app pas encore en service") || !strings.Contains(all, "VM preprod : 2 note(s) de plan") || strings.Contains(all, "secret-origine") {
		t.Fatalf("notes : %v", notes)
	}

	computePlan = func(context.Context, provision.API, provision.Config, []inventory.App) (*provision.Plan, error) {
		return nil, fmt.Errorf("waf-x : %w", &coolify.HTTPError{Method: "GET", Path: "/api/v1/applications/u/envs", Status: 500, Body: `{"value":"secret-dans-le-corps"}`})
	}
	_, notes = ControlePlan(context.Background(), fakeAPI{}, p, "u", "t", inv, map[string]bool{"preprod": true})
	if len(notes) != 1 || notes[0] != "provision : VM preprod : Coolify GET /api/v1/applications/u/envs : HTTP 500" {
		t.Fatalf("corps d'erreur Coolify : %v", notes)
	}
	computePlan = func(context.Context, provision.API, provision.Config, []inventory.App) (*provision.Plan, error) {
		return nil, errors.New("destination dst sur le réseau coolify")
	}
	ecarts, notes = ControlePlan(context.Background(), fakeAPI{}, p, "u", "t", inv, map[string]bool{"preprod": true, "prod": true})
	if len(ecarts) != 2 || ecarts[0] != "provision : VM 1 absente de WAF_OPS_PROVISION" || ecarts[1] != "provision : plan de la VM preprod impossible" || !strings.Contains(strings.Join(notes, ""), "réseau coolify") {
		t.Fatalf("erreurs : %v %v", ecarts, notes)
	}
}

func TestLectureSeule(t *testing.T) {
	var api provision.API = lectureSeule{fakeAPI{}}
	if _, err := api.CreateApplication(context.Background(), nil); !errors.Is(err, errLectureSeule) {
		t.Fatal(err)
	}
	if err := api.UpdateApplication(context.Background(), "u", nil); !errors.Is(err, errLectureSeule) {
		t.Fatal(err)
	}
	if err := api.UpsertApplicationEnvs(context.Background(), "u", []coolify.EnvWrite{}); !errors.Is(err, errLectureSeule) {
		t.Fatal(err)
	}
}
