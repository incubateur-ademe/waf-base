package ops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/incubateur-ademe/waf-base/internal/certs"
	"github.com/incubateur-ademe/waf-base/internal/cloudflare"
	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/ghaudit"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

// envOptionnel : des variables valides pour les trois tâches facultatives.
func envOptionnel(t *testing.T) map[string]string {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	hpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewPublicKey(hpub)
	if err != nil {
		t.Fatal(err)
	}
	rsaOnce.Do(func() { rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
	appKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	e := fullEnv()
	e[certs.EnvCleSSH] = string(pem.EncodeToMemory(blk))
	e[certs.EnvKnownHosts] = "172.16.12.7 " + string(ssh.MarshalAuthorizedKey(hk))
	e[certs.EnvVMs] = "preprod=172.16.12.7"
	e[certs.EnvFGPEcriture] = `{"osc-fr1": {"waf-pilote": "` + testBlob + `"}}`
	e[ghaudit.EnvAppID] = "Iv23liTEST"
	e[ghaudit.EnvAppKey] = string(appKey)
	e[cloudflare.TokenEnv] = "jeton-cloudflare-de-test-0123456789"
	return e
}

func TestOptionnellesAbsentes(t *testing.T) {
	cfg, err := LoadConfig(env(fullEnv()), ModeBoucle)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Opt.Certs != nil || cfg.Opt.GitHub != nil || cfg.Opt.CloudflareToken != "" || len(cfg.Opt.Erreurs) != 0 {
		t.Fatalf("tâches facultatives sans variables : %+v", cfg.Opt)
	}
	ts, absentes := Taches(cfg, Deps{})
	if len(ts) != 1 || ts[0].Nom != "audit" || strings.Join(absentes, ",") != "certificats,cloudflare,github" {
		t.Fatalf("tâches : %v, absentes : %v", ts, absentes)
	}
}

func TestOptionnellesValides(t *testing.T) {
	e := envOptionnel(t)
	cfg, err := LoadConfig(env(e), ModeBoucle)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Opt.Certs == nil || cfg.Opt.GitHub == nil || cfg.Opt.CloudflareToken == "" || len(cfg.Opt.Erreurs) != 0 {
		t.Fatalf("config : certs=%v github=%v cloudflare=%q erreurs=%v", cfg.Opt.Certs != nil, cfg.Opt.GitHub != nil, cfg.Opt.CloudflareToken, cfg.Opt.Erreurs)
	}
	if cfg.Opt.Certs.FGPKey != testKey || cfg.Opt.Certs.State != cfg.State {
		t.Fatal("certificats : clé FGP ou dossier d'état non repris de la config de waf-ops")
	}
	cf, _ := cloudflare.New(cfg.Opt.CloudflareToken)
	ts, absentes := Taches(cfg, Deps{Cloudflare: cf})
	var noms []string
	for _, x := range ts {
		noms = append(noms, fmt.Sprintf("%s/%s", x.Nom, x.Periode))
	}
	if strings.Join(noms, ",") != "audit/1h0m0s,certificats/24h0m0s,github/1h0m0s,cloudflare/1h0m0s" || len(absentes) != 0 {
		t.Fatalf("tâches : %v, absentes : %v", noms, absentes)
	}
	if _, absentes := Taches(cfg, Deps{}); strings.Join(absentes, ",") != "cloudflare" {
		t.Fatalf("Cloudflare sans client lancée : %v", absentes)
	}
}

func TestOptionnellesIncompletes(t *testing.T) {
	e := envOptionnel(t)
	cle := e[certs.EnvCleSSH]
	delete(e, certs.EnvKnownHosts)
	delete(e, ghaudit.EnvAppKey)
	e[cloudflare.TokenEnv] = "jeton avec des blancs"
	cfg, err := LoadConfig(env(e), ModeBoucle)
	if err != nil {
		t.Fatalf("une config facultative incomplète arrête waf-ops : %v", err)
	}
	if cfg.Opt.Certs != nil || cfg.Opt.GitHub != nil || cfg.Opt.CloudflareToken != "" {
		t.Fatalf("config incomplète gardée : %+v", cfg.Opt)
	}
	if !strings.Contains(cfg.Opt.Erreurs["certificats"], certs.EnvKnownHosts) || !strings.Contains(cfg.Opt.Erreurs["github"], ghaudit.EnvAppKey) ||
		cfg.Opt.Erreurs["cloudflare"] == "" {
		t.Fatalf("erreurs : %v", cfg.Opt.Erreurs)
	}
	for nom, msg := range cfg.Opt.Erreurs {
		if strings.Contains(msg, "BEGIN") || strings.Contains(msg, cle[40:60]) || strings.Contains(msg, "jeton avec") {
			t.Fatalf("%s : valeur dans l'erreur : %q", nom, msg)
		}
	}
	ts, absentes := Taches(cfg, Deps{})
	if len(ts) != 4 || len(absentes) != 0 {
		t.Fatalf("tâches en erreur de config non lancées : %d %v", len(ts), absentes)
	}
	for _, x := range ts[1:] {
		_, _, err := x.Run(context.Background(), nil)
		if err == nil || !strings.HasPrefix(err.Error(), "configuration : ") {
			t.Fatalf("%s : %v", x.Nom, err)
		}
	}

	// Dans la boucle : le pulse le dit, le contrôle continue.
	d, _ := pilotDeps(t, ipPP+"/32")
	cfg.Inventaire, cfg.Etc, cfg.State = testCfg(t).Inventaire, "../..", t.TempDir()
	p := &fakePulse{}
	o := &Runner{Cfg: cfg, Deps: d, Pulse: p, Logf: func(string, ...any) {}, Taches: ts[1:]}
	o.Passage(context.Background())
	if !strings.Contains(p.bodies[0], "certificats en échec : configuration : variables manquantes : "+certs.EnvKnownHosts) {
		t.Fatalf("pulse : %v", p.bodies)
	}
}

type fakeDomaines struct{}

func (fakeDomaines) DomainesTLS(context.Context, string, string) ([]certs.Domain, error) {
	return nil, nil
}

func TestCopieCertificats(t *testing.T) {
	cfg := testCfg(t)
	cfg.Opt.Certs = &certs.Config{State: cfg.State}
	d, _ := pilotDeps(t, ipPP+"/32")
	d.Domaines = fakeDomaines{}
	var vms []certs.VM
	var apps []certs.App
	certsQuotidien = func(_ context.Context, c certs.Config, v []certs.VM, a []certs.App, deps certs.Deps) ([]string, []string, error) {
		vms, apps = v, a
		if deps.Lecteur == nil || deps.Now == nil {
			t.Fatal("lecteur ou horloge non transmis")
		}
		return []string{"waf-pilote : certificat de waf-pilote.incubateur.ademe.dev à moins de 21 jours"}, []string{"vm preprod : copie gardée"}, nil
	}
	t.Cleanup(func() { certsQuotidien = certs.Quotidien })
	r, err := CopieCertificats(context.Background(), cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 2 || vms[0] != (certs.VM{Name: "1", Stage: "prod"}) && vms[1] != (certs.VM{Name: "1", Stage: "prod"}) {
		t.Fatalf("VM : %v (toutes celles de l'inventaire)", vms)
	}
	if len(apps) != 1 || apps[0].Name != "waf-pilote" || apps[0].Scalingo != "waf-pilote" || apps[0].Region != "osc-fr1" ||
		strings.Join(apps[0].Hosts, ",") != "waf-pilote.incubateur.ademe.dev" {
		t.Fatalf("apps : %+v", apps)
	}
	if r.Apps != 1 || len(r.Ecarts) != 1 || !strings.Contains(strings.Join(r.Notes, "\n"), "copie gardée") {
		t.Fatalf("rapport : %+v", r)
	}

	// UPSTREAM absente : l'app n'est pas passée, la note le dit, sans écart.
	d.Coolify = fakeTeam{envs: []coolify.SharedEnv{shared(t, "LOCK_WAF_PILOTE", "x", false)}}
	apps = nil
	r, _ = CopieCertificats(context.Background(), cfg, d)
	if len(apps) != 0 || len(r.Ecarts) != 1 || !strings.Contains(strings.Join(r.Notes, "\n"), "UPSTREAM_WAF_PILOTE absente") {
		t.Fatalf("cible illisible : %v %+v", apps, r)
	}

	d.Domaines = nil
	if _, err := CopieCertificats(context.Background(), cfg, d); err == nil {
		t.Fatal("copie lancée sans lecteur de domaines")
	}
	certsQuotidien = func(context.Context, certs.Config, []certs.VM, []certs.App, certs.Deps) ([]string, []string, error) {
		return nil, nil, context.Canceled
	}
	d.Domaines = fakeDomaines{}
	if _, err := CopieCertificats(context.Background(), cfg, d); !errors.Is(err, context.Canceled) {
		t.Fatalf("erreur de Quotidien perdue : %v", err)
	}
}

func TestAuditsGitHubCloudflare(t *testing.T) {
	cfg := testCfg(t)
	cfg.Opt.GitHub = &ghaudit.Config{AppID: "x"}
	d, _ := pilotDeps(t, ipPP+"/32")
	var vus []string
	ghAudit = func(_ context.Context, _ ghaudit.Config, apps []inventory.App) ([]string, []string, error) {
		for _, a := range apps {
			vus = append(vus, a.Name)
		}
		return []string{"incubateur-ademe/waf-pilote : CODEOWNERS absent"}, nil, nil
	}
	t.Cleanup(func() { ghAudit = ghaudit.Audit })
	r, err := GitHub(context.Background(), cfg, d)
	if err != nil || strings.Join(vus, ",") != "koyo,waf-pilote" || r.Apps != 2 || len(r.Ecarts) != 1 {
		t.Fatalf("github : %v %v %+v (apps live du stage, toutes plateformes)", err, vus, r)
	}

	cf, _ := cloudflare.New("jeton-cloudflare-de-test-0123456789")
	d.Cloudflare = cf
	var apps, all []string
	var team int
	cfAudit = func(_ context.Context, _ cloudflare.Reader, a, tout []inventory.App, tm map[string]coolify.SharedEnv) ([]string, []string, error) {
		for _, x := range a {
			apps = append(apps, x.Name)
		}
		for _, x := range tout {
			all = append(all, x.Name)
		}
		team = len(tm)
		return nil, []string{"note"}, errors.New("zone tacct.ademe.fr invisible du jeton")
	}
	t.Cleanup(func() { cfAudit = cloudflare.Audit })
	r, err = Cloudflare(context.Background(), cfg, d)
	if err == nil || strings.Join(apps, ",") != "koyo,waf-pilote" || len(all) != 4 || team == 0 || len(r.Notes) == 0 {
		t.Fatalf("cloudflare : %v apps=%v all=%v team=%d %+v", err, apps, all, team, r)
	}
	d.Cloudflare = nil
	if _, err := Cloudflare(context.Background(), cfg, d); err == nil {
		t.Fatal("audit Cloudflare sans client")
	}
}

func TestDomainesTLS(t *testing.T) {
	c := fgpServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/waf-pilote/domains" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `{"domains":[{"id":"d1","name":"waf-pilote.incubateur.ademe.dev","ssl":true,"tlscert":"CN=waf-pilote.incubateur.ademe.dev","validity":"2027-02-17T00:00:00Z"},{"id":"d2","name":"x.example.org","ssl":false,"validity":null}]}`)
	})
	doms, err := c.DomainesTLS(context.Background(), "osc-fr1", "waf-pilote")
	if err != nil || len(doms) != 2 || doms[0].ID != "d1" || !doms[0].Validity.Equal(time.Date(2027, 2, 17, 0, 0, 0, 0, time.UTC)) || !doms[1].Validity.IsZero() {
		t.Fatalf("%v %+v", err, doms)
	}
	if _, err := c.DomainesTLS(context.Background(), "osc-fr1", "../x"); err == nil {
		t.Fatal("nom d'app invalide accepté")
	}
	c = fgpServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) })
	if _, err := c.DomainesTLS(context.Background(), "osc-fr1", "waf-pilote"); err == nil {
		t.Fatal("réponse sans domains acceptée")
	}
}

func TestMainGitHubSansConfig(t *testing.T) {
	var out, errw bytes.Buffer
	e := fullEnv()
	cfg := testCfg(t)
	e["WAF_OPS_INVENTAIRE"], e["WAF_OPS_ETC"], e["WAF_OPS_STATE"] = cfg.Inventaire, "../..", cfg.State
	if err := Main(context.Background(), []string{"github"}, env(e), &out, &errw); err == nil || !strings.Contains(err.Error(), "audit GitHub non configuré") {
		t.Fatalf("github sans config : %v", err)
	}
	e[ghaudit.EnvAppID] = "Iv23liTEST"
	if err := Main(context.Background(), []string{"github"}, env(e), &out, &errw); err == nil || !strings.Contains(err.Error(), "github : configuration : variables manquantes") {
		t.Fatalf("github incomplet : %v", err)
	}
}
