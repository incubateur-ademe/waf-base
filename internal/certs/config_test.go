package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const cleEdTest = "fausse-cle-privee-ed25519"

func clePEM(t *testing.T, k any, phrase string) string {
	t.Helper()
	var blk *pem.Block
	var err error
	if phrase != "" {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(k, "", []byte(phrase))
	} else {
		blk, err = ssh.MarshalPrivateKey(k, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(blk))
}

type envTest struct {
	vals map[string]string
	cle  string
	hote [2]ssh.PublicKey
}

func nouvelEnv(t *testing.T) envTest {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h1, h2 := signerEd25519(t).PublicKey(), signerECDSA(t).PublicKey()
	cle := clePEM(t, k, "")
	kh := "# waf-1\n172.16.12.5 " + string(ssh.MarshalAuthorizedKey(h1)) + "[172.16.12.7]:22 " + string(ssh.MarshalAuthorizedKey(h2))
	return envTest{
		cle:  cle,
		hote: [2]ssh.PublicKey{h1, h2},
		vals: map[string]string{
			EnvCleSSH:      cle,
			EnvKnownHosts:  kh,
			EnvVMs:         "1=172.16.12.5, preprod=172.16.12.7",
			EnvFGPEcriture: `{"osc-fr1": {"waf-pilote": "` + testBlob + `"}}`,
		},
	}
}

func (e envTest) get(k string) string { return e.vals[k] }

func TestLoadConfig(t *testing.T) {
	e := nouvelEnv(t)
	c, err := LoadConfig(e.get, "https://fgp.incubateur.ademe.fr/", testCleFGP, "/var/lib/waf-ops")
	if err != nil {
		t.Fatal(err)
	}
	if c.FGPURL != "https://fgp.incubateur.ademe.fr" || c.FGPKey != testCleFGP || c.State != "/var/lib/waf-ops" {
		t.Errorf("FGP ou état : %q %q", c.FGPURL, c.State)
	}
	if c.Signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("clé %s", c.Signer.PublicKey().Type())
	}
	if c.VMs["1"] != netip.MustParseAddr("172.16.12.5") || c.VMs["preprod"] != netip.MustParseAddr("172.16.12.7") {
		t.Errorf("VMs %v", c.VMs)
	}
	if k := c.KnownHosts[netip.MustParseAddr("172.16.12.7")]; len(k) != 1 || string(k[0].Marshal()) != string(e.hote[1].Marshal()) {
		t.Errorf("known_hosts de 172.16.12.7 : %v", k)
	}
	if c.Ecriture["osc-fr1"]["waf-pilote"] != testBlob {
		t.Error("blob d'écriture non lu")
	}
	if c.port() != 22 {
		t.Errorf("port %d", c.port())
	}
}

func TestLoadConfigManquantes(t *testing.T) {
	_, err := LoadConfig(func(string) string { return "" }, "https://fgp.example.org", testCleFGP, "/s")
	want := "variables manquantes : WAF_OPS_ACME_SSH_KEY, WAF_OPS_ACME_KNOWN_HOSTS, WAF_OPS_ACME_VMS, WAF_OPS_FGP_ECRITURE"
	if err == nil || err.Error() != want {
		t.Fatalf("erreur %v", err)
	}
}

func TestLoadConfigRefus(t *testing.T) {
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	ec := ecKey(t)
	h := string(ssh.MarshalAuthorizedKey(signerEd25519(t).PublicKey()))
	cas := []struct {
		nom, k, v, attendu string
		url, cle           string
	}{
		{nom: "clé ecdsa", k: EnvCleSSH, v: clePEM(t, ec, ""), attendu: "ed25519 attendue"},
		{nom: "clé chiffrée", k: EnvCleSSH, v: clePEM(t, edk, "phrase"), attendu: "sans phrase de passe"},
		{nom: "clé illisible", k: EnvCleSSH, v: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + cleEdTest + "\n-----END OPENSSH PRIVATE KEY-----", attendu: "multiligne"},
		{nom: "host haché", k: EnvKnownHosts, v: "|1|abc=|def= " + h, attendu: "IPv4 en clair"},
		{nom: "host par nom", k: EnvKnownHosts, v: "waf-1 " + h, attendu: "IPv4 en clair"},
		{nom: "autre port", k: EnvKnownHosts, v: "[172.16.12.5]:2222 " + h, attendu: "IPv4 en clair"},
		{nom: "marqueur", k: EnvKnownHosts, v: "@cert-authority 172.16.12.5 " + h, attendu: "marqueur"},
		{nom: "ligne tronquée", k: EnvKnownHosts, v: "172.16.12.5", attendu: "ligne 1 illisible"},
		{nom: "known_hosts vide", k: EnvKnownHosts, v: "# rien", attendu: "aucune clé d'hôte"},
		{nom: "IP publique", k: EnvVMs, v: "1=78.232.54.148", attendu: "IPv4 privée"},
		{nom: "IPv6", k: EnvVMs, v: "1=fd00::5", attendu: "IPv4 privée"},
		{nom: "nom de VM", k: EnvVMs, v: "../x=172.16.12.5", attendu: "<vm>=<ip privée>"},
		{nom: "VM en double", k: EnvVMs, v: "1=172.16.12.5,1=172.16.12.7", attendu: "en double"},
		{nom: "VM sans clé d'hôte", k: EnvVMs, v: "1=172.16.12.9", attendu: "aucune clé d'hôte pour 172.16.12.9"},
		{nom: "écriture illisible", k: EnvFGPEcriture, v: `{"osc-fr1": "` + testBlob + `"}`, attendu: "JSON"},
		{nom: "région", k: EnvFGPEcriture, v: `{"` + testBlob + `": {"a": "b"}}`, attendu: "région n°1"},
		{nom: "app", k: EnvFGPEcriture, v: `{"osc-fr1": {"A/../b": "` + testBlob + `"}}`, attendu: "nom d'app"},
		{nom: "blob à blanc", k: EnvFGPEcriture, v: `{"osc-fr1": {"a": "` + testBlob + ` x"}}`, attendu: "avec des blancs"},
		{nom: "blob trop long", k: EnvFGPEcriture, v: `{"osc-fr1": {"a": "` + strings.Repeat("b", maxBlob+1) + `"}}`, attendu: "trop long"},
		{nom: "écriture vide", k: EnvFGPEcriture, v: `{}`, attendu: "aucun blob"},
		{nom: "FGP en http", url: "http://fgp.example.org", attendu: "https://<hôte>"},
		{nom: "FGP avec identifiants", url: "https://u:" + testCleFGP + "@fgp.example.org", attendu: "https://<hôte>"},
		{nom: "FGP avec chemin", url: "https://fgp.example.org/v1", attendu: "https://<hôte>"},
		{nom: "clé FGP courte", cle: "courte", attendu: "24 caractères"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			e := nouvelEnv(t)
			if c.k != "" {
				e.vals[c.k] = c.v
			}
			url, cle := "https://fgp.example.org", testCleFGP
			if c.url != "" {
				url = c.url
			}
			if c.cle != "" {
				cle = c.cle
			}
			_, err := LoadConfig(e.get, url, cle, "/s")
			if err == nil || !strings.Contains(err.Error(), c.attendu) {
				t.Fatalf("erreur %v, %q attendu", err, c.attendu)
			}
			sansSecret(t, c.nom, []string{err.Error()}, []string{testBlob, testCleFGP, cleEdTest, e.cle})
		})
	}
}
