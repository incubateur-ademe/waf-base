package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	testCleFGP = "cle-fgp-de-test-qui-ne-doit-jamais-sortir"
	testBlob   = "blob-ecriture-de-test-qui-ne-doit-jamais-sortir"
	hostPilote = "waf-pilote.incubateur.ademe.dev"
	idPilote   = "dom-0e5c2a3e-1111-2222-3333-444455556666"
)

var maintenant = time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)

type pki struct {
	root     *x509.Certificate
	inter    *x509.Certificate
	interKey crypto.Signer
	pool     *x509.CertPool
}

var (
	pkiOnce sync.Once
	pkiTest *pki
	rsaOnce sync.Once
	rsaCle  *rsa.PrivateKey
	serial  int64 = 100
	serialM sync.Mutex
)

func nextSerial() *big.Int {
	serialM.Lock()
	defer serialM.Unlock()
	serial++
	return big.NewInt(serial)
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func nouvelleAC(t *testing.T, cn string, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	k := ecKey(t)
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent, parentKey = tpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, k.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func nouvellePKI(t *testing.T, nom string) *pki {
	t.Helper()
	root, rootKey := nouvelleAC(t, nom+" racine", nil, nil)
	inter, interKey := nouvelleAC(t, nom+" R11", root, rootKey)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &pki{root: root, inter: inter, interKey: interKey, pool: pool}
}

func lePKI(t *testing.T) *pki {
	pkiOnce.Do(func() { pkiTest = nouvellePKI(t, "Test") })
	return pkiTest
}

// emis : chaîne et clé PEM d'un certificat de feuille, comme Traefik les range.
type emis struct {
	chaine []byte
	cle    []byte
	leaf   *x509.Certificate
}

type optsFeuille struct {
	cn        string
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	// ec (SEC 1, défaut), rsa (PKCS #1) ou pkcs8.
	cle string
}

func (p *pki) feuille(t *testing.T, o optsFeuille) emis {
	t.Helper()
	if o.notBefore.IsZero() {
		o.notBefore = maintenant.Add(-10 * 24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = maintenant.Add(80 * 24 * time.Hour)
	}
	if o.dns == nil {
		o.dns = []string{o.cn}
	}
	var pub crypto.PublicKey
	var keyPEM []byte
	switch o.cle {
	case "rsa":
		rsaOnce.Do(func() {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaCle = k
		})
		pub = rsaCle.Public()
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaCle)})
	case "pkcs8":
		k := ecKey(t)
		pub = k.Public()
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	default:
		k := ecKey(t)
		pub = k.Public()
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	tpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: o.cn},
		DNSNames:     o.dns,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.inter, pub, p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var chaine bytes.Buffer
	_ = pem.Encode(&chaine, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&chaine, &pem.Block{Type: "CERTIFICATE", Bytes: p.inter.Raw})
	return emis{chaine: chaine.Bytes(), cle: keyPEM, leaf: leaf}
}

type entree struct {
	main string
	cert []byte
	key  []byte
	// brut remplace l'encodage base64 de cert et key.
	certB64, keyB64 string
}

func acmeJSON(t *testing.T, resolver string, es ...entree) []byte {
	t.Helper()
	type c struct {
		Domain      map[string]any `json:"domain"`
		Certificate string         `json:"certificate"`
		Key         string         `json:"key"`
		Store       string         `json:"Store"`
	}
	var cs []c
	for _, e := range es {
		cb, kb := e.certB64, e.keyB64
		if cb == "" {
			cb = base64.StdEncoding.EncodeToString(e.cert)
		}
		if kb == "" {
			kb = base64.StdEncoding.EncodeToString(e.key)
		}
		cs = append(cs, c{Domain: map[string]any{"main": e.main}, Certificate: cb, Key: kb, Store: "default"})
	}
	b, err := json.Marshal(map[string]any{
		resolver: map[string]any{
			"Account":      map[string]any{"Email": "", "PrivateKey": "AAAA", "KeyType": "4096"},
			"Certificates": cs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// secrets rend les morceaux d'une clé PEM qui ne doivent sortir nulle part :
// chaque ligne de base64, la clé entière et son encodage base64.
func secrets(cles ...[]byte) []string {
	var out []string
	for _, k := range cles {
		out = append(out, string(k), base64.StdEncoding.EncodeToString(k))
		for _, l := range strings.Split(string(k), "\n") {
			if len(l) >= 16 && !strings.HasPrefix(l, "-----") {
				out = append(out, l)
			}
		}
	}
	return out
}

func sansSecret(t *testing.T, ou string, textes []string, interdits []string) {
	t.Helper()
	for _, tx := range textes {
		for _, s := range interdits {
			if s != "" && strings.Contains(tx, s) {
				t.Errorf("%s : secret dans %q", ou, tx)
			}
		}
	}
}

// fauxFGP : FGP et Scalingo d'un coup. Il relit le certificat poussé pour
// répondre comme Scalingo, avec la fin de validité du certificat reçu.
type fauxFGP struct {
	srv     *httptest.Server
	mu      sync.Mutex
	appels  []appelFGP
	reponse func(w http.ResponseWriter, a appelFGP) bool
}

type appelFGP struct {
	Method, Path, Key, Blob, ContentType string
	Body                                 []byte
}

func demarrerFGP(t *testing.T) *fauxFGP {
	t.Helper()
	f := &fauxFGP{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a := appelFGP{Method: r.Method, Path: r.URL.EscapedPath(), Key: r.Header.Get("X-FGP-Key"), Blob: r.Header.Get("X-FGP-Blob"), ContentType: r.Header.Get("Content-Type"), Body: b}
		f.mu.Lock()
		f.appels = append(f.appels, a)
		rep := f.reponse
		f.mu.Unlock()
		if rep != nil && rep(w, a) {
			return
		}
		repondreCommeScalingo(w, a)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fauxFGP) liste() []appelFGP {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]appelFGP(nil), f.appels...)
}

func repondreCommeScalingo(w http.ResponseWriter, a appelFGP) {
	var corps struct {
		Domain struct {
			TLSCert string `json:"tlscert"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(a.Body, &corps); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	blk, _ := pem.Decode([]byte(corps.Domain.TLSCert))
	if blk == nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	paris := time.FixedZone("CET", 3600)
	id := a.Path[strings.LastIndex(a.Path, "/")+1:]
	_ = json.NewEncoder(w).Encode(map[string]any{"domain": map[string]any{
		"id": id, "name": hostPilote, "ssl": true,
		"tlscert":  "/CN=" + leaf.Subject.CommonName,
		"tlskey":   "EC private key - 256 bits",
		"validity": leaf.NotAfter.In(paris).Format("2006-01-02T15:04:05.000-07:00"),
	}})
}

type fauxLecteur struct {
	mu     sync.Mutex
	doms   map[string][]Domain
	err    map[string]error
	appels []string
}

func (f *fauxLecteur) DomainesTLS(_ context.Context, region, app string) ([]Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := region + "/" + app
	f.appels = append(f.appels, k)
	if e := f.err[k]; e != nil {
		return nil, e
	}
	return f.doms[k], nil
}

type fauxCopieur struct {
	contenu map[string][]byte
	err     map[string]error
}

func (f fauxCopieur) copier(_ context.Context, vm string) ([]byte, error) {
	if e := f.err[vm]; e != nil {
		return nil, e
	}
	if b, ok := f.contenu[vm]; ok {
		return b, nil
	}
	return nil, errors.New("VM inconnue du faux copieur")
}

func cfgTest(t *testing.T, f *fauxFGP) Config {
	t.Helper()
	return Config{
		State:     t.TempDir(),
		FGPURL:    f.srv.URL,
		FGPKey:    testCleFGP,
		Ecriture:  map[string]map[string]string{"osc-fr1": {"waf-pilote": testBlob}},
		Roots:     lePKI(t).pool,
		transport: f.srv.Client().Transport,
	}
}

// Faux serveur SSH.

type fauxSSH struct {
	addr      netip.AddrPort
	cleHote   []ssh.Signer
	mode      string
	contenu   []byte
	mu        sync.Mutex
	commandes []string
	users     []string
	sessions  int
	fin       chan struct{}
}

func signerEd25519(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signerECDSA(t *testing.T) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ecKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func demarrerSSH(t *testing.T, client ssh.PublicKey, mode string, contenu []byte, cleHote ...ssh.Signer) *fauxSSH {
	t.Helper()
	f := &fauxSSH{cleHote: cleHote, mode: mode, contenu: contenu, fin: make(chan struct{})}
	t.Cleanup(func() { close(f.fin) })
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(k.Marshal(), client.Marshal()) {
				return nil, errors.New("clé refusée")
			}
			f.mu.Lock()
			f.users = append(f.users, c.User())
			f.mu.Unlock()
			return nil, nil
		},
	}
	for _, h := range cleHote {
		cfg.AddHostKey(h)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = netip.MustParseAddrPort(ln.Addr().String())
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.servir(nc, cfg)
		}
	}()
	return f
}

func (f *fauxSSH) servir(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.sessions++
		f.mu.Unlock()
		go f.session(ch, creqs)
	}
}

func (f *fauxSSH) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		f.mu.Lock()
		f.commandes = append(f.commandes, p.Command)
		f.mu.Unlock()
		_ = req.Reply(true, nil)
		status := 0
		switch f.mode {
		case "force":
			_, _ = ch.Write(f.contenu)
		case "libre":
			// Pas de commande forcée : un shell exécute la demande.
			status = 127
			switch {
			case strings.HasPrefix(p.Command, "exit "):
				if n, err := strconv.Atoi(strings.TrimPrefix(p.Command, "exit ")); err == nil {
					status = n
				}
			case strings.HasPrefix(p.Command, "cat "):
				_, _ = ch.Write(f.contenu)
				status = 0
			}
		case "gros":
			bloc := bytes.Repeat([]byte("x"), 64<<10)
			for n := 0; n <= maxAcme; n += len(bloc) {
				if _, err := ch.Write(bloc); err != nil {
					return
				}
			}
		case "echec":
			_, _ = ch.Stderr().Write([]byte("cat: secret-de-stderr-qui-ne-doit-pas-sortir"))
			status = 1
		case "vide":
		case "muet":
			<-f.fin
			return
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}

func (f *fauxSSH) vu() (commandes, users []string, sessions int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commandes...), append([]string(nil), f.users...), f.sessions
}

func cfgSSH(client ssh.Signer, srv *fauxSSH, pinned ...ssh.PublicKey) Config {
	ip := srv.addr.Addr()
	return Config{
		Signer:     client,
		VMs:        map[string]netip.Addr{"preprod": ip},
		KnownHosts: map[netip.Addr][]ssh.PublicKey{ip: pinned},
		sshPort:    int(srv.addr.Port()),
	}
}
