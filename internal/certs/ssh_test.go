package certs

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCopierCommandeForcee(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "force", []byte(`{"letsencrypt":{}}`), hote)
	b, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(context.Background(), "preprod")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"letsencrypt":{}}` {
		t.Errorf("contenu %q", b)
	}
	cmds, users, _ := srv.vu()
	if len(cmds) != 1 || cmds[0] != "exit 97" {
		t.Errorf("commandes demandées %q, exit 97 attendue", cmds)
	}
	if len(users) != 1 || users[0] != "root" {
		t.Errorf("utilisateur %q, root attendu", users)
	}
}

// Une VM qui exécute la commande demandée a une clé sans command= : accès root.
func TestCopierCommandeNonForcee(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "libre", []byte(`{"letsencrypt":{}}`), hote)
	_, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(context.Background(), "preprod")
	if !errors.Is(err, ErrNonForcee) {
		t.Fatalf("erreur %v, ErrNonForcee attendue", err)
	}
}

// Jamais d'InsecureIgnoreHostKey : une clé d'hôte hors de known_hosts arrête
// tout avant la moindre session.
func TestCopierCleHoteInconnue(t *testing.T) {
	client, hote, autre := signerEd25519(t), signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "force", []byte("{}"), hote)
	_, err := sshCopieur{cfg: cfgSSH(client, srv, autre.PublicKey())}.copier(context.Background(), "preprod")
	var hi *hoteInconnu
	if !errors.As(err, &hi) {
		t.Fatalf("erreur %v, clé d'hôte inconnue attendue", err)
	}
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(hote.PublicKey())) {
		t.Errorf("l'erreur ne cite pas l'empreinte présentée : %v", err)
	}
	if _, users, sessions := srv.vu(); sessions != 0 || len(users) != 0 {
		t.Errorf("%d session(s), %d authentification(s) malgré une clé d'hôte inconnue", sessions, len(users))
	}
}

// La VM a deux clés d'hôte, une seule épinglée : la négociation doit choisir
// celle-là, sans quoi la VM présenterait l'autre, refusée.
func TestCopierTypeEpingle(t *testing.T) {
	client, ed, ec := signerEd25519(t), signerEd25519(t), signerECDSA(t)
	srv := demarrerSSH(t, client.PublicKey(), "force", []byte("{}"), ec, ed)
	if _, err := (sshCopieur{cfg: cfgSSH(client, srv, ed.PublicKey())}).copier(context.Background(), "preprod"); err != nil {
		t.Fatalf("clé ed25519 épinglée, ecdsa présentée ? %v", err)
	}
}

func TestCopierTropGros(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "gros", nil, hote)
	_, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(context.Background(), "preprod")
	if err == nil || !strings.Contains(err.Error(), "plus de") {
		t.Fatalf("erreur %v, taille dépassée attendue", err)
	}
}

func TestCopierEchecSansStderr(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "echec", nil, hote)
	_, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(context.Background(), "preprod")
	if err == nil || !strings.Contains(err.Error(), "sortie 1") {
		t.Fatalf("erreur %v, sortie 1 attendue", err)
	}
	if strings.Contains(err.Error(), "secret-de-stderr") {
		t.Errorf("la sortie d'erreur de la VM entre dans l'erreur : %v", err)
	}
}

// Avant toute vérification de clé d'hôte, un pair quelconque peut envoyer un
// SSH_MSG_DISCONNECT au texte libre : il n'entre pas dans l'erreur.
func TestCopierDeconnexionPiegee(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const piege = "ALERTE waf-1 compromis\nwafgen ops: note : fausse ligne"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-faux\r\n"))
		_, _ = bufio.NewReader(c).ReadString('\n')
		var payload []byte
		payload = append(payload, 1)
		payload = binary.BigEndian.AppendUint32(payload, 2)
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(piege)))
		payload = append(payload, piege...)
		payload = binary.BigEndian.AppendUint32(payload, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
		pkt = append(pkt, byte(pad))
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		time.Sleep(200 * time.Millisecond)
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	cfg := Config{
		Signer:     signerEd25519(t),
		VMs:        map[string]netip.Addr{"preprod": ap.Addr()},
		KnownHosts: map[netip.Addr][]ssh.PublicKey{ap.Addr(): {signerEd25519(t).PublicKey()}},
		sshPort:    int(ap.Port()),
	}
	_, err = sshCopieur{cfg: cfg}.copier(context.Background(), "preprod")
	if err == nil || !strings.Contains(err.Error(), "poignée de main en échec") {
		t.Fatalf("erreur %v", err)
	}
	if strings.Contains(err.Error(), "ALERTE") {
		t.Errorf("texte du pair dans l'erreur : %v", err)
	}
}

func TestCopierAuthRefusee(t *testing.T) {
	client, autre, hote := signerEd25519(t), signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, autre.PublicKey(), "force", []byte("{}"), hote)
	_, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(context.Background(), "preprod")
	if err == nil || !strings.Contains(err.Error(), "authentification refusée") {
		t.Fatalf("erreur %v", err)
	}
}

func TestCopierVide(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "vide", nil, hote)
	if _, err := (sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}).copier(context.Background(), "preprod"); err == nil || !strings.Contains(err.Error(), "vide") {
		t.Fatalf("erreur %v, sortie vide attendue", err)
	}
}

func TestCopierDelai(t *testing.T) {
	client, hote := signerEd25519(t), signerEd25519(t)
	srv := demarrerSSH(t, client.PublicKey(), "muet", nil, hote)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	debut := time.Now()
	_, err := sshCopieur{cfg: cfgSSH(client, srv, hote.PublicKey())}.copier(ctx, "preprod")
	if err == nil || !strings.Contains(err.Error(), "délai") {
		t.Fatalf("erreur %v, délai attendu", err)
	}
	if d := time.Since(debut); d > 5*time.Second {
		t.Errorf("coupé après %s", d)
	}
}

func TestCopierSansConfig(t *testing.T) {
	client := signerEd25519(t)
	ip := netip.MustParseAddr("127.0.0.1")
	c := sshCopieur{cfg: Config{Signer: client, VMs: map[string]netip.Addr{"preprod": ip}}}
	if _, err := c.copier(context.Background(), "1"); err == nil {
		t.Error("VM sans IP privée acceptée")
	}
	if _, err := c.copier(context.Background(), "preprod"); err == nil || !strings.Contains(err.Error(), "épinglée") {
		t.Errorf("VM sans clé d'hôte épinglée : %v", err)
	}
}
