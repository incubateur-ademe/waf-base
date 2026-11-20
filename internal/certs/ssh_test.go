package certs

import (
	"context"
	"errors"
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
