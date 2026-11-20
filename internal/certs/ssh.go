package certs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	utilisateurSSH = "root"
	delaiSSH       = time.Minute
	maxAcme        = 8 << 20
	// La clé force « cat /data/coolify/proxy/acme.json » (authorized_keys2), qui
	// tourne quelle que soit la commande demandée. La commande demandée sort en
	// 97 : une VM qui rend 97 a exécuté la demande, donc la clé n'y est pas
	// restreinte.
	commandeDemandee = "exit 97"
	sortieNonForcee  = 97
)

// ErrNonForcee : la VM a exécuté la commande demandée au lieu de la commande
// forcée par authorized_keys2. La clé y vaut alors un accès root.
var ErrNonForcee = errors.New("clé sans commande forcée sur la VM, accès root ouvert")

type copieur interface {
	copier(ctx context.Context, vm string) ([]byte, error)
}

type sshCopieur struct{ cfg Config }

// copier lit acme.json de la VM par SSH sur le Private Network, clé d'hôte
// épinglée par la config. Ni la sortie d'erreur de la VM ni un morceau de la
// sortie n'entrent dans une erreur.
func (s sshCopieur) copier(ctx context.Context, vm string) ([]byte, error) {
	ip, ok := s.cfg.VMs[vm]
	if !ok {
		return nil, fmt.Errorf("pas d'IP privée pour la VM dans %s", EnvVMs)
	}
	pinned := s.cfg.KnownHosts[ip]
	if len(pinned) == 0 {
		return nil, fmt.Errorf("aucune clé d'hôte épinglée pour %s", ip)
	}
	if s.cfg.Signer == nil {
		return nil, errors.New("clé SSH absente")
	}
	ctx, cancel := context.WithTimeout(ctx, delaiSSH)
	defer cancel()
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(s.cfg.port()))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connexion à %s : %v", addr, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              utilisateurSSH,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(s.cfg.Signer)},
		HostKeyCallback:   epingle(ip, pinned),
		HostKeyAlgorithms: algos(pinned),
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("SSH vers %s : délai dépassé", addr)
		}
		var he *hoteInconnu
		if errors.As(err, &he) {
			return nil, he
		}
		return nil, fmt.Errorf("SSH vers %s : %v", addr, err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH vers %s : session refusée", addr)
	}
	defer sess.Close()
	out := &borne{max: maxAcme}
	sess.Stdout = out
	sess.Stderr = io.Discard
	err = sess.Run(commandeDemandee)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("SSH vers %s : délai dépassé", addr)
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		if ee.ExitStatus() == sortieNonForcee {
			return nil, ErrNonForcee
		}
		return nil, fmt.Errorf("lecture d'acme.json sur %s : sortie %d", addr, ee.ExitStatus())
	}
	if err != nil {
		return nil, fmt.Errorf("lecture d'acme.json sur %s : session interrompue", addr)
	}
	if out.depasse {
		return nil, fmt.Errorf("acme.json de %s : plus de %d octets", addr, maxAcme)
	}
	if out.buf.Len() == 0 {
		return nil, fmt.Errorf("acme.json de %s : vide", addr)
	}
	return out.buf.Bytes(), nil
}

// hoteInconnu : la VM présente une clé d'hôte hors de known_hosts. Seule
// l'empreinte, publique, entre dans le message.
type hoteInconnu struct {
	ip        netip.Addr
	empreinte string
	typeDeCle string
}

func (e *hoteInconnu) Error() string {
	return fmt.Sprintf("clé d'hôte de %s inconnue (%s %s) : refusée", e.ip, e.typeDeCle, e.empreinte)
}

func epingle(ip netip.Addr, pinned []ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, k ssh.PublicKey) error {
		for _, p := range pinned {
			if bytes.Equal(k.Marshal(), p.Marshal()) {
				return nil
			}
		}
		return &hoteInconnu{ip: ip, empreinte: ssh.FingerprintSHA256(k), typeDeCle: k.Type()}
	}
}

// algos limite la négociation aux types de clé épinglés. Sans elle, la VM
// présenterait sa clé d'hôte préférée, d'un autre type, refusée à tort.
func algos(pinned []ssh.PublicKey) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, p := range pinned {
		if p.Type() == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
			continue
		}
		add(p.Type())
	}
	return out
}

// borne garde au plus max octets et jette la suite : une VM qui enverrait sans
// fin est coupée par le délai, pas par la mémoire.
type borne struct {
	buf     bytes.Buffer
	max     int
	depasse bool
}

func (b *borne) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.depasse = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.depasse = true
	}
	return len(p), nil
}
