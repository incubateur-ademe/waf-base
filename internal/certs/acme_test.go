package certs

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseAcme(t *testing.T) {
	p := lePKI(t)
	ec := p.feuille(t, optsFeuille{cn: "a.example.org"})
	rs := p.feuille(t, optsFeuille{cn: "b.example.org", cle: "rsa"})
	p8 := p.feuille(t, optsFeuille{cn: "c.example.org", cle: "pkcs8"})
	autre := p.feuille(t, optsFeuille{cn: "d.example.org"})
	chiffree := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("x")})
	blkCle, _ := pem.Decode(ec.cle)
	cleEnTete := pem.EncodeToMemory(&pem.Block{Type: blkCle.Type, Headers: map[string]string{"Comment": "x"}, Bytes: blkCle.Bytes})
	blkCert, _ := pem.Decode(ec.chaine)
	chaineEnTete := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "x"}, Bytes: blkCert.Bytes})
	blkP8, _ := pem.Decode(p8.cle)
	clePKCS8Chiffree := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: blkP8.Bytes})
	raw := acmeJSON(t, "letsencrypt",
		entree{main: "a.example.org", cert: ec.chaine, key: ec.cle},
		entree{main: "b.example.org", cert: rs.chaine, key: rs.cle},
		entree{main: "c.example.org", cert: p8.chaine, key: p8.cle},
		entree{main: "d.example.org", cert: autre.chaine, key: ec.cle},
		entree{main: "e.example.org", cert: ec.chaine, key: chiffree},
		entree{main: "f.example.org", certB64: "%%%", key: ec.cle},
		entree{main: "g.example.org\nfausse ligne", cert: ec.chaine, keyB64: "!!"},
		entree{main: "h.example.org", cert: []byte("pas du PEM"), key: ec.cle},
		entree{main: "i.example.org", cert: ec.chaine, key: cleEnTete},
		entree{main: "j.example.org", cert: chaineEnTete, key: ec.cle},
		entree{main: "k.example.org", cert: p8.chaine, key: clePKCS8Chiffree},
		entree{main: "l.example.org", cert: ec.chaine, key: append(append([]byte{}, ec.cle...), ec.cle...)},
	)
	certs, notes, err := parseAcme(raw, "preprod")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("%d certificats lus, 3 attendus ; notes %q", len(certs), notes)
	}
	for i, cn := range []string{"a.example.org", "b.example.org", "c.example.org"} {
		c := certs[i]
		if c.feuille.Subject.CommonName != cn || c.VM != "preprod" {
			t.Errorf("certificat %d : %s sur %s", i, c.feuille.Subject.CommonName, c.VM)
		}
		if !bytes.HasPrefix(c.chaine, []byte("-----BEGIN CERTIFICATE-----\n")) || len(c.inter) != 1 {
			t.Errorf("chaîne de %s mal relue", cn)
		}
		if !strings.HasPrefix(c.cle.clair(), "-----BEGIN ") {
			t.Errorf("clé de %s mal relue", cn)
		}
	}
	if len(notes) != 9 {
		t.Errorf("notes %q, 9 attendues", notes)
	}
	for _, n := range notes {
		if strings.ContainsAny(n, "\n\r") {
			t.Errorf("note sur plusieurs lignes : %q", n)
		}
	}
	sansSecret(t, "notes", notes, secrets(ec.cle, rs.cle, p8.cle))
}

func TestParseAcmeRefus(t *testing.T) {
	p := lePKI(t)
	e := p.feuille(t, optsFeuille{cn: "a.example.org"})
	if _, _, err := parseAcme(acmeJSON(t, "autre", entree{cert: e.chaine, key: e.cle}), "1"); err == nil || !strings.Contains(err.Error(), "letsencrypt absent") {
		t.Errorf("résolveur absent : %v", err)
	}
	casse := []byte(`{"letsencrypt": {"Certificates": [{"key": "` + string(e.cle) + `"`)
	_, _, err := parseAcme(casse, "1")
	if err == nil {
		t.Fatal("JSON cassé accepté")
	}
	sansSecret(t, "erreur", []string{err.Error()}, secrets(e.cle))
	if certs, _, err := parseAcme([]byte(`{"letsencrypt": {"Certificates": null}}`), "1"); err != nil || len(certs) != 0 {
		t.Errorf("aucun certificat : %v, %d", err, len(certs))
	}
}

func TestChoisir(t *testing.T) {
	p := lePKI(t)
	autreAC := nouvellePKI(t, "Inconnue")
	ancien := p.feuille(t, optsFeuille{cn: "a.example.org", notAfter: maintenant.Add(30 * 24 * time.Hour)})
	recent := p.feuille(t, optsFeuille{cn: "a.example.org", dns: []string{"a.example.org", "www.a.example.org"}, notAfter: maintenant.Add(85 * 24 * time.Hour)})
	horsAC := autreAC.feuille(t, optsFeuille{cn: "a.example.org", notAfter: maintenant.Add(89 * 24 * time.Hour)})
	expire := p.feuille(t, optsFeuille{cn: "b.example.org", notBefore: maintenant.Add(-100 * 24 * time.Hour), notAfter: maintenant.Add(-24 * time.Hour)})
	futur := p.feuille(t, optsFeuille{cn: "c.example.org", notBefore: maintenant.Add(24 * time.Hour)})
	joker := p.feuille(t, optsFeuille{cn: "*.d.example.org"})
	var certs []certificat
	for _, e := range []emis{ancien, recent, horsAC, expire, futur, joker} {
		cs, _, err := parseAcme(acmeJSON(t, "letsencrypt", entree{cert: e.chaine, key: e.cle}), "1")
		if err != nil || len(cs) != 1 {
			t.Fatalf("%v %d", err, len(cs))
		}
		certs = append(certs, cs...)
	}
	cas := []struct {
		host, raison string
		fin          time.Time
	}{
		{host: "a.example.org", fin: recent.leaf.NotAfter},
		{host: "www.a.example.org", fin: recent.leaf.NotAfter},
		{host: "x.d.example.org", fin: joker.leaf.NotAfter},
		{host: "b.example.org", raison: "expiré le 2026-11-19"},
		{host: "c.example.org", raison: "pas encore valide"},
		{host: "z.example.org", raison: "aucun certificat pour z.example.org"},
		{host: "d.example.org", raison: "aucun certificat pour"},
	}
	for _, c := range cas {
		got, raison := choisir(certs, c.host, maintenant, p.pool)
		if c.raison != "" {
			if got != nil || !strings.Contains(raison, c.raison) {
				t.Errorf("%s : %v, raison %q, %q attendue", c.host, got != nil, raison, c.raison)
			}
			continue
		}
		if got == nil || !got.feuille.NotAfter.Equal(c.fin) {
			t.Errorf("%s : %v (%s)", c.host, got != nil, raison)
		}
	}
	// Seul un certificat d'une autre AC couvre le host : refusé.
	seul := certs[2:3]
	if got, raison := choisir(seul, "a.example.org", maintenant, p.pool); got != nil || !strings.Contains(raison, "autorité inconnue") {
		t.Errorf("AC inconnue : %v, %q", got != nil, raison)
	}
}

// La clé ne sort par aucune mise en forme, directe ou imbriquée.
func TestCleMasquee(t *testing.T) {
	p := lePKI(t)
	e := p.feuille(t, optsFeuille{cn: "a.example.org"})
	cs, _, err := parseAcme(acmeJSON(t, "letsencrypt", entree{cert: e.chaine, key: e.cle}), "1")
	if err != nil || len(cs) != 1 {
		t.Fatal(err)
	}
	c := cs[0]
	type enveloppe struct {
		interne certificat
		Public  certificat
		liste   []certificat
		ptr     *certificat
	}
	env := enveloppe{interne: c, Public: c, liste: cs, ptr: &c}
	var sorties []string
	for _, v := range []any{c.cle, *c.cle, c, &c, cs, env, &env, map[string]certificat{"a": c}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			sorties = append(sorties, fmt.Sprintf(verb, v))
		}
		b, _ := json.Marshal(v)
		sorties = append(sorties, string(b))
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "v", v)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "v", v)
		sorties = append(sorties, buf.String())
	}
	sansSecret(t, "mise en forme", sorties, secrets(e.cle))
	if fmt.Sprint(c.cle) != cleMasquee {
		t.Errorf("clé affichée %q", fmt.Sprint(c.cle))
	}
}
