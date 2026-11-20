package certs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Sous ce délai avant expiration, un certificat est un écart (section 3.7 du design).
const seuil = 21 * 24 * time.Hour

// VM : une VM WAF de l'inventaire.
type VM struct {
	Name  string
	Stage string
}

// App : une app live sur Scalingo d'un stage traité. Scalingo et Region sont
// lues par l'appelant dans UPSTREAM_<APP>.
type App struct {
	Name     string
	Stage    string
	Hosts    []string
	Scalingo string
	Region   string
}

type Deps struct {
	Lecteur Lecteur
	Now     func() time.Time

	copieur  copieur
	ecrivain ecrivain
}

type passage struct {
	ecarts, notes []string
}

const (
	maxEcart = 300
	maxNote  = 1000
)

func (p *passage) ecart(qui, format string, a ...any) {
	p.ecarts = append(p.ecarts, propre(qui+" : "+fmt.Sprintf(format, a...), maxEcart))
}

func (p *passage) note(qui, format string, a ...any) {
	p.notes = append(p.notes, propre(qui+" : "+fmt.Sprintf(format, a...), maxNote))
}

// propre rend une ligne bornée sans caractère de contrôle. Les erreurs reprises
// portent du texte venu d'ailleurs (noms d'un certificat présenté à la place de
// FGP, erreur du lecteur) : un retour à la ligne y forgerait une entrée de log.
func propre(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// Quotidien copie acme.json de chaque VM, puis, pour chaque app, pousse sur
// chacun de ses domaines Scalingo qui est un de ses hosts le certificat de la
// VM de son stage, quand Scalingo n'en porte pas déjà la même version. Une app
// sans domaine Scalingo est sautée sans écart. Un écart est une phrase courte
// pour le pulse, une note un détail pour les logs et l'état. err ne sert qu'aux
// entrées invalides et à l'arrêt.
func Quotidien(ctx context.Context, cfg Config, vms []VM, apps []App, d Deps) (ecarts, notes []string, err error) {
	if d.Lecteur == nil {
		return nil, nil, errors.New("certificats : lecteur de domaines absent")
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	cp, ec := d.copieur, d.ecrivain
	if cp == nil {
		cp = sshCopieur{cfg: cfg}
	}
	if ec == nil {
		ec = fgpEcrivain{cfg: cfg}
	}
	vms = append([]VM(nil), vms...)
	sort.Slice(vms, func(i, j int) bool { return vms[i].Name < vms[j].Name })
	for i, v := range vms {
		if !reVM.MatchString(v.Name) {
			return nil, nil, fmt.Errorf("certificats : nom de VM %q invalide", assaini(v.Name))
		}
		if i > 0 && vms[i-1].Name == v.Name {
			return nil, nil, fmt.Errorf("certificats : VM %s en double", v.Name)
		}
	}
	apps = append([]App(nil), apps...)
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })

	var p passage
	frais := map[string][]certificat{}
	for _, v := range vms {
		if err := ctx.Err(); err != nil {
			return p.ecarts, p.notes, err
		}
		qui := "vm " + v.Name
		raw, err := cp.copier(ctx, v.Name)
		if err != nil {
			p.ecart(qui, "acme.json non copié : %v", err)
			continue
		}
		certs, cnotes, err := parseAcme(raw, v.Name)
		if err != nil {
			p.ecart(qui, "%v", err)
			continue
		}
		if path, err := sauver(cfg.State, v.Name, now(), raw); err != nil {
			p.ecart(qui, "copie d'acme.json non écrite : %v", err)
		} else {
			p.note(qui, "acme.json copié dans %s, %d certificat(s) lisible(s)", path, len(certs))
		}
		for _, n := range cnotes {
			p.note(qui, "%s", n)
		}
		frais[v.Name] = certs
	}
	for _, a := range apps {
		if err := ctx.Err(); err != nil {
			return p.ecarts, p.notes, err
		}
		pousserApp(ctx, cfg, d.Lecteur, ec, now(), vms, frais, a, &p)
	}
	return p.ecarts, p.notes, nil
}

func pousserApp(ctx context.Context, cfg Config, lec Lecteur, ec ecrivain, now time.Time, vms []VM, frais map[string][]certificat, a App, p *passage) {
	if !reApp.MatchString(a.Scalingo) || !reRegion.MatchString(a.Region) {
		p.ecart(a.Name, "app Scalingo ou région invalide")
		return
	}
	where := a.Scalingo + " (" + a.Region + ")"
	var certs []certificat
	var stage, manquantes []string
	for _, v := range vms {
		if v.Stage != a.Stage {
			continue
		}
		stage = append(stage, v.Name)
		if c, ok := frais[v.Name]; ok {
			certs = append(certs, c...)
		} else {
			manquantes = append(manquantes, v.Name)
		}
	}
	if len(stage) == 0 {
		p.ecart(a.Name, "aucune VM du stage %s, certificat non poussé", a.Stage)
		return
	}
	doms, err := lec.DomainesTLS(ctx, a.Region, a.Scalingo)
	if err != nil {
		p.ecart(a.Name, "domaines de %s : %v", where, err)
		return
	}
	hosts := map[string]bool{}
	for _, h := range a.Hosts {
		hosts[normHost(h)] = true
	}
	var rel []Domain
	for _, dm := range doms {
		if hosts[normHost(dm.Name)] {
			rel = append(rel, dm)
		}
	}
	if len(rel) == 0 {
		p.note(a.Name, "aucun de ses hosts sur %s, rien à pousser", where)
		return
	}
	sort.Slice(rel, func(i, j int) bool { return normHost(rel[i].Name) < normHost(rel[j].Name) })
	_, blob := cfg.Ecriture[a.Region][a.Scalingo]
	if !blob {
		p.ecart(a.Name, "aucun blob FGP d'écriture pour %s, certificat non poussé", where)
	}
	for _, dm := range rel {
		host := normHost(dm.Name)
		// Une copie lue mais sans certificat utilisable n'est pas une copie
		// manquante : elle passe par choisir, qui en fait un écart.
		if len(certs) == 0 && len(manquantes) > 0 {
			p.note(a.Name, "%s : pas de copie d'acme.json de %s ce jour, poussée sautée", host, strings.Join(manquantes, ", "))
			expirationScalingo(p, a.Name, host, where, dm, now)
			continue
		}
		pousserDomaine(ctx, ec, now, a, where, host, dm, certs, blob, cfg, p)
	}
}

func pousserDomaine(ctx context.Context, ec ecrivain, now time.Time, a App, where, host string, dm Domain, certs []certificat, blob bool, cfg Config, p *passage) {
	best, raison := choisir(certs, host, now, cfg.Roots)
	if best == nil {
		p.ecart(a.Name, "%s dans acme.json du stage %s", raison, a.Stage)
		expirationScalingo(p, a.Name, host, where, dm, now)
		return
	}
	fin := best.feuille.NotAfter
	if fin.Sub(now) < seuil {
		p.ecart(a.Name, "certificat de %s dans acme.json de %s expire le %s", host, best.VM, jour(fin))
	}
	if identique(dm, best) {
		p.note(a.Name, "%s : certificat à jour sur %s, expire le %s", host, where, jour(fin))
		return
	}
	if dm.SSL && dm.Validity.After(fin) {
		p.note(a.Name, "%s : %s porte un certificat qui expire le %s, après celui d'acme.json, pas de poussée", host, where, jour(dm.Validity.Time))
		expirationScalingo(p, a.Name, host, where, dm, now)
		return
	}
	if !blob {
		expirationScalingo(p, a.Name, host, where, dm, now)
		return
	}
	res, err := ec.poser(ctx, a.Region, a.Scalingo, dm.ID, best.chaine, best.cle)
	if err != nil {
		p.ecart(a.Name, "certificat de %s non poussé sur %s : %s", host, where, probleme(err))
		p.note(a.Name, "%s : détail : %v", host, err)
		expirationScalingo(p, a.Name, host, where, dm, now)
		return
	}
	if !res.SSL || !res.Validity.Equal(fin) {
		p.ecart(a.Name, "certificat de %s poussé sur %s, qui annonce une fin de validité au %s au lieu du %s", host, where, jourOuAucune(res.Validity.Time), jour(fin))
		return
	}
	p.note(a.Name, "%s : certificat de %s poussé sur %s, expire le %s", host, best.VM, where, jour(fin))
}

// identique compare ce que l'API Scalingo dit du certificat posé (sujet et fin
// de validité, à la seconde) au certificat d'acme.json. Deux émissions Let's
// Encrypt ne partagent pas la même fin de validité.
func identique(dm Domain, c *certificat) bool {
	return dm.SSL && !dm.Validity.IsZero() && dm.Validity.Equal(c.feuille.NotAfter) &&
		strings.EqualFold(cnSujet(dm.TLSCert), c.feuille.Subject.CommonName)
}

var reCN = regexp.MustCompile(`(?:^|[/,])\s*CN\s*=\s*([^/,]*)`)

// cnSujet lit le CN du sujet que Scalingo rend dans tlscert, de la forme
// « /C=FR/O=…/CN=example.com ».
func cnSujet(s string) string {
	m := reCN.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func expirationScalingo(p *passage, app, host, where string, dm Domain, now time.Time) {
	if dm.SSL && !dm.Validity.IsZero() && dm.Validity.Sub(now) < seuil {
		p.ecart(app, "certificat de %s sur %s expire le %s", host, where, jour(dm.Validity.Time))
	}
}

func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func jourOuAucune(t time.Time) string {
	if t.IsZero() {
		return "aucune date"
	}
	return jour(t)
}

func probleme(err error) string {
	var fe *ErreurFGP
	switch {
	case errors.Is(err, ErrInjoignable):
		return "FGP injoignable"
	case errors.Is(err, ErrSansBlob):
		return ErrSansBlob.Error()
	case errors.As(err, &fe):
		return fe.Error()
	}
	return err.Error()
}
