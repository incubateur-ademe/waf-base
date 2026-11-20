package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Interval     = 5 * time.Minute
	PulseOK      = "waf-ops-ok"
	pulseKO      = "waf-ops-ko: "
	maxPulseBody = 2000
	// Un passage qui dépasse ce délai est coupé : le suivant repart à l'heure.
	runTimeout = 2 * time.Minute
	etatFile   = "etat.json"
)

// Le check updown cherche « waf-ops-ok » n'importe où dans le corps, sans
// tenir compte de la casse. Les raisons reprennent des valeurs venues de
// l'extérieur (UPSTREAM, inventaire, erreurs) : le marqueur y est cassé, sans
// quoi un corps KO passerait pour OK.
var rePulseOK = regexp.MustCompile(`(?i)waf-ops-ok`)

// PulseBody : « waf-ops-ok », ou « waf-ops-ko: » suivi des raisons : erreur et
// écarts du contrôle, puis celles des tâches.
func PulseBody(r Rapport, err error, taches ...string) string {
	var raisons []string
	if err != nil {
		raisons = append(raisons, err.Error())
	}
	raisons = append(raisons, r.Ecarts...)
	raisons = append(raisons, taches...)
	if len(raisons) == 0 {
		return PulseOK
	}
	b := pulseKO + rePulseOK.ReplaceAllString(strings.Join(raisons, " ; "), "waf-ops-o?k")
	if len(b) <= maxPulseBody {
		return b
	}
	cut := maxPulseBody - len("…")
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut] + "…"
}

type Pulser interface {
	Send(ctx context.Context, body string) error
}

// HTTPPulse envoie le corps à l'URL privée du check pulse. L'URL est un secret :
// elle n'entre dans aucune erreur.
type HTTPPulse struct {
	URL  string
	HTTP *http.Client
}

func (p HTTPPulse) Send(ctx context.Context, body string) error {
	c := p.HTTP
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, strings.NewReader(body))
	if err != nil {
		return errors.New("pulse : requête invalide")
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("pulse : %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("pulse : HTTP %d", resp.StatusCode)
	}
	return nil
}

// Etat est écrit après chaque passage dans le dossier d'état, pour docker exec,
// et relu au démarrage : les tâches reprennent leur rythme et leurs curseurs.
type Etat struct {
	Controle EtatControle         `json:"controle"`
	Taches   map[string]EtatTache `json:"taches,omitempty"`
}

type EtatControle struct {
	A      time.Time `json:"a"`
	Apps   int       `json:"apps"`
	Ecarts []string  `json:"ecarts"`
	Notes  []string  `json:"notes"`
	Erreur string    `json:"erreur,omitempty"`
	Pulse  string    `json:"pulse"`
}

type EtatTache struct {
	A        time.Time            `json:"a"`
	Apps     int                  `json:"apps"`
	Ecarts   []string             `json:"ecarts"`
	Notes    []string             `json:"notes"`
	Erreur   string               `json:"erreur,omitempty"`
	Curseurs map[string]time.Time `json:"curseurs,omitempty"`
}

func writeEtat(dir string, e Etat) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, etatFile), append(b, '\n'), 0o600)
}

// LireEtat rend l'état écrit par la boucle, vide s'il n'existe pas encore.
func LireEtat(dir string) (Etat, error) {
	b, err := os.ReadFile(filepath.Join(dir, etatFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Etat{}, nil
	}
	if err != nil {
		return Etat{}, err
	}
	var e Etat
	if err := json.Unmarshal(b, &e); err != nil {
		return Etat{}, fmt.Errorf("%s : JSON invalide", etatFile)
	}
	return e, nil
}

// Tache est un contrôle moins fréquent que celui des 5 minutes, lancé par la
// boucle quand sa période est écoulée. Ses écarts restent dans le pulse jusqu'à
// son passage suivant : un écart corrigé entre deux passages donne une alerte
// DOWN, puis UP au passage suivant. Run reçoit les curseurs gardés de son
// passage précédent et rend ceux à garder, même en erreur ; nil les laisse
// tels quels.
type Tache struct {
	Nom     string
	Periode time.Duration
	Delai   time.Duration
	Run     func(ctx context.Context, curseurs map[string]time.Time) (Rapport, map[string]time.Time, error)
}

// Une tâche en échec est relancée sans attendre sa période.
const relanceTache = 15 * time.Minute

func (t Tache) due(e EtatTache, ok bool, now time.Time) bool {
	if !ok || e.A.IsZero() || now.Before(e.A) {
		return true
	}
	p := t.Periode
	if e.Erreur != "" && relanceTache < p {
		p = relanceTache
	}
	return now.Sub(e.A) >= p
}

const (
	PeriodeAudit = time.Hour
	delaiAudit   = 4 * time.Minute
)

// TacheAudit : l'audit horaire.
func TacheAudit(cfg Config, d Deps) Tache {
	return Tache{Nom: "audit", Periode: PeriodeAudit, Delai: delaiAudit, Run: func(ctx context.Context, c map[string]time.Time) (Rapport, map[string]time.Time, error) {
		return Audit(ctx, cfg, d, c)
	}}
}

// raisonsTaches : erreur et écarts de la dernière exécution de chaque tâche.
func raisonsTaches(ts []Tache, etat map[string]EtatTache) []string {
	var out []string
	for _, t := range ts {
		e, ok := etat[t.Nom]
		if !ok {
			continue
		}
		if e.Erreur != "" {
			out = append(out, t.Nom+" en échec : "+e.Erreur)
		}
		for _, x := range e.Ecarts {
			out = append(out, t.Nom+" : "+x)
		}
	}
	return out
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// Runner tient l'état de la boucle entre deux passages.
type Runner struct {
	Cfg    Config
	Deps   Deps
	Pulse  Pulser
	Logf   func(string, ...any)
	Taches []Tache
	etat   *Etat
	// Un état illisible au démarrage a fait perdre les curseurs : l'alerte
	// reste dans le pulse pendant une période d'audit.
	alerte       string
	alerteJusqua time.Time
}

func (o *Runner) charger() {
	if o.etat != nil {
		return
	}
	e, err := LireEtat(o.Cfg.State)
	if err != nil {
		now := o.Deps.Now().UTC()
		garde := fmt.Sprintf("%s.illisible-%s", etatFile, now.Format("20060102T150405Z"))
		if rerr := os.Rename(filepath.Join(o.Cfg.State, etatFile), filepath.Join(o.Cfg.State, garde)); rerr != nil {
			garde = "non gardé"
		}
		o.alerte = fmt.Sprintf("état illisible au démarrage (%s), curseurs d'Activity perdus : Activity relue sur %s seulement", garde, activiteSansCurseur)
		o.alerteJusqua = now.Add(PeriodeAudit)
		o.Logf("état illisible, repris à vide : %v ; fichier %s", err, garde)
	}
	o.etat = &e
}

// Passage fait le contrôle et les tâches dues, envoie le pulse et écrit l'état.
// Un passage coupé par l'arrêt n'est pas un écart : ni pulse, ni état, ni
// écarts dans les logs.
func (o *Runner) Passage(ctx context.Context) {
	o.charger()
	logf := o.Logf
	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	r, err := Controle(rctx, o.Cfg, o.Deps)
	cancel()
	if ctx.Err() != nil {
		logf("arrêt pendant le contrôle : passage abandonné, ni pulse ni état")
		return
	}
	taches := map[string]EtatTache{}
	for k, v := range o.etat.Taches {
		taches[k] = v
	}
	type fait struct {
		nom string
		r   Rapport
		err error
	}
	var faits []fait
	for _, t := range o.Taches {
		prev, ok := taches[t.Nom]
		now := o.Deps.Now()
		if !t.due(prev, ok, now) {
			continue
		}
		tctx, tcancel := context.WithTimeout(ctx, t.Delai)
		tr, cur, terr := t.Run(tctx, prev.Curseurs)
		if terr != nil && tctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			terr = fmt.Errorf("délai de %s dépassé : %v", t.Delai, terr)
		}
		tcancel()
		if ctx.Err() != nil {
			logf("arrêt pendant %s : passage abandonné, ni pulse ni état", t.Nom)
			return
		}
		e := EtatTache{A: now.UTC(), Apps: tr.Apps, Ecarts: nonNil(tr.Ecarts), Notes: nonNil(tr.Notes), Curseurs: cur}
		if cur == nil {
			e.Curseurs = prev.Curseurs
		}
		if terr != nil {
			e.Erreur = terr.Error()
		}
		taches[t.Nom] = e
		faits = append(faits, fait{t.Nom, tr, terr})
	}
	raisons := raisonsTaches(o.Taches, taches)
	if o.alerte != "" && o.Deps.Now().Before(o.alerteJusqua) {
		raisons = append(raisons, o.alerte)
	}
	body := PulseBody(r, err, raisons...)
	for _, n := range r.Notes {
		logf("note : %s", n)
	}
	for _, e := range r.Ecarts {
		logf("écart : %s", e)
	}
	if err != nil {
		logf("contrôle en échec : %v", err)
	}
	logf("contrôle : %d app(s), %d écart(s)", r.Apps, len(r.Ecarts))
	for _, f := range faits {
		for _, n := range f.r.Notes {
			logf("%s : note : %s", f.nom, n)
		}
		for _, e := range f.r.Ecarts {
			logf("%s : écart : %s", f.nom, e)
		}
		if f.err != nil {
			logf("%s en échec : %v", f.nom, f.err)
		}
		logf("%s : %d app(s), %d écart(s)", f.nom, f.r.Apps, len(f.r.Ecarts))
	}
	ran := map[string]bool{}
	for _, f := range faits {
		ran[f.nom] = true
	}
	for _, t := range o.Taches {
		e, ok := taches[t.Nom]
		if ok && !ran[t.Nom] && (len(e.Ecarts) > 0 || e.Erreur != "") {
			logf("%s du %s : %d écart(s)%s gardé(s) dans le pulse jusqu'au passage suivant", t.Nom, e.A.UTC().Format(time.RFC3339), len(e.Ecarts), map[bool]string{true: " et une erreur", false: ""}[e.Erreur != ""])
		}
	}
	pulse := "non envoyé"
	if perr := o.Pulse.Send(ctx, body); perr != nil {
		logf("%v", perr)
	} else if body == PulseOK {
		pulse = PulseOK
	} else {
		pulse = "waf-ops-ko"
	}
	c := EtatControle{A: o.Deps.Now().UTC(), Apps: r.Apps, Ecarts: nonNil(r.Ecarts), Notes: nonNil(r.Notes), Pulse: pulse}
	if err != nil {
		c.Erreur = err.Error()
	}
	o.etat.Controle = c
	o.etat.Taches = taches
	if werr := writeEtat(o.Cfg.State, *o.etat); werr != nil {
		logf("état non écrit : %v", werr)
	}
}

// Passage fait un passage sans tâche, l'état relu sur le disque.
func Passage(ctx context.Context, cfg Config, d Deps, p Pulser, logf func(string, ...any)) {
	(&Runner{Cfg: cfg, Deps: d, Pulse: p, Logf: logf}).Passage(ctx)
}

// Boucle fait un passage tout de suite, puis toutes les interval, jusqu'à
// l'annulation de ctx.
func (o *Runner) Boucle(ctx context.Context, interval time.Duration) {
	o.Passage(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.Passage(ctx)
		}
	}
}
