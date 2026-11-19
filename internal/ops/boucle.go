package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
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

// PulseBody : « waf-ops-ok », ou « waf-ops-ko: » suivi des raisons. Le check
// updown attend « waf-ops-ok », que la forme KO ne contient pas.
func PulseBody(r Rapport, err error) string {
	var raisons []string
	if err != nil {
		raisons = append(raisons, err.Error())
	}
	raisons = append(raisons, r.Ecarts...)
	if len(raisons) == 0 {
		return PulseOK
	}
	b := pulseKO + strings.Join(raisons, " ; ")
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

// Etat est écrit après chaque passage dans le dossier d'état, pour docker exec et
// pour les contrôles qui suivront (curseur d'Activity de l'audit).
type Etat struct {
	Controle EtatControle `json:"controle"`
}

type EtatControle struct {
	A      time.Time `json:"a"`
	Apps   int       `json:"apps"`
	Ecarts []string  `json:"ecarts"`
	Notes  []string  `json:"notes"`
	Erreur string    `json:"erreur,omitempty"`
	Pulse  string    `json:"pulse"`
}

func writeEtat(dir string, e Etat) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, etatFile), append(b, '\n'), 0o600)
}

// Passage fait un contrôle, envoie le pulse et écrit l'état. Pendant un arrêt,
// le pulse n'est pas envoyé : un passage coupé n'est pas un écart.
func Passage(ctx context.Context, cfg Config, d Deps, p Pulser, logf func(string, ...any)) {
	rctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	r, err := Controle(rctx, cfg, d)
	body := PulseBody(r, err)
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
	pulse := "non envoyé"
	if ctx.Err() == nil {
		if perr := p.Send(ctx, body); perr != nil {
			logf("%v", perr)
		} else if body == PulseOK {
			pulse = PulseOK
		} else {
			pulse = "waf-ops-ko"
		}
	}
	e := Etat{Controle: EtatControle{A: d.Now().UTC(), Apps: r.Apps, Ecarts: r.Ecarts, Notes: r.Notes, Pulse: pulse}}
	if e.Controle.Ecarts == nil {
		e.Controle.Ecarts = []string{}
	}
	if e.Controle.Notes == nil {
		e.Controle.Notes = []string{}
	}
	if err != nil {
		e.Controle.Erreur = err.Error()
	}
	if werr := writeEtat(cfg.State, e); werr != nil {
		logf("état non écrit : %v", werr)
	}
}

// Boucle fait un passage tout de suite, puis toutes les interval, jusqu'à
// l'annulation de ctx.
func Boucle(ctx context.Context, cfg Config, d Deps, p Pulser, logf func(string, ...any), interval time.Duration) {
	Passage(ctx, cfg, d, p, logf)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Passage(ctx, cfg, d, p, logf)
		}
	}
}
