// Package selftest rejoue l'attaque canonique (section 7, couche 4) : déclinée en
// query, formulaire, JSON, cookie et en-tête, elle doit être bloquée par 949110
// ou 19110, jamais par une règle du tenant.
package selftest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/incubateur-ademe/waf-base/internal/lint"
)

// Payload touche quatre familles de la CRS (941, 942, 932, 930) pour qu'une
// exclusion légitime d'une seule famille ne suffise pas à la laisser passer.
const Payload = `<script>alert(1)</script>' UNION SELECT password FROM users-- ;cat /etc/passwd`

var Allowed = map[int]bool{949110: true, 19110: true}

type Variant struct {
	Name        string
	Method      string
	Query       url.Values
	ContentType string
	Body        string
	Headers     map[string]string
}

// Key tire le nom du paramètre de l'attaque : un tenant ne peut pas viser
// d'avance la clé de l'autotest par une exclusion.
func Key() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "c" + hex.EncodeToString(b)
}

// Variants renvoie les variantes de l'attaque pour une méthode : query, cookie
// et en-tête toujours, formulaire en POST, JSON pour toute méthode à corps.
func Variants(key, nonce, method string) []Variant {
	q := func(extra bool) url.Values {
		v := url.Values{"waf_nonce": {nonce}}
		if extra {
			v.Set(key, Payload)
		}
		return v
	}
	out := []Variant{
		{Name: "query", Method: method, Query: q(true)},
		{Name: "cookie", Method: method, Query: q(false), Headers: map[string]string{"Cookie": key + "=" + url.QueryEscape(Payload)}},
		{Name: "en-tête", Method: method, Query: q(false), Headers: map[string]string{"User-Agent": Payload}},
	}
	switch method {
	case "GET", "HEAD", "OPTIONS":
	case "POST":
		out = append(out,
			Variant{Name: "formulaire", Method: method, Query: q(false), ContentType: "application/x-www-form-urlencoded", Body: url.Values{key: {Payload}}.Encode()},
			Variant{Name: "json", Method: method, Query: q(false), ContentType: "application/json", Body: fmt.Sprintf(`{%q:%q}`, key, Payload)})
	default:
		out = append(out, Variant{Name: "json", Method: method, Query: q(false), ContentType: "application/json", Body: fmt.Sprintf(`{%q:%q}`, key, Payload)})
	}
	return out
}

type Target struct {
	Path    string
	Root    bool
	Methods []string
}

// Targets renvoie la racine puis un chemin sous chaque préfixe cité par un
// retrait, avec GET, POST et les méthodes des maillons de chain.
func Targets(prefixes []lint.Prefix) []Target {
	out := []Target{{Path: "/", Root: true, Methods: []string{"GET", "POST"}}}
	idx := map[string]int{}
	for _, p := range prefixes {
		path := p.Path
		if !p.Exact {
			path = strings.TrimSuffix(p.Path, "/") + "/waf-canon"
		}
		i, ok := idx[path]
		if !ok {
			out = append(out, Target{Path: path, Methods: []string{"GET", "POST"}})
			i = len(out) - 1
			idx[path] = i
		}
		for _, m := range p.Methods {
			if !slices.Contains(out[i].Methods, m) {
				out[i].Methods = append(out[i].Methods, m)
			}
		}
	}
	return out
}

type Outcome struct {
	Path    string
	Root    bool
	Method  string
	Variant string
	Status  int
	RuleID  int
}

func (o Outcome) Blocked() bool { return o.Status == 403 && Allowed[o.RuleID] }

func (o Outcome) String() string {
	return fmt.Sprintf("%s %s %s : statut %d, règle %d", o.Method, o.Path, o.Variant, o.Status, o.RuleID)
}

// Verdict applique la règle : à la racine, toutes les variantes bloquées par
// 949110 ou 19110 ; sous chaque préfixe, au moins une variante par méthode.
func Verdict(outs []Outcome) []string {
	type k struct{ path, method string }
	blocked := map[k]int{}
	var order []k
	var fails []string
	for _, o := range outs {
		key := k{o.Path, o.Method}
		if _, ok := blocked[key]; !ok {
			order = append(order, key)
			blocked[key] = 0
		}
		if o.Blocked() {
			blocked[key]++
		} else if o.Root {
			fails = append(fails, "attaque canonique non bloquée par 949110 ou 19110 : "+o.String())
		}
	}
	for _, key := range order {
		if key.path != "/" && blocked[key] == 0 {
			fails = append(fails, fmt.Sprintf("sous %s en %s, aucune variante de l'attaque canonique n'est bloquée par 949110 ou 19110", key.path, key.method))
		}
	}
	return fails
}

// NewWAF construit Coraza comme coraza-caddy sans load_owasp_crs : tout est lu
// sur le disque, la CRS embarquée dans le module n'est pas joignable.
func NewWAF(directives string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
}

// InProc rejoue les variantes dans Coraza en mémoire.
func InProc(waf coraza.WAF, host string, targets []Target) []Outcome {
	key := Key()
	var outs []Outcome
	for _, t := range targets {
		for _, m := range t.Methods {
			for _, v := range Variants(key, "inproc", m) {
				o := evaluate(waf, host, t.Path, v)
				o.Root, o.Method = t.Root, m
				outs = append(outs, o)
			}
		}
	}
	return outs
}

func evaluate(waf coraza.WAF, host, path string, v Variant) Outcome {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	o := Outcome{Path: path, Variant: v.Name, Status: 200}
	done := func(it *types.Interruption) Outcome {
		if it != nil {
			o.Status = it.Status
			o.RuleID = it.RuleID
		}
		return o
	}
	tx.ProcessConnection("203.0.113.10", 41000, "127.0.0.1", 8080)
	tx.ProcessURI(path+"?"+v.Query.Encode(), v.Method, "HTTP/1.1")
	tx.AddRequestHeader("Host", host)
	tx.SetServerName(host)
	tx.AddRequestHeader("Accept", "*/*")
	if _, ok := v.Headers["User-Agent"]; !ok {
		tx.AddRequestHeader("User-Agent", "wafgen-selftest")
	}
	for k, val := range v.Headers {
		tx.AddRequestHeader(k, val)
	}
	if v.Body != "" {
		tx.AddRequestHeader("Content-Type", v.ContentType)
		tx.AddRequestHeader("Content-Length", fmt.Sprint(len(v.Body)))
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return done(it)
	}
	if v.Body != "" {
		if it, _, err := tx.WriteRequestBody([]byte(v.Body)); err != nil || it != nil {
			return done(it)
		}
	}
	it, _ := tx.ProcessRequestBody()
	return done(it)
}

// Request construit la requête HTTP d'une variante vers base (http://127.0.0.1:8080).
func Request(base, host, path string, v Variant) (*http.Request, error) {
	var body *strings.Reader
	if v.Body != "" {
		body = strings.NewReader(v.Body)
	} else {
		body = strings.NewReader("")
	}
	r, err := http.NewRequest(v.Method, base+path+"?"+v.Query.Encode(), body)
	if err != nil {
		return nil, err
	}
	r.Host = host
	r.Header.Set("User-Agent", "wafgen-selftest")
	for k, val := range v.Headers {
		r.Header.Set(k, val)
	}
	if v.Body != "" {
		r.Header.Set("Content-Type", v.ContentType)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	return r, nil
}
