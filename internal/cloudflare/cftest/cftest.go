// Package cftest est un faux de l'API Rulesets de Cloudflare pour les tests :
// enveloppe {success, errors, result}, 404 sur un entrypoint absent, refus de
// créer un second ruleset de zone pour une phase, refs uniques dans un ruleset,
// règle ajoutée en fin de liste. Un PUT ou un DELETE fait échouer le test.
package cftest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const Phase = "http_request_late_transform"

type Fake struct {
	t     testing.TB
	Token string
	URL   string

	mu     sync.Mutex
	zones  map[string]string
	sets   map[string]*ruleset
	nextID int
	// Requests : méthode et chemin de chaque requête reçue.
	Requests []string
	// Fail : statut renvoyé pour « MÉTHODE chemin », avec un message qui recopie
	// la requête, comme une erreur de validation.
	Fail map[string]int
}

type ruleset struct {
	ID    string
	Rules []map[string]any
}

// New démarre le faux, arrêté à la fin du test.
func New(t testing.TB, token string) *Fake {
	f := &Fake{t: t, Token: token, zones: map[string]string{}, sets: map[string]*ruleset{}, Fail: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

func (f *Fake) id() string {
	f.nextID++
	return fmt.Sprintf("%032x", f.nextID)
}

// AddZone crée une zone visible du jeton et rend son identifiant.
func (f *Fake) AddZone(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.id()
	f.zones[name] = id
	return id
}

// AddRule ajoute une règle à l'entrypoint de la zone, créé s'il manque, et rend
// son identifiant.
func (f *Fake) AddRule(zone string, rule map[string]any) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	zid := f.zones[zone]
	rs := f.sets[zid]
	if rs == nil {
		rs = &ruleset{ID: f.id()}
		f.sets[zid] = rs
	}
	r := f.normalize(rule, "")
	rs.Rules = append(rs.Rules, r)
	return r["id"].(string)
}

// Rules rend une copie des règles de l'entrypoint de la zone, nil sans entrypoint.
func (f *Fake) Rules(zone string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.sets[f.zones[zone]]
	if rs == nil {
		return nil
	}
	b, _ := json.Marshal(rs.Rules)
	var out []map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// RulesetID rend l'identifiant de l'entrypoint de la zone, "" sans entrypoint.
func (f *Fake) RulesetID(zone string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rs := f.sets[f.zones[zone]]; rs != nil {
		return rs.ID
	}
	return ""
}

// Writes rend les requêtes qui ne sont pas des GET.
func (f *Fake) Writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.Requests {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

func (f *Fake) normalize(in map[string]any, keepID string) map[string]any {
	r := map[string]any{}
	for k, v := range in {
		r[k] = v
	}
	r["id"] = keepID
	if keepID == "" {
		r["id"] = f.id()
	}
	if ref, _ := r["ref"].(string); ref == "" {
		r["ref"] = r["id"]
	}
	if _, ok := r["enabled"]; !ok {
		r["enabled"] = true
	}
	r["version"] = "1"
	r["last_updated"] = "2026-11-20T00:00:00Z"
	return r
}

func reply(w http.ResponseWriter, code int, result any, errs ...map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if errs == nil {
		errs = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": code < 300, "errors": errs, "messages": []any{}, "result": result})
}

func (rs *ruleset) json() map[string]any {
	return map[string]any{"id": rs.ID, "name": "default", "kind": "zone", "phase": Phase, "version": "1", "rules": rs.Rules}
}

func (rs *ruleset) refTaken(ref, except string) bool {
	for _, r := range rs.Rules {
		if r["ref"] == ref && r["id"] != except {
			return true
		}
	}
	return false
}

var (
	reZones = regexp.MustCompile(`^/client/v4/zones$`)
	reEntry = regexp.MustCompile(`^/client/v4/zones/([0-9a-f]{32})/rulesets/phases/([a-z_]+)/entrypoint$`)
	reSets  = regexp.MustCompile(`^/client/v4/zones/([0-9a-f]{32})/rulesets$`)
	reRules = regexp.MustCompile(`^/client/v4/zones/([0-9a-f]{32})/rulesets/([0-9a-f]{32})/rules$`)
	reRule  = regexp.MustCompile(`^/client/v4/zones/([0-9a-f]{32})/rulesets/([0-9a-f]{32})/rules/([0-9a-f]{32})$`)
)

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	f.Requests = append(f.Requests, r.Method+" "+p)
	if r.Header.Get("Authorization") != "Bearer "+f.Token {
		reply(w, 403, nil, map[string]any{"code": 10000, "message": "Authentication error"})
		return
	}
	var body map[string]any
	var raw []byte
	if r.Method != http.MethodGet {
		var err error
		raw, err = io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(raw, &body) != nil {
			reply(w, 400, nil, map[string]any{"code": 10026, "message": "could not parse request body"})
			return
		}
	}
	if code := f.Fail[r.Method+" "+p]; code != 0 {
		reply(w, code, nil, map[string]any{"code": 20021, "message": "requête refusée : " + string(raw) + " " + r.Header.Get("Authorization")})
		return
	}
	switch {
	case r.Method == http.MethodPut || r.Method == http.MethodDelete:
		f.t.Errorf("%s %s : interdit, il remplacerait ou retirerait des règles hors de waf-ops", r.Method, p)
		reply(w, 405, nil, map[string]any{"code": 10405, "message": "interdit par le faux"})
	case r.Method == http.MethodGet && reZones.MatchString(p):
		name := r.URL.Query().Get("name")
		out := []map[string]any{}
		if id, ok := f.zones[name]; ok {
			out = append(out, map[string]any{"id": id, "name": name, "status": "active"})
		}
		reply(w, 200, out)
	case r.Method == http.MethodGet && reEntry.MatchString(p):
		m := reEntry.FindStringSubmatch(p)
		rs := f.sets[m[1]]
		if rs == nil || m[2] != Phase {
			reply(w, 404, nil, map[string]any{"code": 10003, "message": "could not find entrypoint ruleset in the '" + m[2] + "' phase"})
			return
		}
		reply(w, 200, rs.json())
	case r.Method == http.MethodPost && reSets.MatchString(p):
		zid := reSets.FindStringSubmatch(p)[1]
		if body["kind"] != "zone" || body["phase"] != Phase {
			reply(w, 400, nil, map[string]any{"code": 20217, "message": "kind ou phase inattendus : " + string(raw)})
			return
		}
		if f.sets[zid] != nil {
			reply(w, 400, nil, map[string]any{"code": 20217, "message": "a ruleset of this kind and phase already exists"})
			return
		}
		rs := &ruleset{ID: f.id()}
		rules, _ := body["rules"].([]any)
		for _, x := range rules {
			m, _ := x.(map[string]any)
			n := f.normalize(m, "")
			if rs.refTaken(n["ref"].(string), "") {
				reply(w, 400, nil, map[string]any{"code": 20200, "message": "ref en double"})
				return
			}
			rs.Rules = append(rs.Rules, n)
		}
		f.sets[zid] = rs
		reply(w, 200, rs.json())
	case r.Method == http.MethodPost && reRules.MatchString(p):
		m := reRules.FindStringSubmatch(p)
		rs := f.sets[m[1]]
		if rs == nil || rs.ID != m[2] {
			reply(w, 404, nil, map[string]any{"code": 10003, "message": "ruleset introuvable"})
			return
		}
		n := f.normalize(body, "")
		if rs.refTaken(n["ref"].(string), "") {
			reply(w, 400, nil, map[string]any{"code": 20200, "message": "ref en double : " + string(raw)})
			return
		}
		rs.Rules = append(rs.Rules, n)
		reply(w, 200, rs.json())
	case r.Method == http.MethodPatch && reRule.MatchString(p):
		m := reRule.FindStringSubmatch(p)
		rs := f.sets[m[1]]
		if rs == nil || rs.ID != m[2] {
			reply(w, 404, nil, map[string]any{"code": 10003, "message": "ruleset introuvable"})
			return
		}
		for i, cur := range rs.Rules {
			if cur["id"] != m[3] {
				continue
			}
			n := f.normalize(body, m[3])
			if rs.refTaken(n["ref"].(string), m[3]) {
				reply(w, 400, nil, map[string]any{"code": 20200, "message": "ref en double"})
				return
			}
			rs.Rules[i] = n
			reply(w, 200, rs.json())
			return
		}
		reply(w, 404, nil, map[string]any{"code": 10003, "message": "règle introuvable"})
	default:
		reply(w, 404, nil, map[string]any{"code": 7003, "message": "route inconnue du faux : " + r.Method + " " + p})
	}
}
