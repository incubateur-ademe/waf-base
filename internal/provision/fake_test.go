package provision

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

// fakeCoolify reproduit le comportement de l'API Coolify 4.7.5 lu dans son code :
// variables en is_buildtime=true par défaut, copie preview créée avec chaque
// variable, chaîne vide convertie en null, réglages d'app rangés sous settings,
// suppression de variable refusée (le jeton SecOps n'a pas l'ability delete).
// Une variable d'équipe vide n'entre que par la vue développeur de l'UI : POST
// /team/envs la refuse en HTTP 500 (colonne value NOT NULL), et refuse en 422 un
// champ hors de key, value, is_literal, is_multiline, is_shown_once et comment.
// Un domaine déjà porté par une autre app de l'équipe donne 409, sauf avec
// force_domain_override.
type fakeCoolify struct {
	t     *testing.T
	token string
	mu    sync.Mutex

	apps     map[string]*fakeApp
	dests    map[string]fakeDest
	ghApps   []map[string]any
	team     []*fakeShared
	server   map[string][]*fakeShared
	requests int
	writes   []string
	nextID   int
	bodies   []string

	// createLandsOn, s'il est posé, remplace la destination demandée à la création.
	createLandsOn string
	// ignorePatch liste les champs que le PATCH d'app accepte sans les écrire.
	ignorePatch map[string]bool
	// notAdmin : le compte du jeton n'est pas admin de l'équipe, Coolify refuse
	// la création d'une variable partagée (policy create).
	notAdmin bool
}

type fakeDest struct{ Name, Network, Server string }

type fakeApp struct {
	data  map[string]any
	dest  string
	extra []string
	envs  []*fakeEnv
}

type fakeEnv struct {
	UUID, Key                   string
	Value                       *string
	Buildtime, Runtime, Preview bool
}

// fakeShared : Locked est une variable verrouillée (is_shown_once), Hidden une
// valeur que le jeton ne lit pas (sans read:sensitive). Dans les deux cas le GET
// omet value.
type fakeShared struct {
	ID     int
	Key    string
	Value  *string
	Locked bool
	Hidden bool
}

const ghAppUUID = "gh-ops"

func newFake(t *testing.T, token string) (*fakeCoolify, *httptest.Server) {
	f := &fakeCoolify{
		t:     t,
		token: token,
		apps:  map[string]*fakeApp{},
		dests: map[string]fakeDest{
			"dest-waf":         {"waf-1-waf", "waf", "srv-waf-1"},
			"dest-coolify":     {"waf-1-coolify", "coolify", "srv-waf-1"},
			"dest-waf-preprod": {"waf-preprod-waf", "waf", "srv-waf-preprod"},
		},
		server: map[string][]*fakeShared{"srv-waf-1": nil, "srv-waf-preprod": nil},
		ghApps: []map[string]any{
			{"id": 3, "uuid": "gh-autre"},
			{"id": 7, "uuid": ghAppUUID, "client_secret": "ne-doit-pas-sortir"},
		},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		for i, w := range f.writes {
			if w == "POST /api/v1/team/envs" && reEdgeTeamWrite.MatchString(f.bodies[i]) {
				continue
			}
			if strings.HasPrefix(w, "POST /api/v1/team/envs") || strings.Contains(w, "/team/envs/") {
				t.Errorf("écriture d'une variable d'équipe hors de EDGE_SECRET_<APP> : %s", w)
			}
			if strings.HasPrefix(w, "POST /api/v1/servers/") || strings.Contains(w, "/envs/") && strings.Contains(w, "/servers/") {
				t.Errorf("écriture d'une variable de serveur : %s", w)
			}
		}
	})
	return f, srv
}

func ptr(s string) *string { return &s }

func (f *fakeCoolify) id(prefix string) string {
	f.nextID++
	return fmt.Sprintf("%s%d", prefix, f.nextID)
}

func coolifyDefaults() map[string]any {
	return map[string]any{
		"build_pack":                "nixpacks",
		"base_directory":            "/",
		"dockerfile_location":       nil,
		"watch_paths":               nil,
		"ports_exposes":             "3000",
		"ports_mappings":            nil,
		"fqdn":                      nil,
		"health_check_enabled":      true,
		"health_check_path":         "/",
		"health_check_port":         nil,
		"health_check_interval":     5,
		"health_check_retries":      10,
		"health_check_timeout":      5,
		"health_check_start_period": 5,
		"limits_memory":             "0",
		"limits_cpu_shares":         1024,
		"source_type":               nil,
		"source_id":                 nil,
		"settings": map[string]any{
			"is_preview_deployments_enabled":   false,
			"is_pr_deployments_public_enabled": false,
			"is_git_submodules_enabled":        true,
			"is_git_lfs_enabled":               true,
			"use_build_secrets":                false,
			"inject_build_args_to_dockerfile":  true,
			"include_source_commit_in_build":   false,
			"is_auto_deploy_enabled":           true,
			"is_force_https_enabled":           true,
			"stop_grace_period":                nil,
			"rolling_update_drain_seconds":     5,
		},
	}
}

var teamEnvFields = map[string]bool{"key": true, "value": true, "is_literal": true, "is_multiline": true, "is_shown_once": true, "comment": true}

var settingFields = map[string]bool{
	"is_preview_deployments_enabled": true, "is_pr_deployments_public_enabled": true,
	"is_git_submodules_enabled": true, "is_git_lfs_enabled": true, "use_build_secrets": true,
	"inject_build_args_to_dockerfile": true, "include_source_commit_in_build": true,
	"is_auto_deploy_enabled": true, "is_force_https_enabled": true, "stop_grace_period": true,
}

var topFields = map[string]bool{
	"git_repository": true, "git_branch": true, "build_pack": true, "base_directory": true,
	"dockerfile_location": true, "watch_paths": true, "ports_exposes": true, "ports_mappings": true,
	"health_check_enabled": true, "health_check_path": true, "health_check_port": true,
	"health_check_interval": true, "health_check_retries": true, "health_check_timeout": true,
	"health_check_start_period": true, "limits_memory": true, "limits_cpu_shares": true,
}

// addApp pose une app existante, à la manière de l'app pilote relevée le 2026-11-16.
func (f *fakeCoolify) addApp(name, dest string, over map[string]any) *fakeApp {
	d := coolifyDefaults()
	d["name"] = name
	d["source_type"] = `App\Models\GithubApp`
	d["source_id"] = 7
	for k, v := range over {
		if settingFields[k] {
			d["settings"].(map[string]any)[k] = v
		} else {
			d[k] = v
		}
	}
	uuid := f.id("app")
	d["uuid"] = uuid
	a := &fakeApp{data: d, dest: dest}
	f.apps[uuid] = a
	return a
}

func (a *fakeApp) env(key string) *fakeEnv {
	for _, e := range a.envs {
		if e.Key == key && !e.Preview {
			return e
		}
	}
	return nil
}

func (a *fakeApp) setEnv(f *fakeCoolify, key string, value *string, buildtime, runtime bool) {
	if v := value; v != nil && *v == "" {
		value = nil
	}
	a.envs = append(a.envs,
		&fakeEnv{UUID: f.id("env"), Key: key, Value: value, Buildtime: buildtime, Runtime: runtime},
		&fakeEnv{UUID: f.id("env"), Key: key, Value: value, Buildtime: buildtime, Runtime: runtime, Preview: true},
	)
}

func (f *fakeCoolify) addShared(key string, value *string) *fakeShared {
	if value == nil {
		f.t.Fatalf("variable d'équipe %s sans valeur", key)
	}
	f.nextID++
	s := &fakeShared{ID: f.nextID, Key: key, Value: value}
	f.team = append(f.team, s)
	return s
}

func (f *fakeCoolify) addServerShared(server, key string, value *string) *fakeShared {
	f.nextID++
	s := &fakeShared{ID: f.nextID, Key: key, Value: value}
	f.server[server] = append(f.server[server], s)
	return s
}

// domainConflicts rend, au format du 409 de Coolify 4.7.5, les apps qui portent
// déjà un des hosts de domains, hors de l'app self.
func (f *fakeCoolify) domainConflicts(self string, domains any) []map[string]any {
	hosts := func(v any) map[string]bool {
		out := map[string]bool{}
		s, _ := v.(string)
		for _, d := range strings.Split(s, ",") {
			d = strings.TrimSpace(strings.ToLower(d))
			d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
			if d = strings.TrimRight(d, "/"); d != "" {
				out[d] = true
			}
		}
		return out
	}
	want := hosts(domains)
	var out []map[string]any
	for u, a := range f.apps {
		if u == self {
			continue
		}
		for h := range hosts(a.data["fqdn"]) {
			if want[h] {
				out = append(out, map[string]any{"domain": h, "resource_name": a.data["name"], "resource_uuid": u,
					"resource_type": "application", "message": fmt.Sprintf("Domain %s is already in use by application '%s'", h, a.data["name"])})
			}
		}
	}
	return out
}

func conflict409(w http.ResponseWriter, c []map[string]any) {
	write(w, 409, map[string]any{
		"message":   "Domain conflicts detected. Use force_domain_override=true to proceed.",
		"conflicts": c,
		"warning":   "Using the same domain for multiple resources can cause routing conflicts and unpredictable behavior.",
	})
}

func (f *fakeCoolify) shared(key string) *fakeShared {
	for _, s := range f.team {
		if s.Key == key {
			return s
		}
	}
	return nil
}

func (f *fakeCoolify) appByName(name string) *fakeApp {
	for _, a := range f.apps {
		if a.data["name"] == name {
			return a
		}
	}
	return nil
}

func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envJSON(e *fakeEnv) map[string]any {
	return map[string]any{
		"uuid": e.UUID, "key": e.Key, "value": e.Value, "real_value": e.Value,
		"is_buildtime": e.Buildtime, "is_runtime": e.Runtime, "is_preview": e.Preview,
		"is_literal": false, "is_shown_once": false,
	}
}

// Seule écriture de variable d'équipe admise : EDGE_SECRET_<APP> générée.
var reEdgeTeamWrite = regexp.MustCompile(`^\{"comment":"[^"]*","key":"EDGE_SECRET_[A-Z0-9_]+","value":"[A-Za-z0-9_-]{43}"\}$`)

var (
	reApp     = regexp.MustCompile(`^/api/v1/applications/([A-Za-z0-9_-]+)$`)
	reAppEnvs = regexp.MustCompile(`^/api/v1/applications/([A-Za-z0-9_-]+)/envs$`)
	reAppBulk = regexp.MustCompile(`^/api/v1/applications/([A-Za-z0-9_-]+)/envs/bulk$`)
	reAppEnv  = regexp.MustCompile(`^/api/v1/applications/([A-Za-z0-9_-]+)/envs/([A-Za-z0-9_-]+)$`)
	reAppDest = regexp.MustCompile(`^/api/v1/applications/([A-Za-z0-9_-]+)/destinations$`)
	reDest    = regexp.MustCompile(`^/api/v1/destinations/([A-Za-z0-9_-]+)$`)
	reSrvEnvs = regexp.MustCompile(`^/api/v1/servers/([A-Za-z0-9_-]+)/envs$`)
)

func (f *fakeCoolify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		write(w, 401, map[string]any{"message": "Unauthenticated."})
		return
	}
	var body map[string]any
	if r.Method != http.MethodGet {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		raw := map[string]any{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil && !(r.Method == http.MethodDelete && err == io.EOF) {
			write(w, 400, map[string]any{"message": "json"})
			return
		}
		b, _ := json.Marshal(raw)
		f.bodies = append(f.bodies, string(b))
		body = raw
	}
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/api/v1/applications":
		var out []map[string]any
		for _, a := range f.apps {
			out = append(out, map[string]any{"uuid": a.data["uuid"], "name": a.data["name"]})
		}
		write(w, 200, out)
	case r.Method == "GET" && reApp.MatchString(p):
		a := f.apps[reApp.FindStringSubmatch(p)[1]]
		if a == nil {
			write(w, 404, map[string]any{"message": "Application not found."})
			return
		}
		write(w, 200, a.data)
	case r.Method == "GET" && reAppDest.MatchString(p):
		a := f.apps[reAppDest.FindStringSubmatch(p)[1]]
		out := []map[string]any{}
		for i, u := range append([]string{a.dest}, a.extra...) {
			d := f.dests[u]
			out = append(out, map[string]any{"uuid": u, "name": d.Name, "network": d.Network, "server_uuid": d.Server, "is_primary": i == 0})
		}
		write(w, 200, out)
	case r.Method == "GET" && reAppEnvs.MatchString(p):
		a := f.apps[reAppEnvs.FindStringSubmatch(p)[1]]
		var out []map[string]any
		for _, e := range a.envs {
			out = append(out, envJSON(e))
		}
		write(w, 200, out)
	case r.Method == "GET" && reDest.MatchString(p):
		u := reDest.FindStringSubmatch(p)[1]
		d, ok := f.dests[u]
		if !ok {
			write(w, 404, map[string]any{"message": "Destination not found."})
			return
		}
		write(w, 200, map[string]any{"uuid": u, "name": d.Name, "network": d.Network, "type": "standalone", "server_uuid": d.Server})
	case r.Method == "GET" && p == "/api/v1/github-apps":
		write(w, 200, f.ghApps)
	case r.Method == "GET" && p == "/api/v1/team/envs":
		out := []map[string]any{}
		for _, s := range f.team {
			m := map[string]any{"id": s.ID, "key": s.Key, "is_literal": false, "is_shown_once": s.Locked, "type": "team"}
			if !s.Locked && !s.Hidden {
				m["value"] = s.Value
			}
			out = append(out, m)
		}
		write(w, 200, out)
	case r.Method == "GET" && reSrvEnvs.MatchString(p):
		list, ok := f.server[reSrvEnvs.FindStringSubmatch(p)[1]]
		if !ok {
			write(w, 404, map[string]any{"message": "Server not found."})
			return
		}
		out := []map[string]any{}
		for _, s := range list {
			m := map[string]any{"id": s.ID, "key": s.Key, "is_literal": false, "is_shown_once": s.Locked, "type": "server"}
			if !s.Locked && !s.Hidden {
				m["value"] = s.Value
			}
			out = append(out, m)
		}
		write(w, 200, out)
	case r.Method == "POST" && p == "/api/v1/team/envs" && f.notAdmin:
		write(w, 403, map[string]any{"message": "This action is unauthorized."})
	case r.Method == "POST" && p == "/api/v1/team/envs":
		for k := range body {
			if !teamEnvFields[k] {
				write(w, 422, map[string]any{"message": "Validation failed.", "errors": map[string]any{k: "This field is not allowed."}})
				return
			}
		}
		key, _ := body["key"].(string)
		if f.shared(key) != nil {
			write(w, 409, map[string]any{"message": "Environment variable already exists."})
			return
		}
		s, _ := body["value"].(string)
		if strings.TrimSpace(s) == "" {
			write(w, 500, map[string]any{"message": `SQLSTATE[23502]: Not null violation: null value in column "value" of relation "shared_environment_variables"`})
			return
		}
		sh := f.addShared(key, &s)
		write(w, 201, map[string]any{"id": sh.ID})
	case r.Method == "DELETE" && reAppEnv.MatchString(p):
		write(w, 403, map[string]any{"message": "Missing required permissions: delete"})
	case r.Method == "POST" && p == "/api/v1/applications/private-github-app":
		f.create(w, body)
	case r.Method == "PATCH" && reApp.MatchString(p):
		u := reApp.FindStringSubmatch(p)[1]
		a := f.apps[u]
		if d, ok := body["domains"]; ok && body["force_domain_override"] != true {
			if c := f.domainConflicts(u, d); len(c) > 0 {
				conflict409(w, c)
				return
			}
		}
		for k, v := range body {
			switch {
			case k == "force_domain_override":
			case f.ignorePatch[k]:
			case k == "domains":
				a.data["fqdn"] = v
			case k == "github_app_uuid":
				a.data["source_id"] = f.ghID(v)
			case settingFields[k]:
				a.data["settings"].(map[string]any)[k] = v
			case topFields[k]:
				a.data[k] = v
			default:
				write(w, 422, map[string]any{"message": "Validation failed.", "errors": map[string]any{k: "This field is not allowed."}})
				return
			}
		}
		write(w, 200, map[string]any{"uuid": a.data["uuid"]})
	case r.Method == "PATCH" && reAppBulk.MatchString(p):
		a := f.apps[reAppBulk.FindStringSubmatch(p)[1]]
		items, _ := body["data"].([]any)
		for _, it := range items {
			m := it.(map[string]any)
			key := m["key"].(string)
			if pr, _ := m["is_preview"].(bool); pr {
				f.t.Errorf("variable preview écrite : %s", key)
			}
			var val *string
			_, hasVal := m["value"]
			if s, ok := m["value"].(string); ok && s != "" {
				val = &s
			}
			if e := a.env(key); e != nil {
				if hasVal {
					e.Value = val
				}
				if b, ok := m["is_buildtime"].(bool); ok {
					e.Buildtime = b
				}
				if b, ok := m["is_runtime"].(bool); ok {
					e.Runtime = b
				}
				continue
			}
			bt, ok := m["is_buildtime"].(bool)
			if !ok {
				bt = true
			}
			rt, ok := m["is_runtime"].(bool)
			if !ok {
				rt = true
			}
			a.setEnv(f, key, val, bt, rt)
		}
		write(w, 201, []any{})
	default:
		write(w, 404, map[string]any{"message": "route inconnue du faux Coolify : " + r.Method + " " + p})
	}
}

func (f *fakeCoolify) ghID(v any) any {
	for _, g := range f.ghApps {
		if g["uuid"] == v {
			return g["id"]
		}
	}
	return nil
}

// create ignore les réglages de settings autres que ceux que la route traite à
// part, pour vérifier que provision relit l'app et complète par un PATCH.
func (f *fakeCoolify) create(w http.ResponseWriter, body map[string]any) {
	for _, k := range []string{"project_uuid", "server_uuid", "github_app_uuid", "git_repository", "git_branch", "build_pack"} {
		if _, ok := body[k]; !ok {
			write(w, 422, map[string]any{"message": "Validation failed.", "errors": map[string]any{k: "required"}})
			return
		}
	}
	if body["environment_name"] == nil && body["environment_uuid"] == nil {
		write(w, 422, map[string]any{"message": "environment_name or environment_uuid is required."})
		return
	}
	dest, _ := body["destination_uuid"].(string)
	if dest == "" {
		write(w, 400, map[string]any{"message": "Server has multiple destinations and you do not set destination_uuid."})
		return
	}
	if _, ok := f.dests[dest]; !ok {
		write(w, 422, map[string]any{"message": "Destination not found."})
		return
	}
	if body["force_domain_override"] != true {
		if c := f.domainConflicts("", body["domains"]); len(c) > 0 {
			conflict409(w, c)
			return
		}
	}
	d := coolifyDefaults()
	uuid := f.id("app")
	d["uuid"] = uuid
	d["name"] = body["name"]
	d["source_type"] = `App\Models\GithubApp`
	d["source_id"] = f.ghID(body["github_app_uuid"])
	d["fqdn"] = body["domains"]
	for k, v := range body {
		switch {
		case topFields[k]:
			d[k] = v
		case k == "is_auto_deploy_enabled" || k == "is_force_https_enabled" || k == "is_preview_deployments_enabled" || k == "use_build_secrets":
			d["settings"].(map[string]any)[k] = v
		}
	}
	if body["instant_deploy"] == true {
		f.t.Errorf("création avec instant_deploy")
	}
	if f.createLandsOn != "" {
		dest = f.createLandsOn
	}
	f.apps[uuid] = &fakeApp{data: d, dest: dest}
	write(w, 201, map[string]any{"uuid": uuid, "domains": strings.Split(fmt.Sprint(body["domains"]), ",")})
}
