package ghaudit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	testAppID  = "Iv23liTESTAPPIDTEST"
	testToken  = "ghs_jetonDeTestQuiNeDoitJamaisSortir0123"
	opsOrg     = "incubateur-ademe"
	canonCO    = "/waf/                   @incubateur-ademe/secops\n/.github/CODEOWNERS     @incubateur-ademe/secops\n/.gitmodules            @incubateur-ademe/secops\n/.gitattributes         @incubateur-ademe/secops\n/.lfsconfig             @incubateur-ademe/secops\n"
	protOK     = `{"required_pull_request_reviews":{"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"require_last_push_approval":false,"required_approving_review_count":0},"enforce_admins":{"enabled":true},"allow_force_pushes":{"enabled":false}}`
	prRuleOK   = `{"type":"pull_request","ruleset_id":42,"ruleset_source_type":"Repository","parameters":{"require_code_owner_review":true,"dismiss_stale_reviews_on_push":true,"require_last_push_approval":false,"required_approving_review_count":0}}`
	rulesetNoB = `{"id":42,"name":"main","enforcement":"active","target":"branch","rules":[]}`
)

var (
	keyOnce sync.Once
	testRSA *rsa.PrivateKey
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testRSA = k
	})
	return testRSA
}

type fakeFile struct {
	content string
	mode    string
}

type fakeRepo struct {
	private       bool
	defaultBranch string
	branch        string
	files         map[string]fakeFile
	coErrors      string
	teams         string
	collabs       string
	protection    string
	protStatus    int
	rules         string
	rulesets      map[string]string
	truncated     bool
}

type fakeInstall struct {
	id        int
	perms     map[string]string
	login     string
	suspended bool
}

type fakeGH struct {
	t          *testing.T
	pub        *rsa.PublicKey
	now        time.Time
	repos      map[string]*fakeRepo
	installs   map[string]*fakeInstall
	members    string
	owners     string
	tokenPerms map[string]string
	tokenValue string
	blobExtra  string
	status     map[string]int
	rateLimit  bool
	mu         sync.Mutex
	calls      []string
	nodes      map[string]fakeNode
}

type fakeNode struct {
	repo, dir string
	isTree    bool
	content   string
}

func baseRepo() *fakeRepo {
	return &fakeRepo{
		defaultBranch: "main",
		branch:        "main",
		files: map[string]fakeFile{
			".github/CODEOWNERS":           {content: canonCO},
			".github/workflows/ci.yml":     {content: "on: push\n"},
			"README.md":                    {content: "# app\n"},
			"src/app.js":                   {content: "console.log(1)\n"},
			"waf/Dockerfile":               {content: DockerfileCanonique},
			"waf/waf.yaml":                 {content: "version: 1\n"},
			"waf/coraza/before.conf":       {content: "# rien\n"},
			"waf/tests/attaque-sql.yaml":   {content: "tests: []\n"},
			"docs/architecture/archi.md":   {content: "x\n"},
			"docs/architecture/schema.png": {content: "png"},
		},
		coErrors:   `{"errors":[]}`,
		teams:      `[{"slug":"core","permission":"admin"},{"slug":"secops","permission":"push"},{"slug":"devs","permission":"maintain"}]`,
		collabs:    `[{"login":"ops1","permissions":{"admin":true}},{"login":"Patron","permissions":{"admin":true}},{"login":"dev1","permissions":{"admin":false,"maintain":true}}]`,
		protection: protOK,
		rules:      `[]`,
		rulesets:   map[string]string{},
	}
}

func newFake(t *testing.T) *fakeGH {
	return &fakeGH{
		t:   t,
		pub: &testKey(t).PublicKey,
		now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC),
		repos: map[string]*fakeRepo{
			"incubateur-ademe/waf-pilote": baseRepo(),
		},
		installs: map[string]*fakeInstall{
			"incubateur-ademe": {id: 7, perms: map[string]string{"administration": "read", "contents": "read", "metadata": "read", "members": "read"}},
		},
		members:    `[{"login":"ops1"},{"login":"OPS2"},{"login":"ops3"}]`,
		owners:     `[{"login":"ops1"},{"login":"patron"}]`,
		tokenPerms: nil,
		status:     map[string]int{},
	}
}

func (f *fakeGH) start() (*httptest.Server, Config) {
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.t.Cleanup(srv.Close)
	cfg := Config{
		AppID:   testAppID,
		Key:     testKey(f.t),
		API:     srv.URL,
		OpsOrg:  opsOrg,
		OpsTeam: "secops",
		HTTP:    srv.Client(),
		Now:     func() time.Time { return f.now },
	}
	return srv, cfg
}

func apps(repos ...string) []inventory.App {
	var out []inventory.App
	for i, r := range repos {
		out = append(out, inventory.App{Name: fmt.Sprintf("app%d", i), Repo: r, Branch: "main", WafDir: "waf"})
	}
	return out
}

func sha(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func (f *fakeGH) writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	if f.rateLimit && status == http.StatusForbidden {
		w.Header().Set("X-RateLimit-Remaining", "0")
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeGH) checkJWT(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(head) != `{"alg":"RS256","typ":"JWT"}` {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	now := f.now.Unix()
	return c.Iss == testAppID && c.Iat <= now && c.Exp > now && c.Exp-c.Iat <= 600
}

func (f *fakeGH) buildNodes() {
	f.nodes = map[string]fakeNode{}
	for name, r := range f.repos {
		f.nodes[sha("tree:"+name+":")] = fakeNode{repo: name, dir: "", isTree: true}
		for p, file := range r.files {
			dir := path.Dir(p)
			for dir != "." {
				f.nodes[sha("tree:"+name+":"+dir)] = fakeNode{repo: name, dir: dir, isTree: true}
				dir = path.Dir(dir)
			}
			f.nodes[sha("blob:"+name+":"+p)] = fakeNode{repo: name, dir: p, content: file.content}
		}
	}
}

type entry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size,omitempty"`
}

func (f *fakeGH) treeEntries(repo, dir string, recursive bool) []entry {
	r := f.repos[repo]
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	seen := map[string]bool{}
	var out []entry
	for p, file := range r.files {
		rel, ok := strings.CutPrefix(p, prefix)
		if !ok {
			continue
		}
		segs := strings.Split(rel, "/")
		for i := 1; i < len(segs); i++ {
			if !recursive && i > 1 {
				break
			}
			d := strings.Join(segs[:i], "/")
			if !seen[d] {
				seen[d] = true
				out = append(out, entry{Path: d, Mode: "040000", Type: "tree", SHA: sha("tree:" + repo + ":" + prefix + d)})
			}
		}
		if !recursive && len(segs) > 1 {
			continue
		}
		mode, typ := file.mode, "blob"
		if mode == "" {
			mode = "100644"
		}
		if mode == "160000" {
			typ = "commit"
		}
		out = append(out, entry{Path: rel, Mode: mode, Type: typ, SHA: sha("blob:" + repo + ":" + p), Size: len(file.content)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func paginate(body string, r *http.Request) string {
	var items []json.RawMessage
	if json.Unmarshal([]byte(body), &items) != nil {
		return body
	}
	pp, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pp <= 0 {
		return body
	}
	if pg <= 0 {
		pg = 1
	}
	lo, hi := (pg-1)*pp, pg*pp
	if lo > len(items) {
		lo = len(items)
	}
	if hi > len(items) {
		hi = len(items)
	}
	b, _ := json.Marshal(items[lo:hi])
	return string(b)
}

func (f *fakeGH) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+p)
	if f.nodes == nil {
		f.buildNodes()
	}
	f.mu.Unlock()
	if st, ok := f.status[p]; ok {
		f.writeJSON(w, st, `{"message":"forcé `+testToken+`"}`)
		return
	}
	if r.Header.Get("X-GitHub-Api-Version") != apiVersion || r.Header.Get("User-Agent") == "" {
		f.writeJSON(w, 400, `{"message":"en-têtes"}`)
		return
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	appRoute := strings.HasSuffix(p, "/installation") || strings.HasPrefix(p, "/app/")
	if appRoute {
		if !f.checkJWT(r) {
			f.writeJSON(w, 401, `{"message":"JWT"}`)
			return
		}
	} else if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.writeJSON(w, 401, `{"message":"jeton"}`)
		return
	}
	switch {
	case len(segs) == 3 && segs[0] == "orgs" && segs[2] == "installation":
		f.install(w, segs[1])
	case len(segs) == 4 && segs[0] == "repos" && segs[3] == "installation":
		f.install(w, segs[1])
	case len(segs) == 4 && segs[0] == "app" && segs[3] == "access_tokens" && r.Method == http.MethodPost:
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Permissions) == 0 {
			f.writeJSON(w, 422, `{}`)
			return
		}
		for k, v := range body.Permissions {
			if v != "read" {
				f.writeJSON(w, 422, `{}`)
				return
			}
			_ = k
		}
		perms := body.Permissions
		if f.tokenPerms != nil {
			perms = f.tokenPerms
		}
		tok := testToken
		if f.tokenValue != "" {
			tok = f.tokenValue
		}
		b, _ := json.Marshal(map[string]any{"token": tok, "permissions": perms})
		f.writeJSON(w, 201, string(b))
	case len(segs) == 5 && segs[0] == "orgs" && segs[2] == "teams" && segs[4] == "members":
		f.writeJSON(w, 200, paginate(f.members, r))
	case len(segs) == 3 && segs[0] == "orgs" && segs[2] == "members" && r.URL.Query().Get("role") == "admin":
		f.writeJSON(w, 200, paginate(f.owners, r))
	case len(segs) >= 3 && segs[0] == "repos":
		f.repo(w, r, segs[1]+"/"+segs[2], segs[3:])
	default:
		f.writeJSON(w, 404, `{"message":"Not Found"}`)
	}
}

func (f *fakeGH) install(w http.ResponseWriter, owner string) {
	in, ok := f.installs[strings.ToLower(owner)]
	if !ok {
		f.writeJSON(w, 404, `{"message":"Not Found"}`)
		return
	}
	login := owner
	if in.login != "" {
		login = in.login
	}
	var suspended any
	if in.suspended {
		suspended = "2026-11-01T00:00:00Z"
	}
	b, _ := json.Marshal(map[string]any{"id": in.id, "account": map[string]string{"login": login, "type": "Organization"}, "permissions": in.perms, "suspended_at": suspended})
	f.writeJSON(w, 200, string(b))
}

func (f *fakeGH) repo(w http.ResponseWriter, r *http.Request, name string, rest []string) {
	rp, ok := f.repos[name]
	if !ok {
		f.writeJSON(w, 404, `{"message":"Not Found"}`)
		return
	}
	notFound := func() { f.writeJSON(w, 404, `{"message":"Not Found"}`) }
	branchOK := func(b string) bool { return strings.ReplaceAll(b, "%2F", "/") == rp.branch }
	switch {
	case len(rest) == 0:
		b, _ := json.Marshal(map[string]any{"full_name": name, "private": rp.private, "archived": false, "default_branch": rp.defaultBranch})
		f.writeJSON(w, 200, string(b))
	case len(rest) == 2 && rest[0] == "branches":
		if !branchOK(rest[1]) {
			notFound()
			return
		}
		f.writeJSON(w, 200, fmt.Sprintf(`{"name":%q,"commit":{"sha":%q,"commit":{"tree":{"sha":%q}}},"protected":true}`, rp.branch, sha("commit"), sha("tree:"+name+":")))
	case len(rest) == 3 && rest[0] == "branches" && rest[2] == "protection":
		switch {
		case !branchOK(rest[1]):
			notFound()
		case rp.protStatus != 0:
			f.writeJSON(w, rp.protStatus, `{"message":"Upgrade to GitHub Pro"}`)
		case rp.protection == "":
			f.writeJSON(w, 404, `{"message":"Branch not protected"}`)
		default:
			f.writeJSON(w, 200, rp.protection)
		}
	case len(rest) == 3 && rest[0] == "rules" && rest[1] == "branches":
		f.writeJSON(w, 200, paginate(rp.rules, r))
	case len(rest) == 2 && rest[0] == "rulesets":
		body, ok := rp.rulesets[rest[1]]
		if !ok || r.URL.Query().Get("includes_parents") != "true" {
			notFound()
			return
		}
		f.writeJSON(w, 200, body)
	case len(rest) == 3 && rest[0] == "git" && rest[1] == "trees":
		n, ok := f.nodes[rest[2]]
		if !ok || !n.isTree || n.repo != name {
			notFound()
			return
		}
		b, _ := json.Marshal(map[string]any{"sha": rest[2], "tree": f.treeEntries(name, n.dir, r.URL.Query().Get("recursive") == "1"), "truncated": rp.truncated && r.URL.Query().Get("recursive") == "1"})
		f.writeJSON(w, 200, string(b))
	case len(rest) == 3 && rest[0] == "git" && rest[1] == "blobs":
		n, ok := f.nodes[rest[2]]
		if !ok || n.isTree || n.repo != name {
			notFound()
			return
		}
		enc := base64.StdEncoding.EncodeToString([]byte(n.content + f.blobExtra))
		var lines []string
		for len(enc) > 60 {
			lines = append(lines, enc[:60])
			enc = enc[60:]
		}
		lines = append(lines, enc)
		b, _ := json.Marshal(map[string]any{"sha": rest[2], "encoding": "base64", "content": strings.Join(lines, "\n") + "\n", "size": len(n.content)})
		f.writeJSON(w, 200, string(b))
	case len(rest) == 2 && rest[0] == "codeowners" && rest[1] == "errors":
		if r.URL.Query().Get("ref") != rp.branch {
			notFound()
			return
		}
		f.writeJSON(w, 200, rp.coErrors)
	case len(rest) == 1 && rest[0] == "teams":
		f.writeJSON(w, 200, paginate(rp.teams, r))
	case len(rest) == 1 && rest[0] == "collaborators":
		if r.URL.Query().Get("affiliation") != "all" {
			f.writeJSON(w, 400, `{}`)
			return
		}
		f.writeJSON(w, 200, paginate(rp.collabs, r))
	default:
		notFound()
	}
}
