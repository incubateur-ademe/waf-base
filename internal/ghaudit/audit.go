// Package ghaudit contrôle côté GitHub le verrou des confs WAF de chaque app
// (sections 7 et 8.1 du design), avec une App GitHub en lecture seule.
package ghaudit

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const (
	EnvAppID       = "WAF_OPS_GITHUB_APP_ID"
	EnvAppKey      = "WAF_OPS_GITHUB_APP_KEY"
	DefaultOpsOrg  = "incubateur-ademe"
	DefaultOpsTeam = "secops"
	defaultTimeout = 30 * time.Second
	// DockerfileCanonique est le waf/Dockerfile de chaque app, à l'octet près
	// (section 5.4 du design).
	DockerfileCanonique = "ARG WAF_BASE\nFROM ${WAF_BASE}\n"
	maxCodeowners       = 128 << 10
	maxListed           = 3
	maxNoted            = 20
	maxWafFiles         = 100
	maxShown            = 120
)

// Droits de l'App, tous en lecture : le jeton d'installation est demandé avec
// ces seuls droits, même si l'App en a reçu d'autres. Justification dans README.md.
var (
	repoPermissions = map[string]string{"administration": "read", "contents": "read", "metadata": "read"}
	orgPermissions  = map[string]string{"members": "read"}
)

var (
	reTeam    = regexp.MustCompile(`^[a-z0-9_-]{1,100}$`)
	reOwnerOK = regexp.MustCompile(`^` + reOwner + `$`)
	reNameOK  = regexp.MustCompile(`^` + reName + `$`)
	reRefOK   = regexp.MustCompile(`^` + reRef + `$`)
	reDirSeg  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	rePermKey = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

type Config struct {
	// Client ID de l'App (Iv…) ou App ID numérique.
	AppID   string
	Key     *rsa.PrivateKey
	API     string
	OpsOrg  string
	OpsTeam string
	HTTP    *http.Client
	Now     func() time.Time
}

// FromEnv lit WAF_OPS_GITHUB_APP_ID et WAF_OPS_GITHUB_APP_KEY, sans appel
// réseau. Aucune erreur ne cite la clé.
func FromEnv(getenv func(string) string) (Config, error) {
	id := strings.TrimSpace(getenv(EnvAppID))
	rawKey := getenv(EnvAppKey)
	var missing []string
	if id == "" {
		missing = append(missing, EnvAppID)
	}
	if strings.TrimSpace(rawKey) == "" {
		missing = append(missing, EnvAppKey)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("variables manquantes : %s", strings.Join(missing, ", "))
	}
	if !reAppID.MatchString(id) {
		return Config{}, fmt.Errorf("%s : client ID (Iv…) ou App ID numérique attendu", EnvAppID)
	}
	key, err := ParseKey(rawKey)
	if err != nil {
		return Config{}, fmt.Errorf("%s : %v", EnvAppKey, err)
	}
	return Config{AppID: id, Key: key, API: DefaultAPI, OpsOrg: DefaultOpsOrg, OpsTeam: DefaultOpsTeam}, nil
}

func (c Config) check() error {
	if !reAppID.MatchString(c.AppID) {
		return errors.New("App GitHub : client ID ou App ID invalide")
	}
	if c.Key == nil || c.Key.N.BitLen() < minKeyBits {
		return errors.New("App GitHub : clé RSA de 2048 bits au moins attendue")
	}
	u, err := url.Parse(c.API)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return errors.New("App GitHub : API https://<hôte> attendue")
	}
	if !reOwnerOK.MatchString(c.OpsOrg) || !reTeam.MatchString(c.OpsTeam) {
		return errors.New("App GitHub : org ou équipe ops invalide")
	}
	return nil
}

type target struct {
	owner, name, repo, branch, dir string
	apps                           []string
}

type auditor struct {
	cfg    Config
	c      *client
	team   string
	ops    map[string]bool
	owners map[string]bool
	done   map[string]bool
	ecarts []string
	notes  []string
}

func (a *auditor) ecart(label, format string, args ...any) {
	a.ecarts = append(a.ecarts, label+" : "+fmt.Sprintf(format, args...))
}

func (a *auditor) note(label, format string, args ...any) {
	a.notes = append(a.notes, label+" : "+fmt.Sprintf(format, args...))
}

// once dit si le contrôle de clé k reste à faire : deux apps d'un même repo ne
// rejouent ni les droits ni la protection.
func (a *auditor) once(k string) bool {
	if a.done[k] {
		return false
	}
	a.done[k] = true
	return true
}

// shown rend affichable une valeur venue de GitHub, chemin d'un arbre ou
// login : un nom de fichier admet tout octet sauf NUL et /, et finirait sinon
// tel quel dans les logs et le pulse.
func shown(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, s)
	if len(s) <= maxShown {
		return s
	}
	cut := maxShown
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// listed rend au plus n valeurs affichables, puis le nombre des autres.
func listed(l []string, n int) string {
	more := ""
	if len(l) > n {
		more = fmt.Sprintf(" (+%d)", len(l)-n)
		l = l[:n]
	}
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = shown(s)
	}
	return strings.Join(out, ", ") + more
}

func dedup(l []string) []string {
	seen := map[string]bool{}
	out := l[:0]
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Audit contrôle le repo de chaque app : CODEOWNERS qui réserve waf/ à l'équipe
// ops, équipe ops en write, aucun admin hors ops, protection de la branche
// déployée qui exige la revue des code owners, waf/Dockerfile canonique, aucun
// .dockerignore dans waf/. Un écart est une phrase courte pour le pulse, une
// note un détail pour les logs ; err dit que l'audit n'a pas pu se faire.
func Audit(ctx context.Context, cfg Config, apps []inventory.App) (ecarts, notes []string, err error) {
	if len(apps) == 0 {
		return nil, nil, nil
	}
	if cfg.API == "" {
		cfg.API = DefaultAPI
	}
	if cfg.OpsOrg == "" {
		cfg.OpsOrg = DefaultOpsOrg
	}
	if cfg.OpsTeam == "" {
		cfg.OpsTeam = DefaultOpsTeam
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := cfg.check(); err != nil {
		return nil, nil, err
	}
	a := &auditor{
		cfg:  cfg,
		c:    &client{api: strings.TrimSuffix(cfg.API, "/"), http: newHTTPClient(cfg.HTTP)},
		team: strings.ToLower("@" + cfg.OpsOrg + "/" + cfg.OpsTeam),
		done: map[string]bool{},
	}
	targets := a.targets(apps)
	if len(targets) == 0 {
		return a.ecarts, a.notes, nil
	}
	opsOrg := strings.ToLower(cfg.OpsOrg)
	opsTok, err := a.installToken(ctx, "/orgs/"+cfg.OpsOrg+"/installation", cfg.OpsOrg, true)
	if err != nil {
		return a.ecarts, a.notes, fmt.Errorf("App GitHub d'audit sur %s : %w", cfg.OpsOrg, err)
	}
	if err := a.loadOps(ctx, opsTok); err != nil {
		return a.ecarts, a.notes, err
	}
	tokens := map[string]string{opsOrg: opsTok}
	failed := map[string]error{}
	// Un 404 sur la route d'un repo vaut pour ce repo seul : l'installation de
	// l'owner peut ne pas l'avoir sélectionné et couvrir les suivants.
	outside := map[string]bool{}
	for _, t := range targets {
		o, r := strings.ToLower(t.owner), strings.ToLower(t.repo)
		if _, ok := tokens[o]; ok || failed[o] != nil || outside[r] {
			continue
		}
		tok, err := a.installToken(ctx, "/repos/"+t.owner+"/"+t.name+"/installation", t.owner, false)
		switch {
		case isStatus(err, http.StatusNotFound):
			outside[r] = true
		case err != nil:
			failed[o] = err
		default:
			tokens[o] = tok
		}
	}
	for _, t := range targets {
		o := strings.ToLower(t.owner)
		switch {
		case outside[strings.ToLower(t.repo)]:
			a.ecart(t.repo, "repo hors de l'installation de l'App d'audit, ou App non installée sur %s", t.owner)
		case failed[o] != nil:
			a.ecart(t.repo, "App d'audit GitHub inutilisable sur %s : %v", t.owner, failed[o])
		default:
			a.auditTarget(ctx, tokens[o], t)
		}
	}
	return dedup(a.ecarts), dedup(a.notes), nil
}

// targets regroupe les apps par repo, branche et dossier : deux apps qui
// partagent un waf/ ne font qu'un audit.
func (a *auditor) targets(apps []inventory.App) []target {
	byKey := map[string]*target{}
	for _, app := range apps {
		owner, name, ok := strings.Cut(app.Repo, "/")
		dir := app.WafDir
		if dir == "" {
			dir = "waf"
		}
		switch {
		case !ok || !reOwnerOK.MatchString(owner) || !reNameOK.MatchString(name) || name == "." || name == "..":
			a.ecart(app.Name, "repo %q hors de la forme <organisation>/<dépôt>", app.Repo)
			continue
		case app.Branch == "" || !reRefOK.MatchString(pathEscapeRef(app.Branch)) || strings.Contains(app.Branch, ".."):
			a.ecart(app.Name, "branche %q invalide", app.Branch)
			continue
		case !validDir(dir):
			a.ecart(app.Name, "waf_dir %q invalide", dir)
			continue
		}
		k := strings.ToLower(app.Repo) + "\x00" + app.Branch + "\x00" + dir
		t, ok := byKey[k]
		if !ok {
			t = &target{owner: owner, name: name, repo: app.Repo, branch: app.Branch, dir: dir}
			byKey[k] = t
		}
		t.apps = append(t.apps, app.Name)
	}
	out := make([]target, 0, len(byKey))
	for _, k := range sortedKeys(byKey) {
		out = append(out, *byKey[k])
	}
	return out
}

func validDir(dir string) bool {
	for _, s := range strings.Split(dir, "/") {
		if !reDirSeg.MatchString(s) || s == "." || s == ".." {
			return false
		}
	}
	return true
}

type installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
	Permissions map[string]string `json:"permissions"`
	SuspendedAt *string           `json:"suspended_at"`
}

// withOrg ajoute la lecture des membres de l'org.
func (a *auditor) installToken(ctx context.Context, instPath, account string, withOrg bool) (string, error) {
	jwt, err := appJWT(a.cfg.AppID, a.cfg.Key, a.cfg.Now())
	if err != nil {
		return "", err
	}
	var inst installation
	if err := a.c.do(ctx, http.MethodGet, instPath, nil, authApp, jwt, nil, &inst); err != nil {
		return "", err
	}
	if inst.ID <= 0 {
		return "", errors.New("installation sans identifiant")
	}
	if !strings.EqualFold(inst.Account.Login, account) {
		return "", errors.New("installation d'un autre compte")
	}
	if inst.SuspendedAt != nil {
		return "", errors.New("installation suspendue")
	}
	want := map[string]string{}
	for k, v := range repoPermissions {
		want[k] = v
	}
	if withOrg {
		for k, v := range orgPermissions {
			want[k] = v
		}
	}
	label := "App d'audit GitHub sur " + account
	var extra []string
	for _, k := range sortedKeys(inst.Permissions) {
		v := inst.Permissions[k]
		if !rePermKey.MatchString(k) || !rePermKey.MatchString(v) {
			a.ecart(label, "droit illisible dans l'installation")
			continue
		}
		if v != "read" {
			a.ecart(label, "droit %s en %s, lecture seule attendue", k, v)
			continue
		}
		if _, ok := repoPermissions[k]; !ok {
			if _, ok := orgPermissions[k]; !ok {
				extra = append(extra, k)
			}
		}
	}
	if len(extra) > 0 {
		a.note(label, "droits en lecture hors de la liste minimale : %s", strings.Join(extra, ", "))
	}
	var missing []string
	for _, k := range sortedKeys(want) {
		if _, ok := inst.Permissions[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("droits absents de l'installation : %s", strings.Join(missing, ", "))
	}
	jwt, err = appJWT(a.cfg.AppID, a.cfg.Key, a.cfg.Now())
	if err != nil {
		return "", err
	}
	var tok struct {
		Token       string            `json:"token"`
		Permissions map[string]string `json:"permissions"`
	}
	body := map[string]any{"permissions": want}
	if err := a.c.do(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", inst.ID), nil, authApp, jwt, body, &tok); err != nil {
		return "", err
	}
	if tok.Token == "" || len(tok.Token) > 1024 || strings.ContainsFunc(tok.Token, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return "", errors.New("jeton d'installation de forme inattendue")
	}
	for k, v := range tok.Permissions {
		if want[k] != v {
			return "", errors.New("jeton d'installation hors des droits demandés")
		}
	}
	return tok.Token, nil
}

type member struct {
	Login string `json:"login"`
}

// loadOps lit l'équipe ops, seuls admins admis, et les propriétaires de l'org,
// admins de chaque repo par construction : risque accepté en section 13 du design.
func (a *auditor) loadOps(ctx context.Context, tok string) error {
	label := "équipe " + a.team
	members, err := list[member](ctx, a.c, "/orgs/"+a.cfg.OpsOrg+"/teams/"+a.cfg.OpsTeam+"/members", nil, tok)
	if err != nil {
		return fmt.Errorf("%s : %w", label, err)
	}
	a.ops = map[string]bool{}
	for _, m := range members {
		a.ops[strings.ToLower(m.Login)] = true
	}
	owners, err := list[member](ctx, a.c, "/orgs/"+a.cfg.OpsOrg+"/members", url.Values{"role": {"admin"}}, tok)
	if err != nil {
		return fmt.Errorf("propriétaires de %s : %w", a.cfg.OpsOrg, err)
	}
	a.owners = map[string]bool{}
	var outside []string
	for _, m := range owners {
		l := strings.ToLower(m.Login)
		a.owners[l] = true
		if !a.ops[l] {
			outside = append(outside, l)
		}
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		a.note(a.cfg.OpsOrg, "propriétaire(s) hors de %s, admins de chaque repo (risque accepté, section 13 du design) : %s", a.team, listed(outside, maxNoted))
	}
	return nil
}

func (a *auditor) auditTarget(ctx context.Context, tok string, t target) {
	var repo struct {
		Private       bool   `json:"private"`
		Archived      bool   `json:"archived"`
		DefaultBranch string `json:"default_branch"`
	}
	err := a.c.do(ctx, http.MethodGet, "/repos/"+t.owner+"/"+t.name, nil, authInstallation, tok, nil, &repo)
	switch {
	case isStatus(err, http.StatusNotFound):
		a.ecart(t.repo, "repo introuvable ou hors de l'installation de l'App d'audit")
		return
	case isStatus(err, http.StatusMovedPermanently):
		a.ecart(t.repo, "repo renommé ou transféré, inventaire à corriger")
		return
	case err != nil:
		a.ecart(t.repo, "audit GitHub incomplet : %v", err)
		return
	}
	if repo.DefaultBranch != t.branch {
		a.note(t.repo, "branche déployée %s, branche par défaut %s : contrôles sur %s", t.branch, shown(repo.DefaultBranch), t.branch)
	}
	if repo.Archived {
		a.note(t.repo, "repo archivé")
	}
	repoKey := strings.ToLower(t.repo)
	if a.once("protection\x00" + repoKey + "\x00" + t.branch) {
		if err := a.protection(ctx, tok, t, repo.Private); err != nil {
			a.ecart(t.repo, "protection de %s non auditée : %v", t.branch, err)
		}
	}
	if err := a.files(ctx, tok, t); err != nil {
		a.ecart(t.repo, "fichiers de %s non audités : %v", t.branch, err)
	}
	if a.once("droits\x00" + repoKey) {
		if err := a.access(ctx, tok, t); err != nil {
			a.ecart(t.repo, "droits non audités : %v", err)
		}
	}
}

type teamAccess struct {
	Slug       string `json:"slug"`
	Permission string `json:"permission"`
}

type collaborator struct {
	Login       string `json:"login"`
	Permissions struct {
		Admin bool `json:"admin"`
	} `json:"permissions"`
}

func (a *auditor) access(ctx context.Context, tok string, t target) error {
	base := "/repos/" + t.owner + "/" + t.name
	inOpsOrg := strings.EqualFold(t.owner, a.cfg.OpsOrg)
	if !inOpsOrg {
		a.ecart(t.repo, "repo hors de l'org %s : CODEOWNERS ne peut pas y nommer %s (section 8.1)", a.cfg.OpsOrg, a.team)
	} else {
		teams, err := list[teamAccess](ctx, a.c, base+"/teams", nil, tok)
		if err != nil {
			return err
		}
		perm := ""
		for _, tm := range teams {
			if strings.EqualFold(tm.Slug, a.cfg.OpsTeam) {
				perm = tm.Permission
			}
		}
		switch perm {
		case "push", "maintain", "admin":
		case "":
			a.ecart(t.repo, "%s sans droit sur le repo, write attendu", a.team)
		default:
			if !rePermKey.MatchString(perm) {
				perm = "inconnu"
			}
			a.ecart(t.repo, "%s en %s, write attendu", a.team, perm)
		}
	}
	collabs, err := list[collaborator](ctx, a.c, base+"/collaborators", url.Values{"affiliation": {"all"}}, tok)
	if err != nil {
		return err
	}
	var outside []string
	for _, c := range collabs {
		l := strings.ToLower(c.Login)
		if !c.Permissions.Admin || a.ops[l] || (inOpsOrg && a.owners[l]) {
			continue
		}
		outside = append(outside, l)
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		a.ecart(t.repo, "%d admin(s) hors de %s", len(outside), a.team)
		a.note(t.repo, "admins hors de %s : %s", a.team, listed(outside, maxNoted))
	}
	return nil
}

type classicProtection struct {
	Reviews *struct {
		DismissStale bool `json:"dismiss_stale_reviews"`
		CodeOwners   bool `json:"require_code_owner_reviews"`
		Bypass       *struct {
			Users []json.RawMessage `json:"users"`
			Teams []json.RawMessage `json:"teams"`
			Apps  []json.RawMessage `json:"apps"`
		} `json:"bypass_pull_request_allowances"`
	} `json:"required_pull_request_reviews"`
	EnforceAdmins    *enabled `json:"enforce_admins"`
	AllowDeletions   *enabled `json:"allow_deletions"`
	AllowForcePushes *enabled `json:"allow_force_pushes"`
}

type enabled struct {
	Enabled bool `json:"enabled"`
}

// Section 8.1 du design. La seule approbation du dernier push ne remplace pas la
// révocation : une approbation d'ops donnée avant un nouveau commit resterait
// comptée. Supprimer une branche qui n'est pas celle par défaut puis la recréer
// par un push contourne la PR.
func (p classicProtection) manques() []string {
	r := p.Reviews
	if r == nil {
		return []string{"protection sans PR obligatoire"}
	}
	var m []string
	if !r.CodeOwners {
		m = append(m, "protection sans revue des code owners")
	}
	if !r.DismissStale {
		m = append(m, "protection sans révocation des approbations au push")
	}
	if p.EnforceAdmins == nil || !p.EnforceAdmins.Enabled {
		m = append(m, "protection non appliquée aux administrateurs")
	}
	if p.AllowDeletions != nil && p.AllowDeletions.Enabled {
		m = append(m, "protection qui permet de supprimer la branche")
	}
	if p.AllowForcePushes != nil && p.AllowForcePushes.Enabled {
		m = append(m, "protection qui permet le force push")
	}
	if b := r.Bypass; b != nil {
		if n := len(b.Users) + len(b.Teams) + len(b.Apps); n > 0 {
			m = append(m, fmt.Sprintf("protection contournable par %d acteur(s)", n))
		}
	}
	return m
}

type branchRule struct {
	Type       string          `json:"type"`
	RulesetID  int64           `json:"ruleset_id"`
	Parameters json.RawMessage `json:"parameters"`
}

type prRuleParams struct {
	CodeOwners   bool `json:"require_code_owner_review"`
	DismissStale bool `json:"dismiss_stale_reviews_on_push"`
}

// protection cherche une source unique qui verrouille la branche : la
// protection classique, ou un ruleset actif dont la liste de contournement est
// lisible et vide. GitHub ne rend cette liste qu'à qui peut modifier le
// ruleset, jamais à une App en lecture : un ruleset seul ne suffit donc pas.
func (a *auditor) protection(ctx context.Context, tok string, t target, private bool) error {
	base := "/repos/" + t.owner + "/" + t.name
	ref := pathEscapeRef(t.branch)
	var manques []string
	var cp classicProtection
	planFree := false
	err := a.c.do(ctx, http.MethodGet, base+"/branches/"+ref+"/protection", nil, authInstallation, tok, nil, &cp)
	switch {
	case err == nil:
		m := cp.manques()
		if len(m) == 0 {
			return nil
		}
		manques = append(manques, m...)
	case isStatus(err, http.StatusNotFound):
	case isStatus(err, http.StatusForbidden) && private:
		planFree = true
	default:
		return err
	}
	rules, err := list[branchRule](ctx, a.c, base+"/rules/branches/"+ref, nil, tok)
	if err != nil && !(planFree && isStatus(err, http.StatusForbidden)) {
		return err
	}
	// Les règles qui bloquent suppression et force push doivent venir du
	// ruleset dont on vérifie les contournements, pas d'un autre.
	types := map[int64]map[string]bool{}
	for _, r := range rules {
		if types[r.RulesetID] == nil {
			types[r.RulesetID] = map[string]bool{}
		}
		types[r.RulesetID][r.Type] = true
	}
	seen := map[int64]bool{}
	for _, r := range rules {
		if r.Type != "pull_request" || seen[r.RulesetID] {
			continue
		}
		seen[r.RulesetID] = true
		var p prRuleParams
		if err := json.Unmarshal(r.Parameters, &p); err != nil {
			return fmt.Errorf("règle pull_request du ruleset %d illisible", r.RulesetID)
		}
		switch {
		case !p.CodeOwners:
			manques = append(manques, fmt.Sprintf("ruleset %d sans revue des code owners", r.RulesetID))
			continue
		case !p.DismissStale:
			manques = append(manques, fmt.Sprintf("ruleset %d sans révocation des approbations au push", r.RulesetID))
			continue
		case !types[r.RulesetID]["deletion"]:
			manques = append(manques, fmt.Sprintf("ruleset %d sans blocage de la suppression de la branche", r.RulesetID))
			continue
		case !types[r.RulesetID]["non_fast_forward"]:
			manques = append(manques, fmt.Sprintf("ruleset %d sans blocage du force push", r.RulesetID))
			continue
		}
		ok, why, err := a.rulesetLocks(ctx, tok, t, r.RulesetID)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		manques = append(manques, why)
	}
	switch {
	case planFree && len(seen) == 0:
		a.ecart(t.repo, "repo privé, sans protection possible sur le plan Free : règles à porter par un repo public %s/waf-<app> (section 8.1)", a.cfg.OpsOrg)
	case len(manques) == 0:
		a.ecart(t.repo, "%s sans protection de branche ni ruleset", t.branch)
	default:
		a.ecart(t.repo, "%s sans protection vérifiable : %s", t.branch, strings.Join(manques, ", "))
	}
	return nil
}

func (a *auditor) rulesetLocks(ctx context.Context, tok string, t target, id int64) (bool, string, error) {
	var rs map[string]json.RawMessage
	p := fmt.Sprintf("/repos/%s/%s/rulesets/%d", t.owner, t.name, id)
	if err := a.c.do(ctx, http.MethodGet, p, url.Values{"includes_parents": {"true"}}, authInstallation, tok, nil, &rs); err != nil {
		return false, "", err
	}
	var enforcement string
	if err := json.Unmarshal(rs["enforcement"], &enforcement); err != nil || enforcement != "active" {
		return false, fmt.Sprintf("ruleset %d inactif", id), nil
	}
	raw, ok := rs["bypass_actors"]
	if !ok {
		a.note(t.repo, "ruleset %d : contournements illisibles par une App en lecture seule, ruleset non retenu", id)
		return false, fmt.Sprintf("ruleset %d aux contournements illisibles", id), nil
	}
	var actors []json.RawMessage
	if err := json.Unmarshal(raw, &actors); err != nil {
		return false, "", fmt.Errorf("contournements du ruleset %d illisibles", id)
	}
	if len(actors) > 0 {
		return false, fmt.Sprintf("ruleset %d contournable par %d acteur(s)", id, len(actors)), nil
	}
	return true, "", nil
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type gitTree struct {
	Entries   []treeEntry `json:"tree"`
	Truncated bool        `json:"truncated"`
}

func regular(e treeEntry) bool {
	return e.Type == "blob" && (e.Mode == "100644" || e.Mode == "100755")
}

func find(entries []treeEntry, name string) (treeEntry, bool) {
	for _, e := range entries {
		if e.Path == name {
			return e, true
		}
	}
	return treeEntry{}, false
}

func (a *auditor) tree(ctx context.Context, tok string, t target, sha string, recursive bool) (gitTree, error) {
	var q url.Values
	if recursive {
		q = url.Values{"recursive": {"1"}}
	}
	var tr gitTree
	err := a.c.do(ctx, http.MethodGet, "/repos/"+t.owner+"/"+t.name+"/git/trees/"+sha, q, authInstallation, tok, nil, &tr)
	return tr, err
}

func (a *auditor) blob(ctx context.Context, tok string, t target, e treeEntry) ([]byte, error) {
	var b struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := a.c.do(ctx, http.MethodGet, "/repos/"+t.owner+"/"+t.name+"/git/blobs/"+e.SHA, nil, authInstallation, tok, nil, &b); err != nil {
		return nil, err
	}
	if b.Encoding != "base64" {
		return nil, fmt.Errorf("blob de %s : encodage inattendu", e.Path)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b.Content, "\n", ""))
	if err != nil || int64(len(raw)) != e.Size {
		return nil, fmt.Errorf("blob de %s illisible", e.Path)
	}
	return raw, nil
}

func (a *auditor) files(ctx context.Context, tok string, t target) error {
	var br struct {
		Commit struct {
			Commit struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			} `json:"commit"`
		} `json:"commit"`
	}
	err := a.c.do(ctx, http.MethodGet, "/repos/"+t.owner+"/"+t.name+"/branches/"+pathEscapeRef(t.branch), nil, authInstallation, tok, nil, &br)
	if isStatus(err, http.StatusNotFound) {
		a.ecart(t.repo, "branche %s absente", t.branch)
		return nil
	}
	if err != nil {
		return err
	}
	root, err := a.tree(ctx, tok, t, br.Commit.Commit.Tree.SHA, false)
	if err != nil {
		return err
	}
	wafFiles, err := a.wafTree(ctx, tok, t, root)
	if err != nil {
		return err
	}
	return a.codeowners(ctx, tok, t, root, wafFiles)
}

// wafTree rend les fichiers de waf/, relatifs à waf/, pour la couverture de
// CODEOWNERS ; nil sans waf/ lisible.
func (a *auditor) wafTree(ctx context.Context, tok string, t target, root gitTree) ([]string, error) {
	cur := root
	var dir treeEntry
	for i, seg := range strings.Split(t.dir, "/") {
		e, ok := find(cur.Entries, seg)
		if !ok {
			a.ecart(t.repo, "%s/ absent de %s", t.dir, t.branch)
			return nil, nil
		}
		if e.Type != "tree" {
			a.ecart(t.repo, "%s n'est pas un dossier sur %s", t.dir, t.branch)
			return nil, nil
		}
		dir = e
		if i < strings.Count(t.dir, "/") {
			sub, err := a.tree(ctx, tok, t, e.SHA, false)
			if err != nil {
				return nil, err
			}
			cur = sub
		}
	}
	tr, err := a.tree(ctx, tok, t, dir.SHA, true)
	if err != nil {
		return nil, err
	}
	if tr.Truncated {
		a.ecart(t.repo, "arbre de %s/ tronqué par GitHub, %s/ non contrôlé", t.dir, t.dir)
		return nil, nil
	}
	var files, ignores []string
	for _, e := range tr.Entries {
		if e.Type == "tree" {
			continue
		}
		files = append(files, e.Path)
		if strings.HasSuffix(strings.ToLower(path.Base(e.Path)), ".dockerignore") {
			ignores = append(ignores, t.dir+"/"+e.Path)
		}
	}
	if len(ignores) > 0 {
		a.ecart(t.repo, "%d .dockerignore dans %s/, aucun admis : %s", len(ignores), t.dir, listed(ignores, maxListed))
	}
	if len(files) > maxWafFiles {
		a.ecart(t.repo, "%s/ porte %d fichiers, couverture de CODEOWNERS contrôlée sur les %d premiers", t.dir, len(files), maxWafFiles)
		files = files[:maxWafFiles]
	}
	df, ok := find(tr.Entries, "Dockerfile")
	switch {
	case !ok:
		a.ecart(t.repo, "%s/Dockerfile absent", t.dir)
	case !regular(df):
		a.ecart(t.repo, "%s/Dockerfile n'est pas un fichier ordinaire", t.dir)
	case df.Size != int64(len(DockerfileCanonique)):
		a.ecart(t.repo, "%s/Dockerfile différent du Dockerfile canonique", t.dir)
	default:
		b, err := a.blob(ctx, tok, t, df)
		if err != nil {
			return nil, err
		}
		if string(b) != DockerfileCanonique {
			a.ecart(t.repo, "%s/Dockerfile différent du Dockerfile canonique", t.dir)
		}
	}
	return files, nil
}

// protectedPaths : waf/ entier, fichiers admis par le lint et fichiers présents,
// CODEOWNERS en vigueur et ceux qui la masqueraient s'ils étaient créés, et les
// fichiers qui pilotent le clone du build (section 8.1 du design).
func protectedPaths(dir string, wafFiles []string, effective int) []string {
	var ps []string
	for _, f := range []string{"Dockerfile", ".dockerignore", "Dockerfile.dockerignore", "waf.yaml", "README.md",
		"coraza/config.conf", "coraza/before.conf", "coraza/after.conf", "tests/ghaudit.yaml", "ghaudit"} {
		ps = append(ps, dir+"/"+f)
	}
	for _, f := range wafFiles {
		ps = append(ps, dir+"/"+f)
	}
	ps = append(ps, codeownersPaths[:effective+1]...)
	ps = append(ps, ".gitmodules", ".gitattributes", ".lfsconfig")
	seen := map[string]bool{}
	out := ps[:0]
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func uncoveredPaths(ctx context.Context, rules []coRule, errLines map[int]bool, paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !covered(rules, errLines, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (a *auditor) codeowners(ctx context.Context, tok string, t target, root gitTree, wafFiles []string) error {
	var entry treeEntry
	effective := -1
	for i, p := range codeownersPaths {
		dir, name := path.Split(p)
		entries := root.Entries
		if dir != "" {
			d, ok := find(root.Entries, strings.TrimSuffix(dir, "/"))
			if !ok || d.Type != "tree" {
				continue
			}
			sub, err := a.tree(ctx, tok, t, d.SHA, false)
			if err != nil {
				return err
			}
			entries = sub.Entries
		}
		if e, ok := find(entries, name); ok {
			entry, effective = e, i
			break
		}
	}
	if effective < 0 {
		a.ecart(t.repo, "aucune CODEOWNERS sur %s", t.branch)
		return nil
	}
	file := codeownersPaths[effective]
	switch {
	case !regular(entry):
		a.ecart(t.repo, "%s n'est pas un fichier ordinaire", file)
		return nil
	case entry.Size > maxCodeowners:
		a.ecart(t.repo, "%s de plus de %d Kio, non lue", file, maxCodeowners>>10)
		return nil
	}
	content, err := a.blob(ctx, tok, t, entry)
	if err != nil {
		return err
	}
	var coErrs struct {
		Errors []struct {
			Line int    `json:"line"`
			Kind string `json:"kind"`
			Path string `json:"path"`
		} `json:"errors"`
	}
	q := url.Values{"ref": {t.branch}}
	if err := a.c.do(ctx, http.MethodGet, "/repos/"+t.owner+"/"+t.name+"/codeowners/errors", q, authInstallation, tok, nil, &coErrs); err != nil {
		return err
	}
	errLines := map[int]bool{}
	var lines []string
	for _, e := range coErrs.Errors {
		if e.Path == file {
			errLines[e.Line] = true
		}
		kind := e.Kind
		if len(kind) > 40 || strings.ContainsFunc(kind, func(r rune) bool { return r < ' ' || r > '~' }) {
			kind = "?"
		}
		lines = append(lines, fmt.Sprintf("ligne %d (%s)", e.Line, kind))
	}
	if len(lines) > 0 {
		a.ecart(t.repo, "%s : %d erreur(s) signalée(s) par GitHub", file, len(lines))
		a.note(t.repo, "erreurs de %s : %s", file, listed(lines, maxNoted))
	}
	rules := parseCodeowners(content, a.team)
	if len(rules) > maxRules {
		a.ecart(t.repo, "%s de plus de %d règles, non lue", file, maxRules)
		return nil
	}
	uncovered, err := uncoveredPaths(ctx, rules, errLines, protectedPaths(t.dir, wafFiles, effective))
	if err != nil {
		return err
	}
	if len(uncovered) > 0 {
		a.ecart(t.repo, "%s ne réserve pas à %s : %s", file, a.team, listed(uncovered, maxListed))
		a.note(t.repo, "fichiers hors de %s dans %s : %s", a.team, file, listed(uncovered, maxNoted))
	}
	return nil
}
