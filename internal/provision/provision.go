// Package provision aligne les apps WAF de Coolify sur l'inventaire : état voulu,
// plan des écarts, puis écriture sur demande.
package provision

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

type API interface {
	ListApplications(ctx context.Context) ([]coolify.AppSummary, error)
	GetApplication(ctx context.Context, uuid string) (coolify.Application, error)
	ApplicationDestinations(ctx context.Context, uuid string) ([]coolify.Destination, error)
	GetDestination(ctx context.Context, uuid string) (coolify.Destination, error)
	ListGithubApps(ctx context.Context) ([]coolify.GithubApp, error)
	CreateApplication(ctx context.Context, body map[string]any) (string, error)
	UpdateApplication(ctx context.Context, uuid string, body map[string]any) error
	ListApplicationEnvs(ctx context.Context, uuid string) ([]coolify.Env, error)
	UpsertApplicationEnvs(ctx context.Context, uuid string, envs []coolify.EnvWrite) error
	ListTeamEnvs(ctx context.Context) ([]coolify.SharedEnv, error)
	CreateTeamEnv(ctx context.Context, key, value string) error
}

// Réseau Docker de la destination par défaut d'un serveur Coolify : un WAF qui
// s'y trouverait sortirait sans passer le firewall waf-egress.
const forbiddenNetwork = "coolify"

func ResourceName(app inventory.App, vm string) string {
	return "waf-" + app.Name + "-" + vm
}

// ---------- état voulu

type kind int

const (
	plain kind = iota
	domains
	repo
)

type field struct {
	key  string
	read string
	want any
	kind kind
}

func Domains(app inventory.App) []string {
	out := make([]string, 0, len(app.Hosts))
	for _, h := range app.Hosts {
		if app.Live {
			out = append(out, "https://"+h)
		} else {
			out = append(out, "http://"+h+":8080")
		}
	}
	return out
}

func wantFields(app inventory.App) []field {
	s := func(k string) string { return "settings." + k }
	return []field{
		{"git_repository", "git_repository", app.Repo, repo},
		{"git_branch", "git_branch", app.Branch, plain},
		{"build_pack", "build_pack", "dockerfile", plain},
		{"base_directory", "base_directory", "/" + app.WafDir, plain},
		{"dockerfile_location", "dockerfile_location", "/Dockerfile", plain},
		{"watch_paths", "watch_paths", app.WafDir + "/**", plain},
		{"ports_exposes", "ports_exposes", "8080", plain},
		{"ports_mappings", "ports_mappings", nil, plain},
		{"domains", "fqdn", strings.Join(Domains(app), ","), domains},
		{"health_check_enabled", "health_check_enabled", true, plain},
		{"health_check_path", "health_check_path", "/healthz", plain},
		{"health_check_port", "health_check_port", 2020, plain},
		{"health_check_interval", "health_check_interval", 2, plain},
		{"health_check_retries", "health_check_retries", 3, plain},
		{"health_check_timeout", "health_check_timeout", 5, plain},
		{"health_check_start_period", "health_check_start_period", 60, plain},
		{"limits_memory", "limits_memory", app.LimitsMemory(), plain},
		{"limits_cpu_shares", "limits_cpu_shares", app.CPUWeight, plain},
		{"is_preview_deployments_enabled", s("is_preview_deployments_enabled"), false, plain},
		{"is_pr_deployments_public_enabled", s("is_pr_deployments_public_enabled"), false, plain},
		{"is_git_submodules_enabled", s("is_git_submodules_enabled"), false, plain},
		{"is_git_lfs_enabled", s("is_git_lfs_enabled"), false, plain},
		{"use_build_secrets", s("use_build_secrets"), false, plain},
		{"inject_build_args_to_dockerfile", s("inject_build_args_to_dockerfile"), false, plain},
		{"include_source_commit_in_build", s("include_source_commit_in_build"), false, plain},
		{"is_auto_deploy_enabled", s("is_auto_deploy_enabled"), true, plain},
		{"is_force_https_enabled", s("is_force_https_enabled"), app.Live, plain},
		{"stop_grace_period", s("stop_grace_period"), 20, plain},
	}
}

type envWant struct {
	key       string
	value     string
	buildtime bool
	shared    string
}

func Ref(key string) string { return "{{team." + key + "}}" }

func wantEnvs(app inventory.App, cfg Config) []envWant {
	sfx := app.EnvSuffix()
	out := []envWant{
		{key: "WAF_TENANT", value: app.Name},
		{key: "WAF_HOSTS", value: strings.Join(app.Hosts, ",")},
		{key: "WAF_HOST_HEADER", value: app.HostHeader},
		{key: "WAF_PLATFORM", value: app.Platform},
		{key: "WAF_CRS_PLUGINS", value: strings.Join(app.CRSPlugins, ",")},
		{key: "WAF_CEILINGS", value: app.Ceilings.Env()},
		{key: "UPSTREAM", shared: "UPSTREAM_" + sfx},
		{key: "WAF_DETECTION_UNTIL", shared: "DETECTION_UNTIL_" + sfx},
		{key: "WAF_UNINSPECTED_PATHS", shared: "UNINSPECTED_PATHS_" + sfx},
		{key: "WAF_FORCE_DETECTION", shared: "FORCE_DETECTION_" + sfx},
	}
	if app.Platform == "koyeb" {
		out = append(out, envWant{key: "ORIGIN_TOKEN", shared: "ORIGIN_TOKEN_" + sfx})
	}
	for i := range out {
		if out[i].shared != "" {
			out[i].value = Ref(out[i].shared)
		}
	}
	return append(out, envWant{key: "WAF_BASE", value: cfg.BaseRef, buildtime: true})
}

// ---------- plan

type Change struct {
	Key, Old, New string
}

type EnvChange struct {
	Key, Old, New string
	Write         coolify.EnvWrite
}

type AppPlan struct {
	App    inventory.App
	Name   string
	UUID   string
	Create bool
	Fields []Change
	Envs   []EnvChange
	Notes  []string
	patch  map[string]any
}

func (a *AppPlan) Changed() bool {
	return a.Create || len(a.Fields) > 0 || len(a.Envs) > 0
}

type Plan struct {
	SharedCreate []string
	Apps         []AppPlan
	Notes        []string
	githubAppID  int64
}

// Changes compte les changements que --apply écrirait. Une création compte pour un.
func (p *Plan) Changes() int {
	n := len(p.SharedCreate)
	for i := range p.Apps {
		a := &p.Apps[i]
		if a.Create {
			n++
		} else {
			n += len(a.Fields)
		}
		n += len(a.Envs)
	}
	return n
}

type shared struct {
	exists bool
	known  bool
	empty  bool
}

func sharedState(m map[string]coolify.SharedEnv, key string) shared {
	e, ok := m[key]
	if !ok {
		return shared{}
	}
	if !e.Value.Set || e.IsShownOnce {
		return shared{exists: true}
	}
	return shared{exists: true, known: true, empty: e.Value.Null || strings.TrimSpace(e.Value.Value) == ""}
}

func lookup(app coolify.Application, path string) any {
	var cur any = map[string]any(app)
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func norm(k kind, v any) string {
	var s string
	switch x := v.(type) {
	case nil:
		s = ""
	case string:
		s = x
	case bool:
		s = strconv.FormatBool(x)
	case int:
		s = strconv.Itoa(x)
	case int64:
		s = strconv.FormatInt(x, 10)
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		s = fmt.Sprint(x)
	}
	switch k {
	case domains:
		var l []string
		for _, d := range strings.Split(s, ",") {
			if d = strings.TrimRight(strings.ToLower(strings.TrimSpace(d)), "/"); d != "" {
				l = append(l, d)
			}
		}
		sort.Strings(l)
		s = strings.Join(l, ",")
	case repo:
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "https://github.com/")
		s = strings.TrimSuffix(s, ".git")
	}
	return s
}

func show(v any) string {
	s := norm(plain, v)
	if s == "" {
		return "(vide)"
	}
	return s
}

func fieldChanges(cur coolify.Application, app inventory.App, ghID int64) ([]Change, map[string]any) {
	var ch []Change
	patch := map[string]any{}
	for _, f := range wantFields(app) {
		old := lookup(cur, f.read)
		if norm(f.kind, old) != norm(f.kind, f.want) {
			ch = append(ch, Change{f.key, show(old), show(f.want)})
			patch[f.key] = f.want
		}
	}
	srcType, _ := lookup(cur, "source_type").(string)
	srcID := norm(plain, lookup(cur, "source_id"))
	if !strings.HasSuffix(srcType, "GithubApp") || srcID != strconv.FormatInt(ghID, 10) {
		ch = append(ch, Change{"source", fmt.Sprintf("%s #%s", show(srcType), show(srcID)), fmt.Sprintf("GithubApp #%d", ghID)})
		patch["github_app_uuid"] = nil
	}
	return ch, patch
}

func showEnv(key, v string) string {
	if key == "ORIGIN_TOKEN" && !strings.Contains(v, "{{") && v != "" {
		return "(valeur masquée)"
	}
	return strconv.Quote(v)
}

func envValue(e coolify.Env) string {
	if e.Value.Null {
		return ""
	}
	return e.Value.Value
}

func checkDestination(d coolify.Destination, cfg Config) error {
	if d.Network == "" || d.Network == forbiddenNetwork {
		return fmt.Errorf("destination %s sur le réseau %q : refusée, le WAF doit être sur le réseau waf du serveur", d.UUID, d.Network)
	}
	if d.UUID != cfg.DestinationUUID {
		return fmt.Errorf("destination %s attendue, %s trouvée ; provision ne déplace pas une app", cfg.DestinationUUID, d.UUID)
	}
	if d.ServerUUID != "" && d.ServerUUID != cfg.ServerUUID {
		return fmt.Errorf("destination %s sur le serveur %s, %s attendu", d.UUID, d.ServerUUID, cfg.ServerUUID)
	}
	return nil
}

func checkAppDestination(ctx context.Context, api API, uuid string, cfg Config) error {
	ds, err := api.ApplicationDestinations(ctx, uuid)
	if err != nil {
		return err
	}
	for _, d := range ds {
		if d.IsPrimary {
			return checkDestination(d, cfg)
		}
	}
	return fmt.Errorf("aucune destination principale")
}

var reTeamRef = regexp.MustCompile(`\{\{\s*team\.([A-Za-z0-9_]+)\s*\}\}`)

// Compute lit Coolify et calcule le plan. Il n'écrit rien.
func Compute(ctx context.Context, api API, cfg Config, apps []inventory.App) (*Plan, error) {
	dest, err := api.GetDestination(ctx, cfg.DestinationUUID)
	if err != nil {
		return nil, err
	}
	if err := checkDestination(dest, cfg); err != nil {
		return nil, err
	}
	ghs, err := api.ListGithubApps(ctx)
	if err != nil {
		return nil, err
	}
	p := &Plan{}
	for _, g := range ghs {
		if g.UUID == cfg.GithubAppUUID {
			p.githubAppID = g.ID
		}
	}
	if p.githubAppID == 0 {
		return nil, fmt.Errorf("App GitHub %s introuvable pour ce jeton", cfg.GithubAppUUID)
	}
	teamList, err := api.ListTeamEnvs(ctx)
	if err != nil {
		return nil, err
	}
	team := map[string]coolify.SharedEnv{}
	for _, e := range teamList {
		team[e.Key] = e
	}
	for _, m := range reTeamRef.FindAllStringSubmatch(cfg.BaseRef, -1) {
		if st := sharedState(team, m[1]); !st.exists || (st.known && st.empty) {
			p.Notes = append(p.Notes, fmt.Sprintf("action ops : la variable d'équipe %s, visée par WAF_OPS_BASE_REF, est absente ou vide ; tout build échouera", m[1]))
		}
	}
	list, err := api.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	toCreate := map[string]bool{}
	for _, app := range apps {
		ap, err := computeApp(ctx, api, cfg, app, list, team, p.githubAppID, toCreate)
		if err != nil {
			return nil, fmt.Errorf("%s : %w", ResourceName(app, cfg.VM), err)
		}
		p.Apps = append(p.Apps, ap)
	}
	for k := range toCreate {
		p.SharedCreate = append(p.SharedCreate, k)
	}
	sort.Strings(p.SharedCreate)
	return p, nil
}

func computeApp(ctx context.Context, api API, cfg Config, app inventory.App, list []coolify.AppSummary, team map[string]coolify.SharedEnv, ghID int64, toCreate map[string]bool) (AppPlan, error) {
	ap := AppPlan{App: app, Name: ResourceName(app, cfg.VM)}
	for _, a := range list {
		if a.Name == ap.Name {
			if ap.UUID != "" {
				return ap, fmt.Errorf("plusieurs apps Coolify portent ce nom")
			}
			ap.UUID = a.UUID
		}
	}
	current := map[string]coolify.Env{}
	if ap.UUID == "" {
		ap.Create = true
		for _, f := range wantFields(app) {
			ap.Fields = append(ap.Fields, Change{f.key, "", show(f.want)})
		}
		ap.Fields = append(ap.Fields, Change{"source", "", fmt.Sprintf("GithubApp #%d", ghID)})
	} else {
		if err := checkAppDestination(ctx, api, ap.UUID, cfg); err != nil {
			return ap, err
		}
		cur, err := api.GetApplication(ctx, ap.UUID)
		if err != nil {
			return ap, err
		}
		ap.Fields, ap.patch = fieldChanges(cur, app, ghID)
		envs, err := api.ListApplicationEnvs(ctx, ap.UUID)
		if err != nil {
			return ap, err
		}
		for _, e := range envs {
			if e.IsPreview {
				continue
			}
			if _, dup := current[e.Key]; dup {
				return ap, fmt.Errorf("variable %s en double", e.Key)
			}
			current[e.Key] = e
		}
	}

	wanted := map[string]bool{}
	for _, w := range wantEnvs(app, cfg) {
		wanted[w.key] = true
		write := coolify.EnvWrite{Key: w.key, IsBuildtime: w.buildtime, IsRuntime: !w.buildtime}
		value := w.value
		var st shared
		if w.shared != "" {
			st = sharedState(team, w.shared)
			if !st.exists {
				toCreate[w.shared] = true
			}
		}
		e, ok := current[w.key]
		if ok && !e.Value.Set {
			return ap, fmt.Errorf("valeur de %s illisible : le jeton doit avoir read:sensitive", w.key)
		}
		old := envValue(e)
		valueOK := ok && old == value
		literalKept := false
		if ok && !valueOK && w.shared != "" && strings.TrimSpace(old) != "" && !strings.Contains(old, "{{") {
			// Une valeur littérale en service ne cède la place à la référence que si
			// la variable partagée est remplie : sinon l'app perdrait sa valeur.
			if st.known && !st.empty {
				ap.Notes = append(ap.Notes, fmt.Sprintf("%s : valeur littérale remplacée par %s, remplie", w.key, value))
			} else {
				ap.Notes = append(ap.Notes, fmt.Sprintf("%s : valeur littérale %s conservée, %s étant absente, vide ou illisible", w.key, showEnv(w.key, old), w.shared))
				valueOK, literalKept = true, true
			}
		}
		if w.key == "UPSTREAM" || w.key == "ORIGIN_TOKEN" {
			switch {
			case (!st.exists || (st.known && st.empty)) && literalKept:
				ap.Notes = append(ap.Notes, fmt.Sprintf("action ops : saisir %s dans l'UI Coolify (variables partagées de l'équipe), puis relancer provision pour remplacer la valeur littérale", w.shared))
			case !st.exists || (st.known && st.empty):
				ap.Notes = append(ap.Notes, fmt.Sprintf("action ops : saisir %s dans l'UI Coolify (variables partagées de l'équipe), sinon wafgen run refuse de démarrer", w.shared))
			case !st.known:
				ap.Notes = append(ap.Notes, fmt.Sprintf("valeur de %s illisible (jeton sans read:sensitive ou variable verrouillée) : non vérifiée", w.shared))
			}
		}
		if !ok {
			write.Value = &value
			ap.Envs = append(ap.Envs, EnvChange{w.key, "(absente)", showEnv(w.key, value), write})
			continue
		}
		flagsOK := e.IsBuildtime == write.IsBuildtime && e.IsRuntime == write.IsRuntime
		if valueOK && flagsOK {
			continue
		}
		oldS := showEnv(w.key, old)
		newS := oldS
		if !valueOK {
			write.Value = &value
			newS = showEnv(w.key, value)
		}
		if !flagsOK {
			oldS += fmt.Sprintf(" build=%t runtime=%t", e.IsBuildtime, e.IsRuntime)
			newS += fmt.Sprintf(" build=%t runtime=%t", write.IsBuildtime, write.IsRuntime)
		}
		ap.Envs = append(ap.Envs, EnvChange{w.key, oldS, newS, write})
	}
	var extra []string
	for k := range current {
		if !wanted[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		ap.Notes = append(ap.Notes, fmt.Sprintf("variable hors liste conservée : %s", k))
	}
	return ap, nil
}

// ---------- application

func createBody(ap *AppPlan, cfg Config) map[string]any {
	b := map[string]any{
		"project_uuid":        cfg.ProjectUUID,
		"environment_name":    cfg.Environment,
		"server_uuid":         cfg.ServerUUID,
		"destination_uuid":    cfg.DestinationUUID,
		"github_app_uuid":     cfg.GithubAppUUID,
		"name":                ap.Name,
		"autogenerate_domain": false,
		"instant_deploy":      false,
		"tags":                []string{"waf", "waf-" + cfg.VM, "waf-app-" + ap.App.Name},
	}
	for _, f := range wantFields(ap.App) {
		if f.want != nil {
			b[f.key] = f.want
		}
	}
	return b
}

func withGithubApp(patch map[string]any, cfg Config) map[string]any {
	if _, ok := patch["github_app_uuid"]; ok {
		patch["github_app_uuid"] = cfg.GithubAppUUID
	}
	return patch
}

// Apply écrit le plan : variables partagées absentes, création ou mise à jour des
// apps, puis leurs variables. Il ne déclenche aucun déploiement.
func Apply(ctx context.Context, api API, cfg Config, p *Plan) error {
	for _, k := range p.SharedCreate {
		if err := api.CreateTeamEnv(ctx, k, ""); err != nil {
			return err
		}
	}
	for i := range p.Apps {
		ap := &p.Apps[i]
		if !ap.Changed() {
			continue
		}
		if ap.Create {
			uuid, err := api.CreateApplication(ctx, createBody(ap, cfg))
			if err != nil {
				return fmt.Errorf("%s : %w", ap.Name, err)
			}
			ap.UUID = uuid
			if err := checkAppDestination(ctx, api, uuid, cfg); err != nil {
				return fmt.Errorf("%s créée, mais %w ; rien d'autre n'est écrit sur cette app", ap.Name, err)
			}
			cur, err := api.GetApplication(ctx, uuid)
			if err != nil {
				return fmt.Errorf("%s : %w", ap.Name, err)
			}
			_, ap.patch = fieldChanges(cur, ap.App, p.githubAppID)
		}
		if len(ap.patch) > 0 {
			if err := api.UpdateApplication(ctx, ap.UUID, withGithubApp(ap.patch, cfg)); err != nil {
				return fmt.Errorf("%s : %w", ap.Name, err)
			}
		}
		if len(ap.Envs) > 0 {
			ws := make([]coolify.EnvWrite, 0, len(ap.Envs))
			for _, e := range ap.Envs {
				ws = append(ws, e.Write)
			}
			if err := api.UpsertApplicationEnvs(ctx, ap.UUID, ws); err != nil {
				return fmt.Errorf("%s : %w", ap.Name, err)
			}
		}
	}
	return nil
}

// ---------- affichage

func Print(w io.Writer, p *Plan) {
	for _, n := range p.Notes {
		fmt.Fprintf(w, "! %s\n", n)
	}
	for _, k := range p.SharedCreate {
		fmt.Fprintf(w, "+ variable d'équipe %s, créée vide\n", k)
	}
	for i := range p.Apps {
		a := &p.Apps[i]
		switch {
		case a.Create:
			fmt.Fprintf(w, "\n%s : création\n", a.Name)
			for _, c := range a.Fields {
				fmt.Fprintf(w, "  %s = %s\n", c.Key, c.New)
			}
		case a.Changed():
			fmt.Fprintf(w, "\n%s (%s) : mise à jour\n", a.Name, a.UUID)
			for _, c := range a.Fields {
				fmt.Fprintf(w, "  ~ %s : %s -> %s\n", c.Key, c.Old, c.New)
			}
		default:
			fmt.Fprintf(w, "\n%s (%s) : conforme\n", a.Name, a.UUID)
		}
		for _, e := range a.Envs {
			if e.Old == "(absente)" {
				fmt.Fprintf(w, "  + env %s = %s\n", e.Key, e.New)
			} else {
				fmt.Fprintf(w, "  ~ env %s : %s -> %s\n", e.Key, e.Old, e.New)
			}
		}
		for _, n := range a.Notes {
			fmt.Fprintf(w, "  ! %s\n", n)
		}
		switch {
		case a.Create:
			fmt.Fprintf(w, "  ! premier déploiement à lancer depuis Coolify une fois les variables partagées saisies\n")
		case a.Changed():
			fmt.Fprintf(w, "  ! redéploiement nécessaire après --apply : provision ne déploie pas\n")
		}
	}
	fmt.Fprintf(w, "\n%d changement(s) prévu(s)\n", p.Changes())
}

// Run calcule le plan, l'affiche et, avec apply, l'écrit puis vérifie qu'un
// second calcul est vide.
func Run(ctx context.Context, api API, cfg Config, apps []inventory.App, apply bool, w io.Writer) error {
	p, err := Compute(ctx, api, cfg, apps)
	if err != nil {
		return err
	}
	Print(w, p)
	if p.Changes() == 0 {
		return nil
	}
	if !apply {
		fmt.Fprintln(w, "plan seul : relancer avec --apply pour écrire")
		return nil
	}
	if err := Apply(ctx, api, cfg, p); err != nil {
		return err
	}
	again, err := Compute(ctx, api, cfg, apps)
	if err != nil {
		return fmt.Errorf("second calcul : %w", err)
	}
	if again.Changes() > 0 {
		fmt.Fprintln(w, "\nsecond calcul :")
		Print(w, again)
		return fmt.Errorf("idempotence : le second calcul prévoit encore %d changement(s)", again.Changes())
	}
	fmt.Fprintln(w, "\nécritures faites ; idempotence vérifiée : le second calcul ne prévoit aucun changement")
	return nil
}
