package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/provision"
)

var computePlan = provision.Compute

// planProbleme : une erreur Coolify perd le corps de sa réponse, qui peut
// reprendre une valeur. incertain dit qu'un nouvel essai peut réussir.
func planProbleme(err error) (msg string, incertain bool) {
	var he *coolify.HTTPError
	var ne net.Error
	switch {
	case errors.As(err, &he):
		return fmt.Sprintf("Coolify %s %s : HTTP %d", he.Method, he.Path, he.Status), he.Status >= 500
	case errors.As(err, &ne), errors.Is(err, context.DeadlineExceeded):
		return "Coolify sans réponse", true
	}
	return err.Error(), false
}

var errLectureSeule = errors.New("écriture refusée : l'audit ne fait que lire")

// lectureSeule ne transmet que les lectures. Une méthode ajoutée à
// provision.API casse la compilation ici, au lieu de passer sans garde.
type lectureSeule struct{ api provision.API }

var _ provision.API = lectureSeule{}

func (l lectureSeule) ListApplications(ctx context.Context) ([]coolify.AppSummary, error) {
	return l.api.ListApplications(ctx)
}
func (l lectureSeule) GetApplication(ctx context.Context, uuid string) (coolify.Application, error) {
	return l.api.GetApplication(ctx, uuid)
}
func (l lectureSeule) ApplicationDestinations(ctx context.Context, uuid string) ([]coolify.Destination, error) {
	return l.api.ApplicationDestinations(ctx, uuid)
}
func (l lectureSeule) GetDestination(ctx context.Context, uuid string) (coolify.Destination, error) {
	return l.api.GetDestination(ctx, uuid)
}
func (l lectureSeule) ListGithubApps(ctx context.Context) ([]coolify.GithubApp, error) {
	return l.api.ListGithubApps(ctx)
}
func (l lectureSeule) ListApplicationEnvs(ctx context.Context, uuid string) ([]coolify.Env, error) {
	return l.api.ListApplicationEnvs(ctx, uuid)
}
func (l lectureSeule) ListTeamEnvs(ctx context.Context) ([]coolify.SharedEnv, error) {
	return l.api.ListTeamEnvs(ctx)
}
func (l lectureSeule) ListServerEnvs(ctx context.Context, uuid string) ([]coolify.SharedEnv, error) {
	return l.api.ListServerEnvs(ctx, uuid)
}
func (lectureSeule) CreateApplication(context.Context, map[string]any) (string, error) {
	return "", errLectureSeule
}
func (lectureSeule) UpdateApplication(context.Context, string, map[string]any) error {
	return errLectureSeule
}
func (lectureSeule) UpsertApplicationEnvs(context.Context, string, []coolify.EnvWrite) error {
	return errLectureSeule
}
func (lectureSeule) CreateTeamEnv(context.Context, coolify.SharedEnvWrite) error {
	return errLectureSeule
}

// ProvisionVM : serveur et destination Coolify d'une VM WAF, et la référence
// de base de ses apps quand elle diffère de celle de toutes les VM.
type ProvisionVM struct {
	Server      string `json:"server"`
	Destination string `json:"destination"`
	BaseRef     string `json:"base_ref"`
}

// Provision décrit, dans WAF_OPS_PROVISION, ce qu'il faut à wafgen provision
// pour calculer le plan de chaque VM. Le jeton est celui de waf-ops : le plan
// ne fait que lire.
type Provision struct {
	Project     string                 `json:"project"`
	Environment string                 `json:"environment"`
	GithubApp   string                 `json:"github_app"`
	BaseRef     string                 `json:"base_ref"`
	VMs         map[string]ProvisionVM `json:"vms"`
}

func parseProvision(raw string) (*Provision, error) {
	if raw == "" {
		return nil, nil
	}
	var p Provision
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf(`WAF_OPS_PROVISION : JSON {"project", "environment", "github_app", "base_ref", "vms": {"<vm>": {"server", "destination", "base_ref"}}} attendu`)
	}
	if p.Project == "" || p.GithubApp == "" || len(p.VMs) == 0 {
		return nil, fmt.Errorf("WAF_OPS_PROVISION : project, github_app et vms requis")
	}
	for name, v := range p.VMs {
		if v.Server == "" || v.Destination == "" {
			return nil, fmt.Errorf("WAF_OPS_PROVISION : server et destination requis pour la VM %s", name)
		}
	}
	return &p, nil
}

// ControlePlan calcule, pour chaque VM des stages traités, le plan de
// wafgen provision, en lecture seule. Sont des écarts : une app existante à
// aligner, une app en service absente de Coolify, une action ops en attente
// (variable partagée à créer ou remplir, référence orpheline), un plan
// impossible. Une app pas encore en service qui reste à créer est une note.
// Les notes de provision peuvent citer une valeur littérale : seul leur
// nombre sort. incertains compte les plans impossibles faute de réponse.
func ControlePlan(ctx context.Context, api provision.API, p Provision, coolifyURL, token string, inv inventory.Inventory, stages map[string]bool) (ecarts, notes []string, incertains int) {
	names := make([]string, 0, len(inv.VMs))
	for _, v := range inv.VMs {
		names = append(names, v.Name)
	}
	sort.Strings(names)
	for _, vm := range inv.VMs {
		if !stages[vm.Stage] {
			continue
		}
		pv, ok := p.VMs[vm.Name]
		if !ok {
			ecarts = append(ecarts, fmt.Sprintf("provision : VM %s absente de WAF_OPS_PROVISION", vm.Name))
			continue
		}
		cfg := provision.Config{
			URL: coolifyURL, Token: token, ProjectUUID: p.Project, Environment: p.Environment,
			ServerUUID: pv.Server, DestinationUUID: pv.Destination, GithubAppUUID: p.GithubApp,
			VM: vm.Name, BaseRef: pv.BaseRef,
			// Tout l'inventaire, tous stages : sans lui, la règle Cloudflare d'une
			// app d'un autre stage dans une zone partagée sortirait « à retirer ».
			Inventory: inv.Apps,
		}
		if cfg.Environment == "" {
			cfg.Environment = "production"
		}
		if cfg.BaseRef == "" {
			cfg.BaseRef = p.BaseRef
		}
		if cfg.BaseRef == "" {
			cfg.BaseRef = provision.DefaultBaseRef
		}
		for _, n := range names {
			if n != vm.Name {
				cfg.OtherVMs = append(cfg.OtherVMs, n)
			}
		}
		var apps []inventory.App
		for _, a := range inv.Apps {
			if a.Stage == vm.Stage {
				apps = append(apps, a)
			}
		}
		plan, err := computePlan(ctx, lectureSeule{api}, cfg, apps)
		if err != nil {
			msg, inc := planProbleme(err)
			ecarts = append(ecarts, fmt.Sprintf("provision : plan de la VM %s impossible : %s", vm.Name, propre(msg, 300)))
			if inc {
				incertains++
			}
			continue
		}
		if b, n := compteNotes(plan.Notes); b > 0 {
			ecarts = append(ecarts, fmt.Sprintf("provision : VM %s : %d action(s) ops en attente, détail par wafgen provision dans le conteneur", vm.Name, b))
		} else if n > 0 {
			notes = append(notes, fmt.Sprintf("provision : VM %s : %d note(s) de plan, détail par wafgen provision dans le conteneur", vm.Name, n))
		}
		for i := range plan.Apps {
			ap := &plan.Apps[i]
			if b, n := compteNotes(ap.Notes); b > 0 {
				ecarts = append(ecarts, fmt.Sprintf("provision : %s : %d action(s) ops en attente (variable partagée à créer ou remplir, référence orpheline), détail par wafgen provision dans le conteneur", ap.Name, b))
			} else if n > 0 {
				notes = append(notes, fmt.Sprintf("provision : %s : %d note(s) de plan", ap.Name, n))
			}
			if !ap.Changed() {
				continue
			}
			if ap.Create {
				msg := fmt.Sprintf("provision : %s à créer", ap.Name)
				if ap.App.Live {
					ecarts = append(ecarts, msg+" alors que l'app est en service")
				} else {
					notes = append(notes, msg+", app pas encore en service")
				}
				continue
			}
			var keys []string
			for _, c := range ap.Fields {
				keys = append(keys, c.Key)
			}
			for _, e := range ap.Envs {
				keys = append(keys, "env "+e.Key)
			}
			ecarts = append(ecarts, fmt.Sprintf("provision : %s à aligner sur le plan de la VM %s (%s), provision --apply à relancer", ap.Name, vm.Name, strings.Join(keys, ", ")))
		}
	}
	return ecarts, notes, incertains
}

// compteNotes : notes bloquantes, puis nombre total.
func compteNotes(l []string) (bloquantes, total int) {
	for _, n := range l {
		if provision.Bloquante(n) {
			bloquantes++
		}
	}
	return bloquantes, len(l)
}
