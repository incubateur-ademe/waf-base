package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/provision"
)

var computePlan = provision.Compute

var errLectureSeule = errors.New("écriture refusée : l'audit ne fait que lire")

// lectureSeule refuse les écritures de l'API avant tout appel réseau, quel que
// soit le jeton.
type lectureSeule struct{ provision.API }

func (lectureSeule) CreateApplication(context.Context, map[string]any) (string, error) {
	return "", errLectureSeule
}
func (lectureSeule) UpdateApplication(context.Context, string, map[string]any) error {
	return errLectureSeule
}
func (lectureSeule) UpsertApplicationEnvs(context.Context, string, []coolify.EnvWrite) error {
	return errLectureSeule
}

// ProvisionVM : serveur et destination Coolify d'une VM WAF.
type ProvisionVM struct {
	Server      string `json:"server"`
	Destination string `json:"destination"`
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
		return nil, fmt.Errorf(`WAF_OPS_PROVISION : JSON {"project", "environment", "github_app", "base_ref", "vms": {"<vm>": {"server", "destination"}}} attendu`)
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
// wafgen provision. Une dérive d'une app existante, ou une app en service
// absente de Coolify, est un écart : provision --apply est à relancer. Une app
// pas encore en service qui reste à créer est une note. Seuls les noms des
// champs et des variables sortent, jamais leurs valeurs.
func ControlePlan(ctx context.Context, api provision.API, p Provision, coolifyURL, token string, inv inventory.Inventory, stages map[string]bool) (ecarts, notes []string) {
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
			VM: vm.Name, BaseRef: p.BaseRef,
		}
		if cfg.Environment == "" {
			cfg.Environment = "production"
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
			ecarts = append(ecarts, fmt.Sprintf("provision : plan de la VM %s impossible", vm.Name))
			notes = append(notes, fmt.Sprintf("provision : VM %s : %v", vm.Name, err))
			continue
		}
		for _, n := range plan.Notes {
			notes = append(notes, fmt.Sprintf("provision : VM %s : %s", vm.Name, n))
		}
		for i := range plan.Apps {
			ap := &plan.Apps[i]
			for _, n := range ap.Notes {
				notes = append(notes, fmt.Sprintf("provision : %s : %s", ap.Name, n))
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
			ecarts = append(ecarts, fmt.Sprintf("provision : %s diffère de l'inventaire (%s), provision --apply à relancer", ap.Name, strings.Join(keys, ", ")))
		}
	}
	return ecarts, notes
}
