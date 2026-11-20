package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/coolify"
)

// Durée de vie d'un blob, un an (IDR-0038).
const blobTTL = 365 * 24 * 3600

// BlobRequest reprend le format de /api/generate de FGP, sans le jeton ni la
// clé, que l'opérateur ajoute à la génération (scaleway/waf-1/fgp/README.md du
// repo infra).
type BlobRequest struct {
	Name   string   `json:"name"`
	Target string   `json:"target"`
	Auth   string   `json:"auth"`
	Scopes []string `json:"scopes"`
	TTL    int      `json:"ttl"`
}

// Scopes rend, par région, la demande du blob d'API de lecture : pour chaque app
// Scalingo des stages traités, les règles du firewall, les domaines et
// l'Activity. Une app sans UPSTREAM lisible arrête la génération, qui serait
// sinon incomplète sans le dire.
func Scopes(ctx context.Context, cfg Config, team TeamEnvs) (map[string]BlobRequest, error) {
	var r Rapport
	inv, err := loadInventory(ctx, cfg, nowFunc(), &r)
	if err != nil {
		return nil, err
	}
	// Un blob vaut un an : il ne part que d'un inventaire relu, jamais du cache.
	if r.Cache {
		return nil, fmt.Errorf("scopes non générés, inventaire non relu : %s", strings.Join(r.Notes, " ; "))
	}
	envs, err := team.ListTeamEnvs(ctx)
	if err != nil {
		return nil, fmt.Errorf("variables d'équipe Coolify : %w", err)
	}
	m := map[string]coolify.SharedEnv{}
	for _, e := range envs {
		m[e.Key] = e
	}
	apps := map[string]map[string]bool{}
	var problems []string
	for _, a := range inv.Apps {
		if !cfg.Stages[a.Stage] || a.Platform != "scalingo" {
			continue
		}
		key := "UPSTREAM_" + a.EnvSuffix()
		up := teamValue(m, key)
		if !up.exists || !up.readable {
			problems = append(problems, fmt.Sprintf("%s : %s absente ou illisible", a.Name, key))
			continue
		}
		app, region, err := scalingoTarget(up.value)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s : %s : %v", a.Name, key, err))
			continue
		}
		if apps[region] == nil {
			apps[region] = map[string]bool{}
		}
		apps[region][app] = true
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("scopes incomplets : %s", strings.Join(problems, " ; "))
	}
	out := map[string]BlobRequest{}
	for region, set := range apps {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		var scopes []string
		for _, n := range names {
			for _, res := range []string{"firewall_rules", "domains", "events"} {
				scopes = append(scopes, "GET:/v1/apps/"+n+"/"+res)
			}
		}
		out[region] = BlobRequest{
			Name:   "waf-ops lecture " + region,
			Target: "https://api." + region + ".scalingo.com",
			Auth:   "scalingo-exchange",
			Scopes: scopes,
			TTL:    blobTTL,
		}
	}
	return out, nil
}

func writeScopes(w io.Writer, s map[string]BlobRequest) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}
