package provision

import (
	"fmt"
	"regexp"
	"strings"
)

type Config struct {
	URL             string
	Token           string
	ProjectUUID     string
	Environment     string
	ServerUUID      string
	DestinationUUID string
	GithubAppUUID   string
	VM              string
	BaseRef         string
}

const DefaultBaseRef = "{{team.WAF_BASE}}"

var (
	reUUID        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reVM          = regexp.MustCompile(`^[1-9][0-9]?$`)
	reEnvironment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// LoadConfig lit la configuration dans l'environnement. Elle ne fait aucun appel
// réseau et liste d'un coup toutes les variables requises manquantes.
func LoadConfig(getenv func(string) string) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := Config{
		URL:             get("COOLIFY_URL"),
		Token:           get("COOLIFY_TOKEN"),
		ProjectUUID:     get("WAF_OPS_PROJECT_UUID"),
		Environment:     get("WAF_OPS_ENVIRONMENT"),
		ServerUUID:      get("WAF_OPS_SERVER_UUID"),
		DestinationUUID: get("WAF_OPS_DESTINATION_UUID"),
		GithubAppUUID:   get("WAF_OPS_GITHUB_APP_UUID"),
		VM:              get("WAF_OPS_VM"),
		BaseRef:         get("WAF_OPS_BASE_REF"),
	}
	var missing []string
	for _, r := range []struct{ k, v string }{
		{"COOLIFY_URL", c.URL},
		{"COOLIFY_TOKEN", c.Token},
		{"WAF_OPS_PROJECT_UUID", c.ProjectUUID},
		{"WAF_OPS_SERVER_UUID", c.ServerUUID},
		{"WAF_OPS_DESTINATION_UUID", c.DestinationUUID},
		{"WAF_OPS_GITHUB_APP_UUID", c.GithubAppUUID},
	} {
		if r.v == "" {
			missing = append(missing, r.k)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("variables manquantes : %s", strings.Join(missing, ", "))
	}
	if c.Environment == "" {
		c.Environment = "production"
	}
	if c.VM == "" {
		c.VM = "1"
	}
	if c.BaseRef == "" {
		c.BaseRef = DefaultBaseRef
	}
	for _, r := range []struct{ k, v string }{
		{"WAF_OPS_PROJECT_UUID", c.ProjectUUID},
		{"WAF_OPS_SERVER_UUID", c.ServerUUID},
		{"WAF_OPS_DESTINATION_UUID", c.DestinationUUID},
		{"WAF_OPS_GITHUB_APP_UUID", c.GithubAppUUID},
	} {
		if !reUUID.MatchString(r.v) {
			return Config{}, fmt.Errorf("%s invalide", r.k)
		}
	}
	if !reEnvironment.MatchString(c.Environment) {
		return Config{}, fmt.Errorf("WAF_OPS_ENVIRONMENT invalide")
	}
	if !reVM.MatchString(c.VM) {
		return Config{}, fmt.Errorf("WAF_OPS_VM %q : numéro de VM attendu", c.VM)
	}
	return c, nil
}
