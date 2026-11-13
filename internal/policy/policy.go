package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Range [2]int

func (r Range) Has(id int) bool { return id >= r[0] && id <= r[1] }

type Regles struct {
	Excluables             []Range  `yaml:"excluables"`
	FamilleMax             int      `yaml:"famille_max"`
	Protegees              []Range  `yaml:"protegees"`
	IDsTenant              Range    `yaml:"ids_tenant"`
	TagsRetirables         []string `yaml:"tags_retirables"`
	PrefixesTagsRetirables []string `yaml:"prefixes_tags_retirables"`
}

type Formes struct {
	Config struct {
		BlockingPL     Range    `yaml:"blocking_paranoia_level"`
		DetectionPLMax int      `yaml:"detection_paranoia_level_max"`
		Threshold      Range    `yaml:"inbound_anomaly_score_threshold"`
		AllowedMethods []string `yaml:"allowed_methods"`
	} `yaml:"config"`
	Exclusions struct {
		CheminsMaxParFamille int      `yaml:"chemins_max_par_famille"`
		FamillesMaxParChemin int      `yaml:"familles_max_par_chemin"`
		Collections          []string `yaml:"collections"`
		RegexLitterauxMin    int      `yaml:"regex_litteraux_min"`
		TypesDeContenu       []string `yaml:"types_de_contenu"`
		MethodesChain        []string `yaml:"methodes_chain"`
	} `yaml:"exclusions"`
	RateLimit struct {
		PlafondMaxParSeconde int `yaml:"plafond_max_par_seconde"`
	} `yaml:"rate_limit"`
	Durcissement struct {
		Operateurs []string `yaml:"operateurs"`
		Variables  []string `yaml:"variables"`
		Statuts    []int    `yaml:"statuts"`
	} `yaml:"durcissement"`
}

type Policy struct {
	Regles   Regles
	Formes   Formes
	Origines map[string][]*regexp.Regexp
}

func decode(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%s : %w", path, err)
	}
	return nil
}

func Load(dir string) (*Policy, error) {
	p := &Policy{Origines: map[string][]*regexp.Regexp{}}
	if err := decode(filepath.Join(dir, "regles.yaml"), &p.Regles); err != nil {
		return nil, err
	}
	if err := decode(filepath.Join(dir, "formes.yaml"), &p.Formes); err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := decode(filepath.Join(dir, "origines.yaml"), &raw); err != nil {
		return nil, err
	}
	for plat, pats := range raw {
		p.Origines[plat] = []*regexp.Regexp{}
		for _, s := range pats {
			re, err := regexp.Compile(s)
			if err != nil {
				return nil, fmt.Errorf("origines.yaml %s : %w", plat, err)
			}
			p.Origines[plat] = append(p.Origines[plat], re)
		}
	}
	if p.Regles.FamilleMax <= 0 || len(p.Regles.Excluables) == 0 {
		return nil, fmt.Errorf("regles.yaml incomplet")
	}
	return p, nil
}

func (p *Policy) Excluable(start, end int) bool {
	for _, r := range p.Regles.Excluables {
		if start >= r[0] && end <= r[1] {
			return true
		}
	}
	return false
}

func (p *Policy) Protegee(id int) bool {
	for _, r := range p.Regles.Protegees {
		if r.Has(id) {
			return true
		}
	}
	return false
}

func (p *Policy) TagRetirable(tag string) bool {
	if slices.Contains(p.Regles.TagsRetirables, tag) {
		return true
	}
	for _, pre := range p.Regles.PrefixesTagsRetirables {
		if strings.HasPrefix(tag, pre) && len(tag) > len(pre) && regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(tag[len(pre):]) {
			return true
		}
	}
	return false
}

func (p *Policy) OrigineAdmise(platform, upstream string) bool {
	for _, re := range p.Origines[platform] {
		if re.MatchString(upstream) {
			return true
		}
	}
	return false
}
