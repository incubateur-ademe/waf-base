package ghaudit

import (
	"path"
	"regexp"
	"strings"
)

// Emplacements lus par GitHub, dans l'ordre : le premier trouvé fait foi.
var codeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type coRule struct {
	line    int
	pattern string
	// Tous les propriétaires sont l'équipe ops : un second propriétaire
	// suffirait à approuver seul.
	lock bool
}

func parseCodeowners(b []byte, team string) []coRule {
	var rules []coRule
	for i, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		var owners []string
		for _, o := range f[1:] {
			if strings.HasPrefix(o, "#") {
				break
			}
			owners = append(owners, strings.ToLower(o))
		}
		lock := len(owners) > 0
		for _, o := range owners {
			if o != team {
				lock = false
			}
		}
		rules = append(rules, coRule{line: i + 1, pattern: f[0], lock: lock})
	}
	return rules
}

type verdict int

const (
	non verdict = iota
	oui
	incertain
)

// Sous-ensemble de la syntaxe dont le sens est sûr : GitHub ignore !, [ ] et
// l'échappement, et tout autre caractère reste douteux.
var reSimplePattern = regexp.MustCompile(`^[A-Za-z0-9._/*?-]+$`)

// match applique la syntaxe gitignore restreinte de CODEOWNERS à un chemin de
// fichier. Un motif dont le dernier segment est joker et qui ne couvre qu'un
// dossier parent est incertain : GitHub n'y étend pas docs/* aux sous-dossiers.
func match(pattern, file string) verdict {
	if !reSimplePattern.MatchString(pattern) {
		return incertain
	}
	dirOnly := strings.HasSuffix(pattern, "/")
	p := strings.TrimSuffix(pattern, "/")
	anchored := strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return incertain
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || (strings.Contains(s, "**") && s != "**") {
			return incertain
		}
	}
	if !anchored {
		segs = append([]string{"**"}, segs...)
	}
	parts := strings.Split(file, "/")
	if !dirOnly && matchSegs(segs, parts) {
		return oui
	}
	last := segs[len(segs)-1]
	for k := len(parts) - 1; k >= 1; k-- {
		if matchSegs(segs, parts[:k]) {
			if last != "**" && strings.ContainsAny(last, "*?") {
				return incertain
			}
			return oui
		}
	}
	return non
}

// matchSegs : ** final couvre au moins un segment, ** de tête ou du milieu zéro
// ou plus, comme gitignore.
func matchSegs(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		min := 0
		if len(pat) == 1 {
			min = 1
		}
		for i := min; i <= len(parts); i++ {
			if matchSegs(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	ok, err := path.Match(pat[0], parts[0])
	return err == nil && ok && matchSegs(pat[1:], parts[1:])
}

// covered dit si la dernière règle qui couvre file réserve le fichier à l'équipe
// ops. Le doute penche vers l'écart : une règle incertaine ou signalée en erreur
// par GitHub ne réserve jamais, et masque ce qui précède si elle ne réserve pas.
func covered(rules []coRule, errLines map[int]bool, file string) bool {
	for i := len(rules) - 1; i >= 0; i-- {
		r := rules[i]
		v := match(r.pattern, file)
		if v == non {
			continue
		}
		if errLines[r.line] {
			v = incertain
		}
		if v == incertain {
			if r.lock {
				continue
			}
			return false
		}
		return r.lock
	}
	return false
}
