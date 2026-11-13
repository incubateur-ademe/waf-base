// Package lint vérifie que les fichiers Coraza d'un tenant n'emploient que les
// formes en liste blanche de la section 6 du design. Toute autre instruction est
// refusée ; le linter ne délègue jamais le parsing à Coraza.
package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/policy"
	"github.com/incubateur-ademe/waf-base/internal/seclang"
)

type Finding struct {
	File string
	Line int
	Warn bool
	Msg  string
}

func (f Finding) String() string {
	lvl := "erreur"
	if f.Warn {
		lvl = "avertissement"
	}
	return fmt.Sprintf("%s:%d: %s : %s", f.File, f.Line, lvl, f.Msg)
}

type Prefix struct {
	Path    string
	Exact   bool
	Methods []string
}

// covers dit si la condition c s'applique à toute requête que la condition p admet.
func (c Prefix) covers(p Prefix) bool {
	if c.Exact {
		return p.Exact && p.Path == c.Path
	}
	return strings.HasPrefix(p.Path, c.Path)
}

type Result struct {
	Findings    []Finding
	Prefixes    []Prefix
	BlockingPL  int
	DetectionPL int
	Threshold   int
	Present     map[string]bool
}

func (r *Result) Errors() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if !f.Warn {
			out = append(out, f)
		}
	}
	return out
}

var (
	reDigits     = regexp.MustCompile(`^[0-9]{1,7}$`)
	reRange      = regexp.MustCompile(`^([0-9]{1,7})-([0-9]{1,7})$`)
	rePath       = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)
	reHeaderName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	reLitKey     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reTag        = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,64}$`)
	reTrans      = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
)

var allowedFiles = map[string]bool{
	"Dockerfile":         true,
	"waf.yaml":           true,
	"README.md":          true,
	"coraza/config.conf": true,
	"coraza/before.conf": true,
	"coraza/after.conf":  true,
}

type linter struct {
	pol      *policy.Policy
	pl       map[int]int
	res      *Result
	ids      map[int]string
	families map[string]map[string]bool
	// retraits complets (ruleRemoveById) par condition de chemin
	removed []removal
}

type removal struct {
	cond     Prefix
	families map[string]bool
	where    seclang.Instr
}

const (
	maxFileSize  = 256 << 10
	maxTotalSize = 2 << 20
)

func (l *linter) err(file string, line int, format string, a ...any) {
	l.res.Findings = append(l.res.Findings, Finding{file, line, false, fmt.Sprintf(format, a...)})
}

func (l *linter) warn(file string, line int, format string, a ...any) {
	l.res.Findings = append(l.res.Findings, Finding{file, line, true, fmt.Sprintf(format, a...)})
}

// Tenant lint le dossier waf/ d'une app. pl associe un ID de règle CRS à son
// niveau de paranoïa ; nil désactive l'avertissement sur les règles inertes.
func Tenant(dir string, pol *policy.Policy, pl map[int]int) *Result {
	l := &linter{
		pol:      pol,
		pl:       pl,
		res:      &Result{BlockingPL: 1, Threshold: 5, Present: map[string]bool{}},
		ids:      map[int]string{},
		families: map[string]map[string]bool{},
	}
	l.walk(dir)
	for _, name := range []string{"config.conf", "before.conf", "after.conf"} {
		p := filepath.Join(dir, "coraza", name)
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		rel := "coraza/" + name
		if err != nil {
			l.err(rel, 0, "lecture : %v", err)
			continue
		}
		l.res.Present[name] = true
		instrs, errs := seclang.Split(rel, b)
		for _, e := range errs {
			l.err(e.File, e.Line, "%s", e.Msg)
		}
		if len(errs) > 0 {
			continue
		}
		switch name {
		case "config.conf":
			l.config(instrs)
		case "before.conf":
			l.before(instrs)
		case "after.conf":
			l.after(instrs)
		}
	}
	if l.res.DetectionPL == 0 {
		l.res.DetectionPL = l.res.BlockingPL
	}
	for fam, paths := range l.families {
		if len(paths) > pol.Formes.Exclusions.CheminsMaxParFamille {
			l.err("coraza/before.conf", 0, "famille %s retirée sous %d conditions de chemin (%d au plus)", fam, len(paths), pol.Formes.Exclusions.CheminsMaxParFamille)
		}
	}
	// Une requête cumule les retraits de toutes les conditions qui la couvrent.
	max := pol.Formes.Exclusions.FamillesMaxParChemin
	for _, r := range l.removed {
		union := map[string]bool{}
		for _, o := range l.removed {
			if o.cond.covers(r.cond) {
				for f := range o.families {
					union[f] = true
				}
			}
		}
		if len(union) > max {
			fams := make([]string, 0, len(union))
			for f := range union {
				fams = append(fams, f)
			}
			sort.Strings(fams)
			l.err(r.where.File, r.where.Line, "sous %s, %d familles de règles retirées en entier (%s), %d au plus", r.cond.Path, len(union), strings.Join(fams, ", "), max)
		}
	}
	sort.Slice(l.res.Prefixes, func(i, j int) bool {
		a, b := l.res.Prefixes[i], l.res.Prefixes[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return strings.Join(a.Methods, " ") < strings.Join(b.Methods, " ")
	})
	l.res.Prefixes = slices.CompactFunc(l.res.Prefixes, func(a, b Prefix) bool {
		return a.Path == b.Path && a.Exact == b.Exact && slices.Equal(a.Methods, b.Methods)
	})
	return l.res
}

func (l *linter) walk(dir string) {
	total := int64(0)
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			l.err(p, 0, "%v", err)
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			l.err(rel, 0, "lien symbolique interdit")
			return nil
		}
		if d.IsDir() {
			if rel != "coraza" && rel != "tests" {
				l.err(rel, 0, "dossier inattendu dans waf/")
				return filepath.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
			if info.Size() > maxFileSize {
				l.err(rel, 0, "fichier de plus de %d Kio", maxFileSize>>10)
			}
			if total > maxTotalSize {
				l.err(rel, 0, "waf/ dépasse %d Mio", maxTotalSize>>20)
				return filepath.SkipAll
			}
		}
		if allowedFiles[rel] {
			return nil
		}
		if m, _ := regexp.MatchString(`^tests/[a-z0-9_-]{1,64}\.yaml$`, rel); m {
			return nil
		}
		l.err(rel, 0, "fichier inattendu dans waf/ ; admis : Dockerfile, waf.yaml, README.md, coraza/{config,before,after}.conf, tests/*.yaml")
		return nil
	})
}

func (l *linter) reason(in seclang.Instr) {
	if len(in.Reason) < 8 {
		l.err(in.File, in.Line, "chaque instruction doit être précédée d'un commentaire qui en donne la raison")
	}
}

func (l *linter) id(in seclang.Instr, v string) int {
	if !reDigits.MatchString(v) {
		l.err(in.File, in.Line, "id invalide %q", v)
		return 0
	}
	n, _ := strconv.Atoi(v)
	r := l.pol.Regles.IDsTenant
	if n < r[0] || n > r[1] {
		l.err(in.File, in.Line, "id %d hors de la plage du tenant %d à %d", n, r[0], r[1])
	}
	if prev, ok := l.ids[n]; ok {
		l.err(in.File, in.Line, "id %d déjà utilisé (%s)", n, prev)
	}
	l.ids[n] = fmt.Sprintf("%s:%d", in.File, in.Line)
	return n
}

func (l *linter) actions(in seclang.Instr, s string) []seclang.Action {
	if strings.Contains(s, "%{") {
		l.err(in.File, in.Line, "macro %%{...} interdite")
		return nil
	}
	acts, err := seclang.ParseActions(s)
	if err != nil {
		l.err(in.File, in.Line, "actions : %v", err)
		return nil
	}
	return acts
}

func count(acts []seclang.Action, key string) int {
	n := 0
	for _, a := range acts {
		if a.Key == key {
			n++
		}
	}
	return n
}

// ---------- config.conf

var configVars = map[string]bool{
	"tx.blocking_paranoia_level":         true,
	"tx.detection_paranoia_level":        true,
	"tx.inbound_anomaly_score_threshold": true,
	"tx.allowed_methods":                 true,
}

func (l *linter) config(instrs []seclang.Instr) {
	seen := map[string]bool{}
	detection := 0
	for _, in := range instrs {
		l.reason(in)
		if in.Directive != "SecAction" {
			l.err(in.File, in.Line, "seul SecAction est admis dans config.conf, pas %q", in.Directive)
			continue
		}
		inner, err := seclang.QuotedActions(in.Opts)
		if err != nil {
			l.err(in.File, in.Line, "%v", err)
			continue
		}
		acts := l.actions(in, inner)
		if acts == nil {
			continue
		}
		var hasID, hasPhase, hasPass, hasNolog, hasSetvar bool
		for _, a := range acts {
			switch a.Key {
			case "id":
				if hasID {
					l.err(in.File, in.Line, "id en double")
				}
				hasID = true
				l.id(in, a.Value)
			case "phase":
				hasPhase = a.Value == "1"
				if !hasPhase {
					l.err(in.File, in.Line, "config.conf : phase:1 seulement")
				}
			case "pass":
				hasPass = a.Value == ""
			case "nolog":
				hasNolog = a.Value == ""
			case "t":
				if a.Value != "none" {
					l.err(in.File, in.Line, "config.conf : t:none seulement")
				}
			case "setvar":
				hasSetvar = true
				k, v, ok := strings.Cut(a.Value, "=")
				if !ok || !configVars[k] {
					l.err(in.File, in.Line, "setvar admis sur tx.blocking_paranoia_level, tx.detection_paranoia_level, tx.inbound_anomaly_score_threshold et tx.allowed_methods seulement, avec « = »")
					continue
				}
				if seen[k] {
					l.err(in.File, in.Line, "%s posé deux fois", k)
				}
				seen[k] = true
				l.configValue(in, k, v, &detection)
			default:
				l.err(in.File, in.Line, "action %q interdite dans config.conf", a.Key)
			}
		}
		if !hasID || !hasPhase || !hasPass || !hasNolog || !hasSetvar {
			l.err(in.File, in.Line, "forme attendue : SecAction \"id:3xxxx,phase:1,pass,nolog,t:none,setvar:...\"")
		}
	}
	if detection != 0 {
		if detection < l.res.BlockingPL {
			l.err("coraza/config.conf", 0, "detection_paranoia_level %d inférieur au niveau bloquant %d", detection, l.res.BlockingPL)
		}
		l.res.DetectionPL = detection
	}
}

func (l *linter) configValue(in seclang.Instr, k, v string, detection *int) {
	f := l.pol.Formes.Config
	if k == "tx.allowed_methods" {
		ms := strings.Split(v, " ")
		got := map[string]bool{}
		for _, m := range ms {
			if !slices.Contains(f.AllowedMethods, m) || got[m] {
				l.err(in.File, in.Line, "allowed_methods : %q refusé (admis : %s, sans doublon)", m, strings.Join(f.AllowedMethods, " "))
			}
			got[m] = true
		}
		return
	}
	if !reDigits.MatchString(v) {
		l.err(in.File, in.Line, "%s : entier attendu", k)
		return
	}
	n, _ := strconv.Atoi(v)
	switch k {
	case "tx.blocking_paranoia_level":
		if n < f.BlockingPL[0] || n > f.BlockingPL[1] {
			l.err(in.File, in.Line, "blocking_paranoia_level %d hors de %d à %d", n, f.BlockingPL[0], f.BlockingPL[1])
		}
		l.res.BlockingPL = n
	case "tx.detection_paranoia_level":
		if n > f.DetectionPLMax || n < 1 {
			l.err(in.File, in.Line, "detection_paranoia_level %d hors de 1 à %d", n, f.DetectionPLMax)
		}
		*detection = n
	case "tx.inbound_anomaly_score_threshold":
		if n < f.Threshold[0] || n > f.Threshold[1] {
			l.err(in.File, in.Line, "inbound_anomaly_score_threshold %d hors de %d à %d", n, f.Threshold[0], f.Threshold[1])
		}
		l.res.Threshold = n
	}
}

// ---------- before.conf

type cond struct {
	kind   string // path, header
	path   string
	exact  bool
	header string
}

func (l *linter) before(instrs []seclang.Instr) {
	for i := 0; i < len(instrs); i++ {
		in := instrs[i]
		l.reason(in)
		if in.Directive != "SecRule" {
			l.err(in.File, in.Line, "seul SecRule est admis dans before.conf, pas %q", in.Directive)
			continue
		}
		r, err := seclang.ParseRule(in.Opts)
		if err != nil {
			l.err(in.File, in.Line, "%v", err)
			continue
		}
		acts := l.actions(in, r.Actions)
		if acts == nil {
			continue
		}
		if count(acts, "deny") > 0 || count(acts, "block") > 0 {
			l.hardening(in, r, acts)
			continue
		}
		var link *seclang.Rule
		var linkActs []seclang.Action
		if count(acts, "chain") > 0 {
			if i+1 >= len(instrs) {
				l.err(in.File, in.Line, "chain sans règle suivante")
				continue
			}
			i++
			next := instrs[i]
			if next.Directive != "SecRule" {
				l.err(next.File, next.Line, "maillon de chain : SecRule attendu")
				continue
			}
			nr, err := seclang.ParseRule(next.Opts)
			if err != nil {
				l.err(next.File, next.Line, "%v", err)
				continue
			}
			link = &nr
			linkActs = l.actions(next, nr.Actions)
			if linkActs == nil {
				continue
			}
		}
		l.exclusion(in, r, acts, link, linkActs)
	}
}

func (l *linter) condition(in seclang.Instr, r seclang.Rule) *cond {
	switch {
	case r.Vars == "REQUEST_FILENAME":
		op, arg, _ := strings.Cut(r.Op, " ")
		if op != "@beginsWith" && op != "@streq" {
			l.err(in.File, in.Line, "condition de chemin : @beginsWith ou @streq seulement")
			return nil
		}
		if !rePath.MatchString(arg) || arg == "/" || strings.Contains(arg, "//") {
			l.err(in.File, in.Line, "chemin %q refusé : ^/[A-Za-z0-9._~/-]{0,200}$, différent de /", arg)
			return nil
		}
		if op == "@beginsWith" && !strings.HasSuffix(arg, "/") {
			l.err(in.File, in.Line, "préfixe %q : un @beginsWith doit couvrir des segments entiers et finir par /", arg)
			return nil
		}
		return &cond{kind: "path", path: arg, exact: op == "@streq"}
	case strings.HasPrefix(r.Vars, "&REQUEST_HEADERS:"):
		name := strings.TrimPrefix(r.Vars, "&REQUEST_HEADERS:")
		if !reHeaderName.MatchString(name) {
			l.err(in.File, in.Line, "nom d'en-tête invalide %q", name)
			return nil
		}
		if r.Op != "@gt 0" {
			l.err(in.File, in.Line, "condition d'en-tête : \"@gt 0\" seulement")
			return nil
		}
		return &cond{kind: "header", header: name}
	}
	l.err(in.File, in.Line, "exclusion : condition sur REQUEST_FILENAME ou &REQUEST_HEADERS:<nom> seulement, pas %q", r.Vars)
	return nil
}

// exclusion vérifie une règle pass. Avec un maillon de chain, Coraza exécute les
// ctl et setvar de la tête même quand le maillon échoue : les effets ne sont
// admis que sur le maillon REQUEST_METHOD.
func (l *linter) exclusion(in seclang.Instr, r seclang.Rule, acts []seclang.Action, link *seclang.Rule, linkActs []seclang.Action) {
	c := l.condition(in, r)
	if c == nil {
		return
	}
	var hasID, hasPhase, hasPass, hasNolog, hasEffect bool
	full := map[string]bool{}
	var families []string
	effect := func(where seclang.Instr, a seclang.Action) {
		switch a.Key {
		case "ctl":
			hasEffect = true
			fam, isFull := l.ctl(where, a.Value, c)
			if fam != "" {
				families = append(families, fam)
				if isFull {
					full[fam] = true
				}
			}
		case "setvar":
			hasEffect = true
			l.contentType(where, a.Value)
		}
	}
	for _, a := range acts {
		switch a.Key {
		case "id":
			hasID = true
			l.id(in, a.Value)
		case "phase":
			hasPhase = a.Value == "1"
			if !hasPhase {
				l.err(in.File, in.Line, "exclusion : phase:1 seulement")
			}
		case "pass":
			hasPass = a.Value == ""
		case "nolog":
			hasNolog = a.Value == ""
		case "chain":
			if a.Value != "" {
				l.err(in.File, in.Line, "chain sans valeur")
			}
		case "t":
			if a.Value != "none" {
				l.err(in.File, in.Line, "exclusion : t:none seulement")
			}
		case "ctl", "setvar":
			if link != nil {
				l.err(in.File, in.Line, "%s sur la tête d'une chain : Coraza l'applique même si le maillon échoue ; le placer sur le maillon REQUEST_METHOD", a.Key)
				continue
			}
			effect(in, a)
		default:
			l.err(in.File, in.Line, "action %q interdite dans une exclusion", a.Key)
		}
	}
	var methods []string
	if link != nil {
		op, arg, _ := strings.Cut(link.Op, " ")
		if link.Vars != "REQUEST_METHOD" || op != "@streq" || strings.Contains(arg, " ") {
			l.err(in.File, in.Line, "maillon de chain : SecRule REQUEST_METHOD \"@streq <méthode>\" seulement, une méthode par maillon")
		} else if !slices.Contains(l.pol.Formes.Exclusions.MethodesChain, arg) {
			l.err(in.File, in.Line, "méthode %q refusée dans le maillon de chain", arg)
		} else {
			methods = []string{arg}
		}
		for _, a := range linkActs {
			switch a.Key {
			case "t":
				if a.Value != "none" {
					l.err(in.File, in.Line, "maillon de chain : t:none seulement")
				}
			case "ctl", "setvar":
				effect(in, a)
			default:
				l.err(in.File, in.Line, "maillon de chain : %s interdit", a.Key)
			}
		}
	}
	if !hasID || !hasPhase || !hasPass || !hasNolog || !hasEffect {
		l.err(in.File, in.Line, "forme attendue : SecRule <condition> \"<op>\" \"id:3xxxx,phase:1,pass,nolog,t:none,ctl:...\"")
	}
	if len(families) == 0 {
		return
	}
	if c.kind != "path" {
		l.err(in.File, in.Line, "un retrait de règle ou de cible exige une condition de chemin")
		return
	}
	key := c.path
	if !c.exact {
		key += "*"
	}
	for _, fam := range families {
		if l.families[fam] == nil {
			l.families[fam] = map[string]bool{}
		}
		l.families[fam][key] = true
	}
	p := Prefix{Path: c.path, Exact: c.exact, Methods: methods}
	l.res.Prefixes = append(l.res.Prefixes, p)
	if len(full) > 0 {
		l.removed = append(l.removed, removal{cond: Prefix{Path: c.path, Exact: c.exact}, families: full, where: in})
	}
}

// ctl renvoie la famille touchée (« 941 » ou « tag:attack-xss ») et dit si la
// règle est retirée en entier ; famille vide si le ctl ne retire rien.
func (l *linter) ctl(in seclang.Instr, v string, c *cond) (string, bool) {
	name, val, ok := strings.Cut(v, "=")
	if !ok {
		l.err(in.File, in.Line, "ctl sans « = »")
		return "", false
	}
	switch name {
	case "requestBodyProcessor":
		if val != "JSON" {
			l.err(in.File, in.Line, "ctl:requestBodyProcessor=JSON seulement")
		}
		return "", false
	case "ruleRemoveById":
		if c.kind != "path" {
			l.err(in.File, in.Line, "ruleRemoveById exige une condition de chemin")
		}
		return l.idOrRange(in, val), true
	case "ruleRemoveTargetById":
		ids, target, ok := strings.Cut(val, ";")
		if !ok {
			l.err(in.File, in.Line, "ruleRemoveTargetById=<id>;<COLLECTION>:<clé> attendu")
			return "", false
		}
		l.target(in, target, false)
		return l.idOrRange(in, ids), false
	case "ruleRemoveTargetByTag":
		tag, target, ok := strings.Cut(val, ";")
		if !ok {
			l.err(in.File, in.Line, "ruleRemoveTargetByTag=<tag>;<COLLECTION>:<clé> attendu")
			return "", false
		}
		if !l.pol.TagRetirable(tag) {
			l.err(in.File, in.Line, "tag %q non admis (OWASP_CRS ou attack-*)", tag)
		}
		l.target(in, target, false)
		return "tag:" + tag, false
	}
	l.err(in.File, in.Line, "ctl:%s interdit (admis : ruleRemoveById, ruleRemoveTargetById, ruleRemoveTargetByTag, requestBodyProcessor=JSON)", name)
	return "", false
}

func (l *linter) idOrRange(in seclang.Instr, v string) string {
	var start, end int
	if reDigits.MatchString(v) {
		start, _ = strconv.Atoi(v)
		end = start
	} else if m := reRange.FindStringSubmatch(v); m != nil {
		start, _ = strconv.Atoi(m[1])
		end, _ = strconv.Atoi(m[2])
	} else {
		l.err(in.File, in.Line, "id ou plage invalide %q", v)
		return ""
	}
	if start > end {
		l.err(in.File, in.Line, "plage inversée %q", v)
		return ""
	}
	if !l.pol.Excluable(start, end) {
		l.err(in.File, in.Line, "règles %d à %d hors de la plage excluable (920000 à 944999)", start, end)
		return ""
	}
	fm := l.pol.Regles.FamilleMax
	if start/fm != end/fm {
		l.err(in.File, in.Line, "plage %q à cheval sur deux familles de %d", v, fm)
		return ""
	}
	for id := start; id <= end && l.pl != nil; id++ {
		if pl, ok := l.pl[id]; ok && pl > l.res.DetectionPLOr() {
			if start == end {
				l.warn(in.File, in.Line, "règle %d de PL %d, au-dessus du niveau de détection %d : exclusion inerte", id, pl, l.res.DetectionPLOr())
			}
		}
	}
	return strconv.Itoa(start / fm)
}

func (r *Result) DetectionPLOr() int {
	if r.DetectionPL != 0 {
		return r.DetectionPL
	}
	return r.BlockingPL
}

func (l *linter) target(in seclang.Instr, t string, negated bool) {
	if negated {
		if !strings.HasPrefix(t, "!") {
			l.err(in.File, in.Line, "cible négative !COLLECTION:clé attendue")
			return
		}
		t = t[1:]
	}
	coll, key, ok := strings.Cut(t, ":")
	if !ok {
		l.err(in.File, in.Line, "cible %q : une clé est obligatoire, jamais une collection entière", t)
		return
	}
	if !slices.Contains(l.pol.Formes.Exclusions.Collections, coll) {
		l.err(in.File, in.Line, "collection %q refusée (admises : %s)", coll, strings.Join(l.pol.Formes.Exclusions.Collections, ", "))
		return
	}
	if strings.HasPrefix(key, "/") {
		if !strings.HasSuffix(key, "/") || len(key) < 3 {
			l.err(in.File, in.Line, "regex de clé mal fermée %q", key)
			return
		}
		rx := key[1 : len(key)-1]
		min := l.pol.Formes.Exclusions.RegexLitterauxMin
		re := regexp.MustCompile(fmt.Sprintf(`^\^([A-Za-z0-9_-]{%d,64})\$?$`, min))
		m := re.FindStringSubmatch(rx)
		switch {
		case m == nil:
			l.err(in.File, in.Line, "regex de clé %q : ^ suivi d'au moins %d caractères littéraux [A-Za-z0-9_-], éventuellement de $, rien d'autre", rx, min)
		case strings.HasPrefix(strings.ToLower(m[1]), "json"):
			l.err(in.File, in.Line, "regex de clé %q : Coraza préfixe toutes les clés JSON par « json. », une regex ne peut pas commencer par json", rx)
		case coll == "REQUEST_HEADERS" && m[1] != strings.ToLower(m[1]):
			l.err(in.File, in.Line, "regex de clé %q : Coraza range les en-têtes en minuscules, la regex doit l'être aussi", rx)
		}
		return
	}
	if !reLitKey.MatchString(key) {
		l.err(in.File, in.Line, "clé %q refusée : [A-Za-z0-9_.-]{1,64} ou /^regex/", key)
	}
}

func (l *linter) contentType(in seclang.Instr, v string) {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k != "tx.allowed_request_content_type" {
		l.err(in.File, in.Line, "setvar admis sur tx.allowed_request_content_type seulement, avec « = »")
		return
	}
	seen := map[string]bool{}
	for _, item := range strings.Split(val, " ") {
		if len(item) < 3 || item[0] != '|' || item[len(item)-1] != '|' {
			l.err(in.File, in.Line, "allowed_request_content_type : |type| séparés par une espace")
			return
		}
		t := item[1 : len(item)-1]
		if !slices.Contains(l.pol.Formes.Exclusions.TypesDeContenu, t) || seen[t] {
			l.err(in.File, in.Line, "type de contenu %q refusé ou en double", t)
		}
		seen[t] = true
	}
}

// ---------- durcissement

func (l *linter) hardening(in seclang.Instr, r seclang.Rule, acts []seclang.Action) {
	f := l.pol.Formes.Durcissement
	for _, v := range strings.Split(r.Vars, "|") {
		name := strings.TrimLeft(v, "!&")
		if len(v)-len(name) > 1 {
			l.err(in.File, in.Line, "variable %q : un seul préfixe ! ou &", v)
		}
		base, key, hasKey := strings.Cut(name, ":")
		if !slices.Contains(f.Variables, base) {
			l.err(in.File, in.Line, "variable %q refusée dans un durcissement", base)
		}
		if hasKey && !reLitKey.MatchString(key) {
			l.err(in.File, in.Line, "clé de variable %q : littérale [A-Za-z0-9_.-] seulement", key)
		}
	}
	op, _, _ := strings.Cut(r.Op, " ")
	op = strings.TrimPrefix(op, "!")
	if !strings.HasPrefix(op, "@") || !slices.Contains(f.Operateurs, op[1:]) {
		l.err(in.File, in.Line, "opérateur %q refusé (admis : @%s)", op, strings.Join(f.Operateurs, ", @"))
	}
	var hasID, hasPhase, hasLog, hasMsg bool
	disruptive := 0
	for _, a := range acts {
		switch a.Key {
		case "id":
			hasID = true
			l.id(in, a.Value)
		case "phase":
			hasPhase = a.Value == "1" || a.Value == "2"
			if !hasPhase {
				l.err(in.File, in.Line, "durcissement : phase:1 ou phase:2")
			}
		case "deny", "block":
			disruptive++
			if a.Value != "" {
				l.err(in.File, in.Line, "%s sans valeur", a.Key)
			}
			if a.Key == "block" {
				l.warn(in.File, in.Line, "block hérite de l'action par défaut de la CRS (pass en mode score) : la règle journalise sans bloquer ; utiliser deny")
			}
		case "status":
			n, err := strconv.Atoi(a.Value)
			if err != nil || !slices.Contains(f.Statuts, n) {
				l.err(in.File, in.Line, "status %q refusé", a.Value)
			}
		case "log":
			hasLog = true
		case "msg":
			hasMsg = true
			if strings.ContainsAny(a.Value, "%{}\n") || len(a.Value) > 200 {
				l.err(in.File, in.Line, "msg : 200 caractères au plus, sans macro ni accolade")
			}
		case "tag":
			if !reTag.MatchString(a.Value) || strings.HasPrefix(a.Value, "OWASP_CRS") || strings.HasPrefix(a.Value, "attack-") || strings.HasPrefix(a.Value, "paranoia-level") || strings.HasPrefix(a.Value, "ademe-") {
				l.err(in.File, in.Line, "tag %q refusé (réservés : OWASP_CRS, attack-*, paranoia-level*, ademe-*)", a.Value)
			}
		case "t":
			if !reTrans.MatchString(a.Value) {
				l.err(in.File, in.Line, "transformation %q invalide", a.Value)
			}
		case "severity":
			if !slices.Contains([]string{"CRITICAL", "ERROR", "WARNING", "NOTICE"}, a.Value) {
				l.err(in.File, in.Line, "severity %q refusée", a.Value)
			}
		default:
			l.err(in.File, in.Line, "action %q interdite dans un durcissement", a.Key)
		}
	}
	if disruptive != 1 {
		l.err(in.File, in.Line, "durcissement : exactement une action deny ou block")
	}
	if !hasID || !hasPhase || !hasLog || !hasMsg {
		l.err(in.File, in.Line, "durcissement : id, phase, log et msg obligatoires")
	}
}

// ---------- after.conf

func (l *linter) after(instrs []seclang.Instr) {
	for _, in := range instrs {
		l.reason(in)
		if in.Directive != "SecRuleUpdateTargetById" && in.Directive != "SecRuleUpdateTargetByTag" {
			l.err(in.File, in.Line, "seuls SecRuleUpdateTargetById et SecRuleUpdateTargetByTag sont admis dans after.conf, pas %q", in.Directive)
			continue
		}
		fields := strings.Split(in.Opts, " ")
		if len(fields) != 2 {
			l.err(in.File, in.Line, "forme attendue : %s <id|plage|tag> \"!COLLECTION:clé\"", in.Directive)
			continue
		}
		t := fields[1]
		if len(t) < 3 || t[0] != '"' || t[len(t)-1] != '"' || strings.Count(t, `"`) != 2 {
			l.err(in.File, in.Line, "cible entre guillemets attendue")
			continue
		}
		t = t[1 : len(t)-1]
		switch in.Directive {
		case "SecRuleUpdateTargetById":
			l.idOrRange(in, fields[0])
		case "SecRuleUpdateTargetByTag":
			if !l.pol.TagRetirable(fields[0]) {
				l.err(in.File, in.Line, "tag %q non admis (OWASP_CRS ou attack-*)", fields[0])
			}
		}
		l.target(in, t, true)
	}
}

// ---------- niveaux de paranoïa de la CRS

var (
	reRuleID = regexp.MustCompile(`id:([0-9]+)`)
	rePL     = regexp.MustCompile(`tag:'paranoia-level/([1-4])'`)
)

// CRSParanoia lit les fichiers de règles de la CRS et associe chaque ID à son
// tag paranoia-level, quand il en a un.
func CRSParanoia(rulesDir string) (map[int]int, error) {
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
	if err != nil {
		return nil, err
	}
	out := map[int]int{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, block := range strings.Split(string(b), "\nSecRule ") {
			ids := reRuleID.FindStringSubmatch(block)
			pl := rePL.FindStringSubmatch(block)
			if ids != nil && pl != nil {
				id, _ := strconv.Atoi(ids[1])
				n, _ := strconv.Atoi(pl[1])
				out[id] = n
			}
		}
	}
	return out, nil
}
