// Package seclang découpe un sous-ensemble strict de SecLang.
//
// Le découpage reproduit celui de Coraza v3.8.1 (internal/seclang/parser.go,
// rule_parser.go) et refuse toute construction où les deux pourraient diverger :
// tabulation, backtick, guillemet échappé, commentaire ou ligne vide au milieu
// d'une continuation, continuation laissée ouverte en fin de fichier.
package seclang

import (
	"bufio"
	"fmt"
	"strings"
	"unicode/utf8"
)

const MaxLine = 60000

type Instr struct {
	File      string
	Line      int
	Reason    string
	Directive string
	Opts      string
}

type Error struct {
	File string
	Line int
	Msg  string
}

func (e Error) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

func Split(file string, data []byte) ([]Instr, []Error) {
	var out []Instr
	var errs []Error
	fail := func(line int, format string, a ...any) {
		errs = append(errs, Error{file, line, fmt.Sprintf(format, a...)})
	}
	if !utf8.Valid(data) {
		fail(0, "fichier non UTF-8")
		return nil, errs
	}
	for _, r := range []struct {
		c   string
		why string
	}{{"\t", "tabulation"}, {"`", "backtick"}, {"\r", "retour chariot"}, {"\x00", "octet nul"}} {
		if i := strings.Index(string(data), r.c); i >= 0 {
			fail(1+strings.Count(string(data[:i]), "\n"), "%s interdite", r.why)
		}
	}
	// Coraza lit avec un bufio.Scanner de 64 Kio sans tester son erreur : au-delà,
	// la fin du fichier est ignorée en silence.
	for i, l := range strings.Split(string(data), "\n") {
		if len(l) > MaxLine {
			fail(i+1, "ligne de plus de %d octets", MaxLine)
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var buf strings.Builder
	var reason []string
	start, n := 0, 0
	inCont := false
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if inCont {
				fail(n, "ligne vide au milieu d'une continuation")
			}
			reason = nil
			continue
		}
		if line[0] == '#' {
			if inCont {
				fail(n, "commentaire au milieu d'une continuation")
				continue
			}
			reason = append(reason, strings.TrimSpace(strings.TrimLeft(line, "#")))
			continue
		}
		if !inCont {
			start = n
		}
		if strings.HasSuffix(line, `\`) {
			buf.WriteString(strings.TrimSuffix(line, `\`))
			inCont = true
			continue
		}
		buf.WriteString(line)
		inCont = false
		logical := buf.String()
		buf.Reset()
		dir, opts, _ := strings.Cut(logical, " ")
		out = append(out, Instr{
			File:      file,
			Line:      start,
			Reason:    strings.TrimSpace(strings.Join(reason, " ")),
			Directive: dir,
			Opts:      opts,
		})
		reason = nil
	}
	if err := sc.Err(); err != nil {
		fail(n, "lecture : %v", err)
	}
	if inCont {
		fail(start, "continuation ouverte en fin de fichier")
	}
	return out, errs
}

// CutQuoted reproduit cutQuotedString de Coraza : la chaîne se termine au premier
// guillemet précédé d'un nombre pair de barres obliques inverses.
func CutQuoted(s string) (inner, rest string, err error) {
	if len(s) == 0 || s[0] != '"' {
		return "", "", fmt.Errorf("chaîne entre guillemets attendue")
	}
	bs := 0
	for i := 1; i < len(s); i++ {
		if s[i] != '"' {
			if s[i] == '\\' {
				bs++
			} else {
				bs = 0
			}
			continue
		}
		if bs%2 == 1 {
			bs = 0
			continue
		}
		inner = s[1:i]
		if strings.Contains(inner, `"`) {
			return "", "", fmt.Errorf("guillemet échappé interdit")
		}
		return inner, s[i+1:], nil
	}
	return "", "", fmt.Errorf("guillemet fermant manquant")
}

// Rule découpe les options d'un SecRule en variables, opérateur et actions,
// comme parseActionOperator de Coraza.
type Rule struct {
	Vars    string
	Op      string
	Actions string
}

func ParseRule(opts string) (Rule, error) {
	data := strings.Trim(opts, " ")
	vars, rest, ok := strings.Cut(data, " ")
	if !ok {
		return Rule{}, fmt.Errorf("SecRule sans opérateur")
	}
	if strings.ContainsAny(vars, `"'`) {
		return Rule{}, fmt.Errorf("guillemet interdit dans les variables")
	}
	rest = strings.TrimLeft(rest, " ")
	op, rest, err := CutQuoted(rest)
	if err != nil {
		return Rule{}, fmt.Errorf("opérateur : %v", err)
	}
	rest = strings.TrimLeft(rest, " ")
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return Rule{}, fmt.Errorf("actions entre guillemets attendues")
	}
	acts := rest[1 : len(rest)-1]
	if strings.Contains(acts, `"`) {
		return Rule{}, fmt.Errorf("guillemet interdit dans les actions")
	}
	return Rule{Vars: vars, Op: op, Actions: acts}, nil
}

// QuotedActions lit les options d'un SecAction : une seule chaîne entre guillemets.
func QuotedActions(opts string) (string, error) {
	if len(opts) < 3 || opts[0] != '"' || opts[len(opts)-1] != '"' {
		return "", fmt.Errorf("actions entre guillemets attendues")
	}
	inner := opts[1 : len(opts)-1]
	if strings.Contains(inner, `"`) {
		return "", fmt.Errorf("guillemet interdit dans les actions")
	}
	return inner, nil
}

type Action struct {
	Key   string
	Value string
}

// ParseActions reproduit parseActions de Coraza sur un sous-ensemble sans barre
// oblique inverse, où l'apostrophe n'entoure qu'une valeur entière.
func ParseActions(s string) ([]Action, error) {
	if strings.Contains(s, `\`) {
		return nil, fmt.Errorf("barre oblique inverse interdite dans les actions")
	}
	var out []Action
	var parts []string
	inQ := false
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQ = !inQ
		case ',':
			if !inQ {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	if inQ {
		return nil, fmt.Errorf("apostrophe non fermée")
	}
	parts = append(parts, s[last:])
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("action vide")
		}
		if p != strings.TrimSpace(p) {
			return nil, fmt.Errorf("espace autour de l'action %q", p)
		}
		k, v, hasV := strings.Cut(p, ":")
		if strings.ContainsAny(k, "' ") || k == "" {
			return nil, fmt.Errorf("nom d'action invalide %q", k)
		}
		if k != strings.ToLower(k) {
			return nil, fmt.Errorf("nom d'action en minuscules attendu : %q", k)
		}
		if hasV {
			if strings.Contains(v, "'") {
				if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' || strings.Count(v, "'") != 2 {
					return nil, fmt.Errorf("apostrophes : seulement autour de la valeur entière (%s)", k)
				}
				v = v[1 : len(v)-1]
			}
			if v != strings.TrimSpace(v) || v == "" {
				return nil, fmt.Errorf("valeur vide ou entourée d'espaces (%s)", k)
			}
		}
		out = append(out, Action{Key: k, Value: v})
	}
	return out, nil
}
