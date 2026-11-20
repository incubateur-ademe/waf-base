package ghaudit

import (
	"context"
	"path"
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, file string
		want          verdict
	}{
		{"/waf/", "waf/Dockerfile", oui},
		{"/waf/", "waf/coraza/before.conf", oui},
		{"/waf/", "waf", non},
		{"/waf/", "src/waf/x", non},
		{"waf/", "src/waf/x", oui},
		{"/waf", "waf/coraza/before.conf", oui},
		{"waf", "a/b/waf", oui},
		{"/waf/*", "waf/Dockerfile", oui},
		{"/waf/*", "waf/coraza/before.conf", incertain},
		{"/waf/**", "waf/coraza/before.conf", oui},
		{"/waf/**", "waf", non},
		{"/.gitmodules/**", ".gitmodules", non},
		{"/waf/**/", "waf/Dockerfile", non},
		{"/waf/**/", "waf/coraza/before.conf", oui},
		{"**/before.conf", "waf/coraza/before.conf", oui},
		{"/waf/**/before.conf", "waf/before.conf", oui},
		{"*", "waf/Dockerfile", oui},
		{"*.conf", "waf/coraza/before.conf", oui},
		{"*.conf", "waf/Dockerfile", non},
		{"/w?f/", "waf/Dockerfile", incertain},
		{"/w?f/Dockerfile", "waf/Dockerfile", oui},
		{"/Waf/", "waf/Dockerfile", non},
		{"/.github/CODEOWNERS", ".github/CODEOWNERS", oui},
		{"CODEOWNERS", "docs/CODEOWNERS", oui},
		{"/CODEOWNERS", "docs/CODEOWNERS", non},
		{"!/waf/", "waf/Dockerfile", incertain},
		{"/waf/[ab]", "waf/a", incertain},
		{`\#waf`, "#waf", incertain},
		{"/", "waf/Dockerfile", incertain},
		{"/waf//x", "waf/x", incertain},
		{"/waf/a**", "waf/ab", incertain},
		{"/wàf/", "wàf/Dockerfile", incertain},
	}
	for _, c := range cases {
		if got := match(c.pattern, c.file); got != c.want {
			t.Errorf("match(%q, %q) = %d, attendu %d", c.pattern, c.file, got, c.want)
		}
	}
}

func TestCovered(t *testing.T) {
	const team = "@incubateur-ademe/secops"
	cases := []struct {
		name     string
		co       string
		errLines map[int]bool
		file     string
		want     bool
	}{
		{"réservé", "/waf/ @incubateur-ademe/secops\n", nil, "waf/Dockerfile", true},
		{"casse des propriétaires", "/waf/ @Incubateur-ADEME/SecOps\n", nil, "waf/Dockerfile", true},
		{"aucune règle", "/src/ @x\n", nil, "waf/Dockerfile", false},
		{"sans propriétaire", "/waf/ @incubateur-ademe/secops\n/waf/Dockerfile\n", nil, "waf/Dockerfile", false},
		{"second propriétaire", "/waf/ @incubateur-ademe/secops @dev\n", nil, "waf/Dockerfile", false},
		{"dernière règle gagne", "/waf/ @incubateur-ademe/secops\n*.conf @dev\n", nil, "waf/coraza/before.conf", false},
		{"règle antérieure écrasée", "* @dev\n/waf/ @incubateur-ademe/secops\n", nil, "waf/Dockerfile", true},
		{"commentaire en ligne", "/waf/ @incubateur-ademe/secops # ops\n", nil, "waf/Dockerfile", true},
		{"propriétaire après un commentaire ignoré", "/waf/ @incubateur-ademe/secops #@dev\n", nil, "waf/Dockerfile", true},
		{"incertaine non réservée masque", "/waf/ @incubateur-ademe/secops\n/w[a]f/ @dev\n", nil, "waf/Dockerfile", false},
		{"incertaine réservée ne couvre pas", "/w[a]f/ @incubateur-ademe/secops\n", nil, "waf/Dockerfile", false},
		{"incertaine réservée laisse la précédente", "/waf/ @incubateur-ademe/secops\n/w[a]f/ @incubateur-ademe/secops\n", nil, "waf/Dockerfile", true},
		{"ligne réservée en erreur", "/waf/ @incubateur-ademe/secops\n", map[int]bool{1: true}, "waf/Dockerfile", false},
		{"ligne non réservée en erreur masque", "/waf/ @incubateur-ademe/secops\n/waf/x @dev\n", map[int]bool{2: true}, "waf/x", false},
		{"ligne en erreur sans rapport", "/waf/ @incubateur-ademe/secops\n/src/ @dev\n", map[int]bool{2: true}, "waf/Dockerfile", true},
		{"CRLF", "/waf/ @incubateur-ademe/secops\r\n", nil, "waf/Dockerfile", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := covered(parseCodeowners([]byte(c.co), team), c.errLines, c.file); got != c.want {
				t.Fatalf("covered = %v, attendu %v", got, c.want)
			}
		})
	}
}

// Un motif écrit par la startup ne doit pas rendre le calcul exponentiel.
func TestMatchBorne(t *testing.T) {
	deep := strings.Repeat("d/", 30) + "f"
	start := time.Now()
	for _, k := range []int{30, 1000} {
		p := "/" + strings.Repeat("**/", k) + "zzz"
		for _, f := range []string{"waf/coraza/config.conf", deep} {
			match(p, f)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("match en %s", d)
	}
	if got := match("/"+strings.Repeat("**/", 40)+"x", "x"); got != incertain {
		t.Fatalf("motif de plus de %d segments : %d", maxSegs, got)
	}
	if got := match("/**/**/**/x", "a/b/c/x"); got != oui {
		t.Fatalf("** consécutifs : %d", got)
	}
	if got := match("/a/**", strings.Repeat("a/", 40)+"x"); got != incertain {
		t.Fatalf("chemin de plus de %d segments : %d", maxSegs, got)
	}
}

func TestCouvertureInterrompue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rules := parseCodeowners([]byte("/src/ @x\n"), "@incubateur-ademe/secops")
	if l, err := uncoveredPaths(ctx, rules, nil, []string{"waf/Dockerfile"}); err != nil || len(l) != 1 {
		t.Fatalf("%q %v", l, err)
	}
	cancel()
	if _, err := uncoveredPaths(ctx, rules, nil, []string{"waf/Dockerfile"}); err == nil {
		t.Fatal("contexte annulé ignoré")
	}
}

// Ancienne récursion, exponentielle mais évidente : référence du calcul par table.
func matchSegsRef(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		min := 0
		if len(pat) == 1 {
			min = 1
		}
		for i := min; i <= len(parts); i++ {
			if matchSegsRef(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	ok, err := path.Match(pat[0], parts[0])
	return err == nil && ok && matchSegsRef(pat[1:], parts[1:])
}

func TestMatchSegsCommeReference(t *testing.T) {
	atoms := []string{"**", "*", "a", "b", "a*", "?", "*.c"}
	names := []string{"a", "b", "ab", "x.c", "c"}
	var pats, files [][]string
	var gen func(cur []string, src []string, max int, out *[][]string)
	gen = func(cur []string, src []string, max int, out *[][]string) {
		*out = append(*out, append([]string(nil), cur...))
		if len(cur) == max {
			return
		}
		for _, s := range src {
			gen(append(cur, s), src, max, out)
		}
	}
	gen(nil, atoms, 4, &pats)
	gen(nil, names, 4, &files)
	n := 0
	for _, p := range pats {
		for _, f := range files {
			if got, want := matchSegs(p, f), matchSegsRef(p, f); got != want {
				t.Fatalf("matchSegs(%q, %q) = %v, référence %v", p, f, got, want)
			}
			n++
		}
	}
	if n < 1_000_000 {
		t.Fatalf("%d cas seulement", n)
	}
}
