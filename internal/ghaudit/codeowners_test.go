package ghaudit

import "testing"

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
