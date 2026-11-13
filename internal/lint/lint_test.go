package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/incubateur-ademe/waf-base/internal/policy"
)

func pol(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Load("../../policy")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tenantDir(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for name, content := range files {
		p := filepath.Join(d, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestExempleTACCT(t *testing.T) {
	r := Tenant("../../tests/exemple-tacct", pol(t), map[int]int{942440: 2})
	if errs := r.Errors(); len(errs) > 0 {
		t.Fatalf("exemple refusé : %v", errs)
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Msg, "942440") {
		t.Fatalf("avertissement attendu sur 942440 inerte au PL 1, obtenu %v", r.Findings)
	}
	want := []Prefix{{"/api/admin/articles/", false, nil}, {"/api/auth/callback", true, nil}}
	if len(r.Prefixes) != 2 || r.Prefixes[0].Path != want[0].Path || r.Prefixes[0].Exact != want[0].Exact || r.Prefixes[1].Path != want[1].Path || r.Prefixes[1].Exact != want[1].Exact {
		t.Fatalf("préfixes %v, attendu %v", r.Prefixes, want)
	}
}

const why = "# Raison suffisamment longue pour le linter\n"

func TestRefus(t *testing.T) {
	cases := []struct {
		name, file, body, want string
	}{
		// Formes relevées par la revue sécurité du 2026-11-11.
		{"cible collection entière", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS_POST"`, "une clé est obligatoire"},
		{"SecArgumentsLimit", "after.conf", why + `SecArgumentsLimit 1`, "seuls SecRuleUpdateTargetById"},
		{"SecRemoteRules", "before.conf", why + `SecRemoteRules key https://x`, "seul SecRule"},
		{"SecUploadDir", "config.conf", why + `SecUploadDir /tmp`, "seul SecAction"},
		{"SecRuleEngine", "config.conf", why + `SecRuleEngine DetectionOnly`, "seul SecAction"},
		{"ctl ruleEngine", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleEngine=Off"`, "ctl:ruleEngine interdit"},
		{"ctl requestBodyAccess", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:requestBodyAccess=Off"`, "interdit"},
		{"ctl ruleRemoveByTag", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"`, "interdit"},
		{"ctl auditEngine", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:auditEngine=Off"`, "interdit"},
		{"allow", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,allow"`, "allow"},
		{"skipAfter", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,skipAfter:END"`, "skipafter"},
		{"setvar seuil dans before", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=100"`, "allowed_request_content_type seulement"},
		{"retrait de 949110", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=949110"`, "hors de la plage excluable"},
		{"retrait de 19110", "after.conf", why + `SecRuleUpdateTargetById 19110 "!ARGS:x"`, "hors de la plage excluable"},
		{"plage sur deux familles", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941000-942999"`, "deux familles"},
		{"retrait sans chemin", "before.conf", why + `SecRule &REQUEST_HEADERS:X-Foo "@gt 0" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100"`, "condition de chemin"},
		{"retrait sur la racine", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100"`, "différent de /"},
		{"REQUEST_URI au lieu de FILENAME", "before.conf", why + `SecRule REQUEST_URI "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100"`, "REQUEST_FILENAME"},
		{"opérateur rx en exclusion", "before.conf", why + `SecRule REQUEST_FILENAME "@rx ^/api" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100"`, "@beginsWith ou @streq"},
		{"cible TX", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=OWASP_CRS;TX:blocking_inbound_anomaly_score"`, "collection \"TX\" refusée"},
		{"regex de clé avec alternative", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS:/^abcd|.*/"`, "rien d'autre"},
		{"regex de clé trop courte", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS:/^ab/"`, "au moins 4"},
		{"regex de clé non ancrée", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!REQUEST_COOKIES:/ph_phc_/"`, "rien d'autre"},
		{"tag protégé", "after.conf", why + `SecRuleUpdateTargetByTag ademe-obligatoire "!ARGS:abcd"`, "non admis"},
		{"id hors plage", "before.conf", why + `SecRule REQUEST_FILENAME "@streq /x" "id:9999,phase:1,pass,nolog,ctl:ruleRemoveById=941100"`, "hors de la plage du tenant"},
		{"PL 0", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=0"`, "hors de 1 à 3"},
		{"seuil 50", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=50"`, "hors de 2 à 5"},
		{"TRACE", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=GET POST TRACE'"`, "TRACE"},
		{"setvar incrément", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=+5"`, "entier attendu"},
		{"macro", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%{tx.x}"`, "macro"},
		{"sampling", "config.conf", why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.sampling_percentage=0"`, "setvar admis"},
		{"sans raison", "config.conf", `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1"`, "commentaire"},
		{"deux disruptives", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'x',pass"`, "interdite dans un durcissement"},
		{"durcissement avec ctl", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'x',ctl:ruleRemoveById=941100"`, "interdite dans un durcissement"},
		{"durcissement avec chain", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'x',chain"`, "interdite dans un durcissement"},
		{"opérateur inspectFile", "before.conf", why + `SecRule FILES "@inspectFile /bin/x" "id:31001,phase:2,deny,log,msg:'x'"`, "refusé"},
		{"opérateur pmFromFile", "before.conf", why + `SecRule ARGS "@pmFromFile /etc/passwd" "id:31001,phase:2,deny,log,msg:'x'"`, "refusé"},
		{"msg avec macro", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'%{MATCHED_VAR}'"`, "macro"},
		{"variable TX en durcissement", "before.conf", why + `SecRule TX:x "@eq 1" "id:31001,phase:2,deny,log,msg:'x'"`, "refusée dans un durcissement"},
		{"maillon de chain hors méthode", "before.conf", why + "SecRule REQUEST_FILENAME \"@streq /x\" \"id:31001,phase:1,pass,nolog,chain\"\nSecRule ARGS:a \"@streq b\" \"t:none,ctl:ruleRemoveById=941100\"", "REQUEST_METHOD"},
		{"maillon de chain avec id", "before.conf", why + "SecRule REQUEST_FILENAME \"@streq /x\" \"id:31001,phase:1,pass,nolog,chain\"\nSecRule REQUEST_METHOD \"@streq POST\" \"id:31002,ctl:ruleRemoveById=941100\"", "maillon de chain : id interdit"},
		{"chain en fin de fichier", "before.conf", why + `SecRule REQUEST_FILENAME "@streq /x" "id:31001,phase:1,pass,nolog,chain"`, "chain sans règle suivante"},
		{"type de contenu inconnu", "before.conf", why + `SecRule &REQUEST_HEADERS:Next-Action "@gt 0" "id:31001,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=|application/x-evil|'"`, "refusé"},
		{"en-tête avec retrait", "before.conf", why + `SecRule &REQUEST_HEADERS:X-A "@gt 0" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:a"`, "condition de chemin"},
		{"id en double", "before.conf", why + "SecRule REQUEST_FILENAME \"@streq /a\" \"id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100\"\n" + why + "SecRule REQUEST_FILENAME \"@streq /b\" \"id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100\"", "déjà utilisé"},
		{"quatre chemins pour une famille", "before.conf", strings.Repeat("", 0) +
			why + "SecRule REQUEST_FILENAME \"@streq /a\" \"id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100\"\n" +
			why + "SecRule REQUEST_FILENAME \"@streq /b\" \"id:31002,phase:1,pass,nolog,ctl:ruleRemoveById=941110\"\n" +
			why + "SecRule REQUEST_FILENAME \"@streq /c\" \"id:31003,phase:1,pass,nolog,ctl:ruleRemoveById=941120\"\n" +
			why + "SecRule REQUEST_FILENAME \"@streq /d\" \"id:31004,phase:1,pass,nolog,ctl:ruleRemoveById=941130\"", "4 conditions de chemin"},
		// Écarts possibles entre le linter et le parseur de Coraza.
		{"backtick", "before.conf", why + "SecRule ARGS \"@rx `x`\" \"id:31001,phase:2,deny,log,msg:'x'\"", "backtick"},
		{"tabulation", "before.conf", why + "SecRule\tARGS \"@rx x\" \"id:31001,phase:2,deny,log,msg:'x'\"", "tabulation"},
		{"commentaire dans une continuation", "before.conf", why + "SecRule REQUEST_FILENAME \"@streq /x\" \\\n# piège\n\"id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941100\"", "commentaire au milieu"},
		{"continuation ouverte", "before.conf", why + "SecRule REQUEST_FILENAME \"@streq /x\" \\", "continuation ouverte"},
		{"guillemet échappé", "before.conf", why + `SecRule ARGS "@rx a\"b" "id:31001,phase:2,deny,log,msg:'x'"`, "guillemet"},
		{"barre oblique dans les actions", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'a\,b'"`, "barre oblique"},
		{"apostrophe au milieu", "before.conf", why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:a'b'"`, "apostrophes"},
		{"directive en minuscules", "config.conf", why + `secaction "id:30001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"`, "seul SecAction"},
		{"Include", "after.conf", why + `Include /etc/passwd`, "seuls SecRuleUpdateTargetById"},
		{"fichier en trop", "coraza/extra.conf", "", "fichier inattendu"},
		// Contournements démontrés par la relecture du 2026-11-13.
		{"préfixe court", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /a" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941000-941999"`, "segments entiers"},
		{"familles cumulées sur un préfixe", "before.conf", why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941000-941999,ctl:ruleRemoveById=942000-942999,ctl:ruleRemoveById=932000-932999"`, "3 familles"},
		{"familles cumulées par préfixes imbriqués", "before.conf",
			why + `SecRule REQUEST_FILENAME "@beginsWith /api/" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveById=941000-941999,ctl:ruleRemoveById=942000-942999"` + "\n" +
				why + `SecRule REQUEST_FILENAME "@beginsWith /api/v1/" "id:31002,phase:1,pass,nolog,ctl:ruleRemoveById=932000-932999"`, "3 familles"},
		{"ctl sur la tête d'une chain", "before.conf", why + "SecRule REQUEST_FILENAME \"@beginsWith /api/\" \"id:31001,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=941000-941999,chain\"\nSecRule REQUEST_METHOD \"@streq POST\" \"t:none\"", "tête d'une chain"},
		{"within dans le maillon", "before.conf", why + "SecRule REQUEST_FILENAME \"@beginsWith /api/\" \"id:31001,phase:1,pass,nolog,t:none,chain\"\nSecRule REQUEST_METHOD \"@within POST PUT\" \"t:none,ctl:ruleRemoveById=941000-941999\"", "une méthode par maillon"},
		{"regex de clé json", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS:/^json.[a-v]/"`, "littéraux"},
		{"regex de clé json sans point", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS:/^jsonx/"`, "json"},
		{"regex de clé avec quantificateur", "after.conf", why + `SecRuleUpdateTargetByTag OWASP_CRS "!ARGS:/^abcd?/"`, "littéraux"},
		{"regex d'en-tête en majuscules", "before.conf", why + `SecRule REQUEST_FILENAME "@streq /x" "id:31001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;REQUEST_HEADERS:/^X-Abcd/"`, "minuscules"},
		{"ligne de plus de 60 000 octets", "before.conf", why + "# " + strings.Repeat("a", 70000) + "\n" + why + `SecRule ARGS "@rx x" "id:31001,phase:2,deny,log,msg:'x'"`, "ligne de plus de"},
		{"fichier géant", "tests/big.yaml", strings.Repeat("a", 300<<10), "fichier de plus de"},
		{"dossier en trop", "x/y", "", "dossier inattendu"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name := c.file
			if !strings.Contains(name, "/") {
				name = "coraza/" + name
			}
			r := Tenant(tenantDir(t, map[string]string{name: c.body}), pol(t), nil)
			for _, f := range r.Errors() {
				if strings.Contains(strings.ToLower(f.Msg), strings.ToLower(c.want)) {
					return
				}
			}
			t.Fatalf("erreur contenant %q attendue, obtenu %v", c.want, r.Findings)
		})
	}
}

func TestAccepte(t *testing.T) {
	ok := map[string]string{
		"coraza/config.conf": why + `SecAction "id:30001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=3,setvar:'tx.allowed_methods=GET HEAD POST PUT'"`,
		"coraza/before.conf": why + "SecRule REQUEST_FILENAME \"@beginsWith /api/upload/\" \\\n    \"id:31001,phase:1,pass,nolog,t:none,chain\"\n    SecRule REQUEST_METHOD \"@streq PUT\" \"t:none,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:description\"\n\n" +
			why + `SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto" "id:31100,phase:1,deny,status:403,log,msg:'Scanner connu',tag:'durcissement',t:lowercase"` + "\n\n" +
			why + `SecRule REMOTE_ADDR "!@ipMatch 192.0.2.0/24" "id:31101,phase:1,deny,log,msg:'Admin hors réseau',t:none"`,
		"coraza/after.conf": why + `SecRuleUpdateTargetById 942100 "!ARGS:json.query"` + "\n" + why + `SecRuleUpdateTargetByTag attack-xss "!REQUEST_COOKIES:/^session_$/"`,
		"waf.yaml":          "version: 1\n",
		"tests/xss.yaml":    "---\n",
	}
	r := Tenant(tenantDir(t, ok), pol(t), nil)
	if errs := r.Errors(); len(errs) > 0 {
		t.Fatalf("refusé à tort : %v", errs)
	}
	if r.BlockingPL != 2 || r.DetectionPL != 3 {
		t.Fatalf("PL lus : %d et %d", r.BlockingPL, r.DetectionPL)
	}
}
