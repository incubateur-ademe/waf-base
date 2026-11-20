package ghaudit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
)

const pilote = "incubateur-ademe/waf-pilote"

type result struct {
	ecarts, notes []string
	err           error
	calls         []string
}

func run(t *testing.T, f *fakeGH, a []inventory.App) result {
	t.Helper()
	_, cfg := f.start()
	e, n, err := Audit(context.Background(), cfg, a)
	res := result{ecarts: e, notes: n, err: err, calls: f.calls}
	assertNoSecret(t, res)
	return res
}

// Aucun secret dans les écarts, notes ou erreurs : jeton, JWT, clé.
func assertNoSecret(t *testing.T, r result) {
	t.Helper()
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey(t))}))
	all := strings.Join(r.ecarts, "\n") + strings.Join(r.notes, "\n")
	if r.err != nil {
		all += r.err.Error()
	}
	for _, s := range []string{testToken, "ghs_", "eyJ", "forcé", "Upgrade", "Not Found", pemKey[40:80]} {
		if strings.Contains(all, s) {
			t.Fatalf("sortie avec %q :\n%s", s, all)
		}
	}
}

func hasEcart(r result, sub string) bool {
	for _, e := range r.ecarts {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func TestConforme(t *testing.T) {
	f := newFake(t)
	r := run(t, f, apps(pilote))
	if r.err != nil || len(r.ecarts) > 0 {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
	joined := strings.Join(r.notes, "\n")
	if !strings.Contains(joined, "propriétaire(s) hors de @incubateur-ademe/secops") || !strings.Contains(joined, "patron") {
		t.Errorf("propriétaire hors ops non noté : %q", r.notes)
	}
}

func TestSansAppAucunAppel(t *testing.T) {
	f := newFake(t)
	r := run(t, f, nil)
	if r.err != nil || len(r.ecarts)+len(r.notes)+len(r.calls) > 0 {
		t.Fatalf("%+v", r)
	}
}

func TestDeuxAppsUnSeulAudit(t *testing.T) {
	f := newFake(t)
	r := run(t, f, apps(pilote, pilote))
	n := 0
	for _, c := range r.calls {
		if c == "GET /repos/"+pilote {
			n++
		}
	}
	if n != 1 || len(r.ecarts) > 0 {
		t.Fatalf("%d audits, écarts %q", n, r.ecarts)
	}
}

func TestDockerfileCanoniqueDuRepo(t *testing.T) {
	b, err := os.ReadFile("../../tests/exemple-tacct/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != DockerfileCanonique {
		t.Fatalf("tests/exemple-tacct/Dockerfile diffère de DockerfileCanonique")
	}
}

// Chaque garde, déclenchée par une mutation de l'état conforme.
func TestGardes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fakeGH, r *fakeRepo)
		want   string
	}{
		{"CODEOWNERS absente", func(_ *fakeGH, r *fakeRepo) { delete(r.files, ".github/CODEOWNERS") }, "aucune CODEOWNERS sur main"},
		{"CODEOWNERS sans waf", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/waf/", "/autre/", 1)}
		}, "ne réserve pas à @incubateur-ademe/secops : waf/Dockerfile"},
		{"waf avec un second propriétaire", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/waf/                   @incubateur-ademe/secops", "/waf/ @incubateur-ademe/secops @dev1", 1)}
		}, "ne réserve pas"},
		{"règle tardive qui reprend tout", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: canonCO + "* @incubateur-ademe/devs\n"}
		}, "ne réserve pas"},
		{"waf/* ne couvre pas les sous-dossiers", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/waf/ ", "/waf/*", 1)}
		}, "waf/coraza/"},
		{"CODEOWNERS non réservée", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/.github/CODEOWNERS ", "/.github/autre ", 1)}
		}, ": .github/CODEOWNERS"},
		{".gitmodules non réservé", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/.gitmodules", "/.gitignore", 1)}
		}, ".gitmodules"},
		{"CODEOWNERS à la racine masquable", func(_ *fakeGH, r *fakeRepo) {
			delete(r.files, ".github/CODEOWNERS")
			r.files["CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/.github/CODEOWNERS ", "/CODEOWNERS ", 1)}
		}, ": .github/CODEOWNERS"},
		{"CODEOWNERS en lien symbolique", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: "../CO", mode: "120000"}
		}, ".github/CODEOWNERS n'est pas un fichier ordinaire"},
		{"erreur GitHub sur la ligne waf", func(_ *fakeGH, r *fakeRepo) {
			r.coErrors = `{"errors":[{"line":1,"column":25,"kind":"Unknown owner","path":".github/CODEOWNERS","message":"secret ` + testToken + `"}]}`
		}, "1 erreur(s) signalée(s) par GitHub"},
		{"erreur GitHub sur la ligne waf, qui ne réserve plus", func(_ *fakeGH, r *fakeRepo) {
			r.coErrors = `{"errors":[{"line":1,"column":25,"kind":"Unknown owner","path":".github/CODEOWNERS"}]}`
		}, "ne réserve pas à @incubateur-ademe/secops : waf/Dockerfile"},
		{"fichiers admis encore absents", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: strings.Replace(canonCO, "/waf/                   @incubateur-ademe/secops\n", "/waf/Dockerfile @incubateur-ademe/secops\n/waf/.dockerignore @incubateur-ademe/secops\n/waf/Dockerfile.dockerignore @incubateur-ademe/secops\n/waf/waf.yaml @incubateur-ademe/secops\n/waf/coraza/before.conf @incubateur-ademe/secops\n/waf/tests/attaque-sql.yaml @incubateur-ademe/secops\n", 1)}
		}, "waf/README.md, waf/coraza/config.conf, waf/coraza/after.conf (+2)"},
		{"blob de taille incohérente", func(f *fakeGH, _ *fakeRepo) { f.blobExtra = "x" }, "fichiers de main non audités"},
		{"secops sans accès", func(_ *fakeGH, r *fakeRepo) {
			r.teams = `[{"slug":"core","permission":"admin"}]`
		}, "@incubateur-ademe/secops sans droit sur le repo"},
		{"secops en lecture", func(_ *fakeGH, r *fakeRepo) {
			r.teams = `[{"slug":"secops","permission":"pull"}]`
		}, "@incubateur-ademe/secops en pull, write attendu"},
		{"admin hors ops", func(_ *fakeGH, r *fakeRepo) {
			r.collabs = `[{"login":"ops1","permissions":{"admin":true}},{"login":"dev1","permissions":{"admin":true}}]`
		}, "1 admin(s) hors de @incubateur-ademe/secops"},
		{"sans PR obligatoire", func(_ *fakeGH, r *fakeRepo) {
			r.protection = `{"enforce_admins":{"enabled":true}}`
		}, "protection sans PR obligatoire"},
		{"sans revue des code owners", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"require_code_owner_reviews":true`, `"require_code_owner_reviews":false`, 1)
		}, "protection sans revue des code owners"},
		{"approbations non révoquées", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"dismiss_stale_reviews":true`, `"dismiss_stale_reviews":false`, 1)
		}, "sans révocation des approbations au push"},
		{"approbation du dernier push sans révocation", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(strings.Replace(protOK, `"dismiss_stale_reviews":true`, `"dismiss_stale_reviews":false`, 1), `"require_last_push_approval":false`, `"require_last_push_approval":true`, 1)
		}, "protection sans révocation des approbations au push"},
		{"suppression de la branche permise", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"allow_force_pushes"`, `"allow_deletions":{"enabled":true},"allow_force_pushes"`, 1)
		}, "protection qui permet de supprimer la branche"},
		{"force push permis", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"allow_force_pushes":{"enabled":false}`, `"allow_force_pushes":{"enabled":true}`, 1)
		}, "protection qui permet le force push"},
		{"rulesets sans blocage de la suppression", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = "[" + prRuleOK + `,{"type":"non_fast_forward","ruleset_id":42}]`
		}, "rulesets sans blocage de la suppression de la branche"},
		{"rulesets sans blocage du force push", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = "[" + prRuleOK + `,{"type":"deletion","ruleset_id":42}]`
		}, "rulesets sans blocage du force push"},
		{"non appliquée aux admins", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"enforce_admins":{"enabled":true}`, `"enforce_admins":{"enabled":false}`, 1)
		}, "non appliquée aux administrateurs"},
		{"contournement de PR", func(_ *fakeGH, r *fakeRepo) {
			r.protection = strings.Replace(protOK, `"required_approving_review_count":0`, `"required_approving_review_count":0,"bypass_pull_request_allowances":{"users":[{"login":"ops1"}],"teams":[],"apps":[]}`, 1)
		}, "protection contournable par 1 acteur(s)"},
		{"aucune protection", func(_ *fakeGH, r *fakeRepo) { r.protection = "" }, "main sans protection de branche ni ruleset"},
		{"ruleset aux contournements illisibles", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(prRuleOK)
			r.rulesets["42"] = rulesetNoB
		}, "ruleset 42 aux contournements illisibles"},
		{"ruleset contournable", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(prRuleOK)
			r.rulesets["42"] = strings.Replace(rulesetNoB, `"rules":[]`, `"rules":[],"bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}]`, 1)
		}, "ruleset 42 contournable par 1 acteur(s)"},
		{"ruleset sans code owners", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(strings.Replace(prRuleOK, `"require_code_owner_review":true`, `"require_code_owner_review":false`, 1))
		}, "ruleset 42 sans revue des code owners"},
		{"ruleset sans révocation", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(strings.Replace(prRuleOK, `"dismiss_stale_reviews_on_push":true`, `"dismiss_stale_reviews_on_push":false,"require_last_push_approval":true`, 1))
		}, "ruleset 42 sans révocation"},
		{"ruleset en évaluation", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(prRuleOK)
			r.rulesets["42"] = strings.Replace(rulesetNoB, `"active"`, `"evaluate"`, 1) + ""
			r.rulesets["42"] = strings.Replace(r.rulesets["42"], `"rules":[]`, `"rules":[],"bypass_actors":[]`, 1)
		}, "ruleset 42 inactif"},
		{"repo privé sur le plan Free", func(_ *fakeGH, r *fakeRepo) {
			r.private = true
			r.protection = ""
			r.protStatus = 403
		}, "repo privé, sans protection possible sur le plan Free"},
		{"repo privé sur le plan Free, rulesets refusés", func(f *fakeGH, r *fakeRepo) {
			r.private = true
			r.protection = ""
			r.protStatus = 403
			f.status["/repos/"+pilote+"/rules/branches/main"] = 403
		}, "repo privé, sans protection possible sur le plan Free"},
		{"rulesets refusés sur repo public", func(f *fakeGH, _ *fakeRepo) {
			f.status["/repos/"+pilote+"/branches/main/protection"] = 404
			f.status["/repos/"+pilote+"/rules/branches/main"] = 403
		}, "protection de main non auditée"},
		{"Dockerfile modifié", func(_ *fakeGH, r *fakeRepo) {
			r.files["waf/Dockerfile"] = fakeFile{content: "ARG WAF_BASE\nFROM ${WAF_BASE}\n#"}
		}, "waf/Dockerfile différent du Dockerfile canonique"},
		{"Dockerfile de même taille", func(_ *fakeGH, r *fakeRepo) {
			r.files["waf/Dockerfile"] = fakeFile{content: "ARG WAF_BASE\nFROM ${WAF_BAZE}\n"}
		}, "waf/Dockerfile différent du Dockerfile canonique"},
		{"Dockerfile absent", func(_ *fakeGH, r *fakeRepo) { delete(r.files, "waf/Dockerfile") }, "waf/Dockerfile absent"},
		{"Dockerfile en lien symbolique", func(_ *fakeGH, r *fakeRepo) {
			r.files["waf/Dockerfile"] = fakeFile{content: DockerfileCanonique, mode: "120000"}
		}, "waf/Dockerfile n'est pas un fichier ordinaire"},
		{".dockerignore", func(_ *fakeGH, r *fakeRepo) {
			r.files["waf/.dockerignore"] = fakeFile{content: "coraza/before.conf\n.dockerignore\n"}
		}, "1 .dockerignore dans waf/, aucun admis : waf/.dockerignore"},
		{"Dockerfile.dockerignore", func(_ *fakeGH, r *fakeRepo) {
			r.files["waf/Dockerfile.dockerignore"] = fakeFile{content: "*\n"}
		}, "aucun admis : waf/Dockerfile.dockerignore"},
		{"waf absent", func(_ *fakeGH, r *fakeRepo) {
			for p := range r.files {
				if strings.HasPrefix(p, "waf/") {
					delete(r.files, p)
				}
			}
		}, "waf/ absent de main"},
		{"waf en fichier", func(_ *fakeGH, r *fakeRepo) {
			for p := range r.files {
				if strings.HasPrefix(p, "waf/") {
					delete(r.files, p)
				}
			}
			r.files["waf"] = fakeFile{content: "x", mode: "120000"}
		}, "waf n'est pas un dossier"},
		{"arbre tronqué", func(_ *fakeGH, r *fakeRepo) { r.truncated = true }, "arbre de waf/ tronqué"},
		{"branche absente", func(_ *fakeGH, r *fakeRepo) { r.branch = "prod" }, "branche main absente"},
		{"repo introuvable", func(f *fakeGH, _ *fakeRepo) { f.status["/repos/"+pilote] = 404 }, "repo introuvable"},
		{"repo renommé", func(f *fakeGH, _ *fakeRepo) { f.status["/repos/"+pilote] = 301 }, "repo renommé ou transféré"},
		{"erreur serveur", func(f *fakeGH, _ *fakeRepo) { f.status["/repos/"+pilote+"/teams"] = 502 }, "droits non audités : GitHub GET /repos/incubateur-ademe/waf-pilote/teams : HTTP 502"},
		{"limite de requêtes", func(f *fakeGH, _ *fakeRepo) {
			f.rateLimit = true
			f.status["/repos/"+pilote+"/collaborators"] = 403
		}, "limite de requêtes atteinte"},
		{"protection illisible sur repo public", func(f *fakeGH, _ *fakeRepo) {
			f.status["/repos/"+pilote+"/branches/main/protection"] = 403
		}, "protection de main non auditée"},
		{"droit d'écriture de l'App", func(f *fakeGH, _ *fakeRepo) {
			f.installs[opsOrg].perms["contents"] = "write"
		}, "droit contents en write, lecture seule attendue"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.mutate(f, f.repos[pilote])
			r := run(t, f, apps(pilote))
			if r.err != nil {
				t.Fatalf("err %v", r.err)
			}
			if !hasEcart(r, c.want) {
				t.Fatalf("écart %q attendu, obtenu %q", c.want, r.ecarts)
			}
		})
	}
}

// Formes admises, qui ne doivent lever aucun écart.
func TestFormesAdmises(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fakeGH, r *fakeRepo)
	}{
		{"ruleset sans contournement", func(_ *fakeGH, r *fakeRepo) {
			r.protection = ""
			r.rules = rulesWith(prRuleOK)
			r.rulesets["42"] = strings.Replace(rulesetNoB, `"rules":[]`, `"rules":[],"bypass_actors":[]`, 1)
		}},
		{"protection classique et ruleset contournable", func(_ *fakeGH, r *fakeRepo) {
			r.rules = rulesWith(prRuleOK)
			r.rulesets["42"] = rulesetNoB
		}},
		{"CODEOWNERS dans docs, masquages réservés", func(_ *fakeGH, r *fakeRepo) {
			delete(r.files, ".github/CODEOWNERS")
			r.files["docs/CODEOWNERS"] = fakeFile{content: "* @incubateur-ademe/devs\n" + canonCO + "/CODEOWNERS @incubateur-ademe/secops\n/docs/CODEOWNERS @incubateur-ademe/secops\n"}
		}},
		{"waf/** et commentaire en ligne", func(_ *fakeGH, r *fakeRepo) {
			r.files[".github/CODEOWNERS"] = fakeFile{content: "# équipe ops\n*.js @incubateur-ademe/devs\n" + strings.Replace(canonCO, "/waf/                  ", "/waf/** ", 1) + "/src/ @incubateur-ademe/devs # code de l'app\n"}
		}},
		{"secops en admin", func(_ *fakeGH, r *fakeRepo) {
			r.teams = `[{"slug":"SecOps","permission":"admin"}]`
		}},
		{"admin membre de secops, casse différente", func(_ *fakeGH, r *fakeRepo) {
			r.collabs = `[{"login":"Ops2","permissions":{"admin":true}}]`
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.mutate(f, f.repos[pilote])
			r := run(t, f, apps(pilote))
			if r.err != nil || len(r.ecarts) > 0 {
				t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
			}
		})
	}
}

func TestDockerfileDeTailleDifferenteNonTelecharge(t *testing.T) {
	f := newFake(t)
	f.repos[pilote].files["waf/Dockerfile"] = fakeFile{content: "FROM evil\n"}
	r := run(t, f, apps(pilote))
	if !hasEcart(r, "waf/Dockerfile différent") {
		t.Fatalf("écarts %q", r.ecarts)
	}
	for _, c := range r.calls {
		if strings.HasSuffix(c, sha("blob:"+pilote+":waf/Dockerfile")) {
			t.Fatalf("Dockerfile téléchargé malgré sa taille : %s", c)
		}
	}
}

func TestWafDirImbrique(t *testing.T) {
	f := newFake(t)
	rp := f.repos[pilote]
	moveWaf(rp, "waf/pilote")
	a := apps(pilote)
	a[0].WafDir = "waf/pilote"
	r := run(t, f, a)
	if r.err != nil || len(r.ecarts) > 0 {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
	rp.files["waf/pilote/.dockerignore"] = fakeFile{content: "*"}
	f.nodes = nil
	f.calls = nil
	r = run(t, f, a)
	if !hasEcart(r, "aucun admis : waf/pilote/.dockerignore") {
		t.Fatalf("écarts %q", r.ecarts)
	}
}

func TestBrancheAvecSlash(t *testing.T) {
	f := newFake(t)
	f.repos[pilote].branch = "release/prod"
	a := apps(pilote)
	a[0].Branch = "release/prod"
	r := run(t, f, a)
	if r.err != nil || len(r.ecarts) > 0 {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "/branches/release%2Fprod/protection") {
		t.Fatalf("branche non échappée : %q", r.calls)
	}
}

func TestAutreOrg(t *testing.T) {
	f := newFake(t)
	f.repos["betagouv/fcu"] = baseRepo()
	r := run(t, f, apps(pilote, "betagouv/fcu"))
	if r.err != nil || !hasEcart(r, "betagouv/fcu : repo hors de l'installation de l'App d'audit, ou App non installée sur betagouv") {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
	if hasEcart(r, pilote) {
		t.Fatalf("écart sur le pilote : %q", r.ecarts)
	}
	f = newFake(t)
	f.repos["betagouv/fcu"] = baseRepo()
	f.installs["betagouv"] = &fakeInstall{id: 9, perms: map[string]string{"administration": "read", "contents": "read", "metadata": "read"}}
	r = run(t, f, apps("betagouv/fcu"))
	if r.err != nil || !hasEcart(r, "repo hors de l'org incubateur-ademe") || !hasEcart(r, "1 admin(s) hors") {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
}

func TestErreursGlobales(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fakeGH)
		want   string
	}{
		{"App absente de l'org ops", func(f *fakeGH) { delete(f.installs, opsOrg) }, "HTTP 404"},
		{"droit members absent", func(f *fakeGH) { delete(f.installs[opsOrg].perms, "members") }, "droits absents de l'installation : members"},
		{"jeton plus large que demandé", func(f *fakeGH) {
			f.tokenPerms = map[string]string{"administration": "read", "contents": "write", "metadata": "read", "members": "read"}
		}, "jeton d'installation hors des droits demandés"},
		{"installation d'un autre compte", func(f *fakeGH) { f.installs[opsOrg].login = "autre-org" }, "installation d'un autre compte"},
		{"installation suspendue", func(f *fakeGH) { f.installs[opsOrg].suspended = true }, "installation suspendue"},
		{"jeton avec un blanc", func(f *fakeGH) { f.tokenValue = "ghs_a b" }, "jeton d'installation de forme inattendue"},
		{"équipe illisible", func(f *fakeGH) { f.status["/orgs/"+opsOrg+"/teams/secops/members"] = 403 }, "HTTP 403"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.mutate(f)
			r := run(t, f, apps(pilote))
			if r.err == nil || !strings.Contains(r.err.Error(), c.want) {
				t.Fatalf("erreur %q attendue, obtenu %v", c.want, r.err)
			}
		})
	}
}

func TestAppsInvalides(t *testing.T) {
	f := newFake(t)
	bad := []inventory.App{
		{Name: "a", Repo: "incubateur-ademe/..", Branch: "main", WafDir: "waf"},
		{Name: "b", Repo: "pas-de-slash", Branch: "main", WafDir: "waf"},
		{Name: "c", Repo: pilote, Branch: "a..b", WafDir: "waf"},
		{Name: "d", Repo: pilote, Branch: "main", WafDir: "waf/../x"},
		{Name: "e", Repo: pilote, Branch: "main", WafDir: "/waf"},
	}
	r := run(t, f, bad)
	if r.err != nil || len(r.ecarts) != len(bad) || len(r.calls) != 0 {
		t.Fatalf("err %v, écarts %q, appels %q", r.err, r.ecarts, r.calls)
	}
}

func TestPagination(t *testing.T) {
	f := newFake(t)
	var c []string
	for i := 0; i < 150; i++ {
		c = append(c, fmt.Sprintf(`{"login":"dev%d","permissions":{"admin":false}}`, i))
	}
	c = append(c, `{"login":"intrus","permissions":{"admin":true}}`)
	f.repos[pilote].collabs = "[" + strings.Join(c, ",") + "]"
	r := run(t, f, apps(pilote))
	if !hasEcart(r, "1 admin(s) hors") || !strings.Contains(strings.Join(r.notes, "\n"), "intrus") {
		t.Fatalf("écarts %q notes %q", r.ecarts, r.notes)
	}
}

func rulesWith(pr string) string {
	return "[" + pr + `,{"type":"deletion","ruleset_id":42},{"type":"non_fast_forward","ruleset_id":42}]`
}

func count(l []string, sub string) int {
	n := 0
	for _, s := range l {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// Un repo hors de l'installation n'empêche pas l'audit des autres repos du même owner.
func TestInstallationParRepo(t *testing.T) {
	f := newFake(t)
	f.repos["betagouv/aaa"] = baseRepo()
	f.repos["betagouv/zzz"] = baseRepo()
	f.installs["betagouv"] = &fakeInstall{id: 9, perms: map[string]string{"administration": "read", "contents": "read", "metadata": "read"}}
	f.status["/repos/betagouv/aaa/installation"] = 404
	r := run(t, f, apps("betagouv/aaa", "betagouv/zzz"))
	if r.err != nil || !hasEcart(r, "betagouv/aaa : repo hors de l'installation") || hasEcart(r, "betagouv/zzz : repo hors de l'installation") {
		t.Fatalf("err %v, écarts %q", r.err, r.ecarts)
	}
	if !hasEcart(r, "betagouv/zzz : repo hors de l'org incubateur-ademe") {
		t.Fatalf("betagouv/zzz non audité : %q", r.ecarts)
	}
}

// Deux waf_dir d'un même repo : droits et protection contrôlés une fois, aucun écart en double.
func TestDeuxDossiersSansDoublon(t *testing.T) {
	f := newFake(t)
	rp := f.repos[pilote]
	rp.protection = ""
	rp.collabs = `[{"login":"dev1","permissions":{"admin":true}}]`
	moveWaf(rp, "waf/a", "waf/b")
	delete(rp.files, ".github/CODEOWNERS")
	a := apps(pilote, pilote)
	a[0].WafDir, a[1].WafDir = "waf/a", "waf/b"
	r := run(t, f, a)
	if count(r.ecarts, "sans protection") != 1 || count(r.ecarts, "admin(s) hors") != 1 || count(r.notes, "admins hors") != 1 || count(r.ecarts, "aucune CODEOWNERS") != 1 {
		t.Fatalf("écarts %q notes %q", r.ecarts, r.notes)
	}
	n := 0
	for _, c := range r.calls {
		if strings.HasSuffix(c, "/collaborators") || strings.HasSuffix(c, "/protection") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d appels de droits et protection, 2 attendus : %q", n, r.calls)
	}
}

// Un nom de fichier venu de GitHub n'arrive dans un écart ou une note qu'affichable et borné.
func TestCheminsAffichables(t *testing.T) {
	f := newFake(t)
	rp := f.repos[pilote]
	evil := "waf/x\x1b[2K\n2026 0 écart(s)\u202e" + strings.Repeat("y", 300) + ".dockerignore"
	rp.files[evil] = fakeFile{content: "*"}
	for i := 0; i < 5; i++ {
		rp.files[fmt.Sprintf("waf/coraza/%d.dockerignore", i)] = fakeFile{content: "*"}
	}
	r := run(t, f, apps(pilote))
	for _, l := range append(append([]string{}, r.ecarts...), r.notes...) {
		if strings.ContainsAny(l, "\x1b\n\u202e") || len(l) > 600 {
			t.Fatalf("sortie non assainie : %q", l)
		}
	}
	if count(r.ecarts, ".dockerignore") != 1 || !hasEcart(r, "6 .dockerignore dans waf/, aucun admis") || !hasEcart(r, "(+3)") {
		t.Fatalf("écarts %q", r.ecarts)
	}
}

func TestShown(t *testing.T) {
	if got := shown("a\x00b\tc\x7f\xffd\u200be"); got != "a?b?c??d?e" {
		t.Fatalf("%q", got)
	}
	long := shown(strings.Repeat("é", 100))
	if !strings.HasSuffix(long, "…") || len(long) > maxShown+len("…") || !utf8.ValidString(long) {
		t.Fatalf("%q", long)
	}
}

func TestBornes(t *testing.T) {
	f := newFake(t)
	rp := f.repos[pilote]
	for i := 0; i < maxWafFiles+5; i++ {
		rp.files[fmt.Sprintf("waf/tests/t%03d.yaml", i)] = fakeFile{content: "x"}
	}
	r := run(t, f, apps(pilote))
	if !hasEcart(r, fmt.Sprintf("waf/ porte %d fichiers", maxWafFiles+5+4)) {
		t.Fatalf("écarts %q", r.ecarts)
	}
	f = newFake(t)
	f.repos[pilote].files[".github/CODEOWNERS"] = fakeFile{content: strings.Repeat("/src/ @x\n", maxRules) + canonCO}
	r = run(t, f, apps(pilote))
	if !hasEcart(r, fmt.Sprintf("de plus de %d règles", maxRules)) {
		t.Fatalf("écarts %q", r.ecarts)
	}
	f = newFake(t)
	f.repos[pilote].files[".github/CODEOWNERS"] = fakeFile{content: canonCO + "#" + strings.Repeat("x", maxCodeowners) + "\n"}
	r = run(t, f, apps(pilote))
	if !hasEcart(r, ".github/CODEOWNERS de plus de 128 Kio, non lue") {
		t.Fatalf("écarts %q", r.ecarts)
	}
}

func TestBrancheParDefautDifferente(t *testing.T) {
	f := newFake(t)
	f.repos[pilote].defaultBranch = "develop"
	r := run(t, f, apps(pilote))
	if len(r.ecarts) > 0 || !strings.Contains(strings.Join(r.notes, "\n"), "branche déployée main, branche par défaut develop") {
		t.Fatalf("écarts %q notes %q", r.ecarts, r.notes)
	}
}

// moveWaf déplace waf/ sous chacun des dossiers donnés.
func moveWaf(rp *fakeRepo, dirs ...string) {
	moved := map[string]fakeFile{}
	for p, file := range rp.files {
		if rest, ok := strings.CutPrefix(p, "waf/"); ok {
			delete(rp.files, p)
			moved[rest] = file
		}
	}
	for rest, file := range moved {
		for _, d := range dirs {
			rp.files[d+"/"+rest] = file
		}
	}
}
