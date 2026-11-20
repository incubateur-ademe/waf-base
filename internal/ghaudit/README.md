# ghaudit

Audit côté GitHub du verrou des confs WAF (sections 7 et 8.1 du design), lancé par `waf-ops` avec une App GitHub en lecture seule. Le package n'importe pas `internal/ops` : l'audit horaire l'appelle ainsi.

```go
cfg, err := ghaudit.FromEnv(getenv)             // WAF_OPS_GITHUB_APP_ID, WAF_OPS_GITHUB_APP_KEY
ecarts, notes, err := ghaudit.Audit(ctx, cfg, apps) // apps déjà filtrées par stage et live
```

Un écart est une phrase courte pour le pulse KO. Une note est un détail pour les logs. `err` dit que l'audit n'a pas pu se faire : configuration refusée, App absente de l'org ops, équipe ops illisible. Une panne sur un repo donne un écart sur ce repo, et les autres repos sont audités.

## Contrôles

Les apps qui partagent un repo, une branche et un dossier `waf_dir` ne font qu'un audit. La branche contrôlée est celle de l'inventaire, celle que Coolify déploie. Une note la signale quand elle diffère de la branche par défaut.

1. **CODEOWNERS.** La CODEOWNERS en vigueur est la première trouvée dans `.github/`, à la racine, puis dans `docs/`, comme GitHub. Elle doit être un fichier ordinaire, sans erreur signalée par GitHub (`codeowners/errors`). Pour chaque fichier sensible, la dernière règle qui le couvre ne doit avoir pour propriétaire que `@incubateur-ademe/secops` : un second propriétaire pourrait approuver seul. Fichiers sensibles : tout fichier présent dans `waf/`, les fichiers admis par le lint même absents, `.dockerignore`, `Dockerfile.dockerignore` et un nom fictif dans `waf/`, la CODEOWNERS en vigueur et les emplacements qui la masqueraient s'ils étaient créés, `.gitmodules`, `.gitattributes` et `.lfsconfig`. Un motif hors de la syntaxe sûre, une règle signalée en erreur ou un motif joker qui ne couvre qu'un dossier parent (`docs/*`) ne réserve jamais un fichier, et masque les règles précédentes s'il ne nomme pas que l'équipe ops. Le calcul est borné, parce que la startup écrit la CODEOWNERS : 128 Kio et 1 000 règles au plus, 32 segments au plus par motif et par chemin, 100 fichiers de `waf/` au plus, et au-delà un écart. Le temps de calcul est linéaire en segments.
2. **`secops` en write.** Droit `push`, `maintain` ou `admin` de l'équipe sur le repo. Un repo hors de l'org `incubateur-ademe` est un écart : sa CODEOWNERS ne peut pas nommer l'équipe.
3. **Aucun admin hors ops.** Collaborateurs `affiliation=all`, équipes comprises. Les propriétaires de l'org sont admins de chaque repo par construction : ils sont exemptés et notés une fois par audit, risque accepté en section 13 du design.
4. **Protection de la branche.** Une seule source doit suffire. Protection classique : PR obligatoire, revue des code owners, approbations révoquées au push, règles appliquées aux administrateurs, aucun contournement de PR, suppression de la branche et force push interdits. Avec la seule approbation du dernier push, une approbation d'ops donnée avant un nouveau commit resterait comptée : elle ne remplace pas la révocation. Une branche déployée qui n'est pas la branche par défaut, supprimée puis recréée par un push, échapperait à la PR. Ruleset : actif, règle `pull_request` avec revue des code owners et révocation au push, règles `deletion` et `non_fast_forward` dans ce même ruleset, liste de contournement lisible et vide.
5. **`waf/Dockerfile` canonique.** Fichier ordinaire, égal à l'octet près aux deux lignes de la section 5.4.
6. **Aucun `.dockerignore` dans `waf/`.** Tout fichier dont le nom finit par `.dockerignore`, à tout niveau de `waf/`, en un seul écart.

Un nom de fichier ou un login venu de GitHub n'entre dans un écart ou une note qu'assaini (caractères de contrôle et de format remplacés, 120 octets au plus), et les listes sont bornées. Deux apps d'un même repo ne rejouent ni les droits ni la protection, et un écart n'apparaît qu'une fois.

### Repo privé sur le plan Free : écart

Un repo privé n'a ni protection de branche ni ruleset sur le plan Free. L'audit lève un écart et non une note. La section 8.1 du design sort ces repos du contrat : leurs règles passent par un repo public `incubateur-ademe/waf-<app>`. La couche 5 de la section 7 repose sur la protection : sans elle, la startup fusionne une PR qui modifie `waf/Dockerfile` sans la revue d'ops. Une note laisserait le pulse vert sur une app dont le verrou ne tient pas, ce que l'audit doit justement signaler. Si l'org passe au plan Team, un repo privé protégé passe l'audit sans changement de code.

### Ruleset : contournements illisibles en lecture seule

GitHub ne rend `bypass_actors` d'un ruleset qu'à qui peut le modifier. Une App en lecture ne le voit jamais, donc un ruleset seul ne prouve pas l'absence de contournement et ne suffit pas. En pratique, la protection classique est requise, et elle se lit entière avec Administration en lecture. Au 2026-11-20, `incubateur-ademe/tacct` n'a qu'un ruleset, avec un contournement `always` d'un membre de `secops` : il recevra un écart quand la prod entrera dans l'audit. La correction est la protection classique de `waf-pilote`, ruleset conservé ou non.

## Permissions de l'App

Toutes en lecture. Le jeton d'installation est demandé avec ces seuls droits, même si l'App en reçoit d'autres. Une installation avec un droit au-delà de la lecture lève un écart, un droit en lecture hors de cette liste une note.

| Permission | Niveau | Routes | Pourquoi |
|---|---|---|---|
| Repository, Metadata | read | `GET /repos/{o}/{r}`, `/collaborators`, `/rules/branches/{b}`, `/rulesets/{id}` | visibilité du repo, admins, rulesets de la branche. GitHub l'impose à toute App. |
| Repository, Contents | read | `GET /repos/{o}/{r}/branches/{b}`, `/git/trees/{sha}`, `/git/blobs/{sha}`, `/codeowners/errors` | arbre de la branche, CODEOWNERS, `waf/Dockerfile`, `.dockerignore`, erreurs de CODEOWNERS. |
| Repository, Administration | read | `GET /repos/{o}/{r}/branches/{b}/protection`, `/teams` | protection classique, droit de `secops` sur le repo. |
| Organization, Members | read | `GET /orgs/{org}/teams/secops/members`, `/orgs/{org}/members?role=admin` | qui est ops, qui est propriétaire de l'org. |

Rien d'autre : ni webhook, ni permission de compte, ni OAuth. Le client refuse toute route, méthode, authentification ou paramètre hors de sa liste. La seule écriture est la création du jeton d'installation. Il ne suit aucune redirection, borne chaque réponse à 4 Mio et ne reprend jamais un corps de réponse dans une erreur.

Contents en lecture ouvre le code des repos où l'App est installée : l'installation se limite aux repos de l'inventaire.

## Gestes ops

1. Créer l'App dans l'org `incubateur-ademe` (Settings, Developer settings, GitHub Apps, New GitHub App) : nom `waf-ops-audit`, URL du repo `waf-base` en homepage, webhook désactivé (« Active » décoché), les quatre permissions ci-dessus et aucune autre, « Only on this account ».
2. Générer une clé privée et relever le Client ID.
3. Installer l'App sur `incubateur-ademe`, « Only select repositories », avec les repos de l'inventaire. Chaque nouvelle app ajoute son repo à l'installation, sinon l'audit lève « repo introuvable ou hors de l'installation de l'App d'audit ».
4. Variables de la ressource Coolify `waf-ops`, en runtime seul et « literal » : `WAF_OPS_GITHUB_APP_ID` (Client ID) et `WAF_OPS_GITHUB_APP_KEY` (le PEM, multiligne). Une clé saisie sur une ligne avec des `\n` littéraux est aussi acceptée.
5. Supprimer le `.pem` téléchargé une fois la variable saisie, et suivre le renouvellement de la clé dans `todo.md` de finops.
