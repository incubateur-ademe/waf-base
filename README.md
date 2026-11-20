# waf-base

Image de base du WAF Caddy + Coraza des apps de l'incubateur ADEME, publiée sur `ghcr.io/incubateur-ademe/waf-base`, paquet privé : les serveurs la tirent avec un PAT classic `read:packages`, et tout autre usage la reconstruit depuis ce dépôt public.
Le design est dans le dossier finops (`waf-coraza-design.md`, sections 5 à 8).

## Contenu

- `main.go` : Caddy 2.11.9 avec coraza-caddy v2.6.2 et caddy-ratelimit `5625512f`, Coraza épinglé au commit `12c67370`.
- `cmd/wafgen`, `internal/` : `wafgen check` (lint des formes, rendu fictif, `caddy validate`, attaque canonique en mémoire), `wafgen run` (rendu depuis les variables ops, contrôles de démarrage, drain à l'arrêt), `wafgen rev`, `wafgen provision`.
- `ops/Dockerfile`, `internal/ops` : image et commande `wafgen ops` du conteneur `waf-ops` d'outils. Boucle toutes les 5 minutes : pour chaque app `live` et Scalingo des stages de `WAF_OPS_STAGES`, règles du firewall Scalingo égales aux IP des VM de son stage si `LOCK_<APP>` est posée, chaque host rattaché à l'app en `host_header: visitor`, puis pulse updown (`waf-ops-ok`, ou `waf-ops-ko:` et les écarts) et état dans `/var/lib/waf-ops/etat.json`. L'app et la région Scalingo viennent de `UPSTREAM_<APP>`. L'API Scalingo passe par FGP : un blob d'API de lecture par région, tous chiffrés avec la clé `WAF_OPS_FGP_KEY` ; `wafgen ops fgp-scopes` rend les demandes de blobs. `wafgen ops controle` fait un passage à la demande, sans pulse.
- `caddy/Caddyfile` : options globales, serveur `:2020` (santé, métriques, mode), catch-all 421. Les routes d'une app sont ajoutées en JSON par `wafgen run`.
- `coraza/` : conf recommandée de Coraza 3.8.1 (SHA-256 vérifié au build), `10-moteur`, `20-planchers`, `90-garde-fous`.
- `crs/` : version et SHA-256 de la CRS 4.25.2 LTS, téléchargée et vérifiée au build.
- `policy/` : règles excluables, formes SecLang admises, origines par plateforme, schéma de `waf.yaml`.
- `lint/` : action appelée par les repos des startups, et modèle de workflow.
- `inventaire.yaml` : apps protégées, lu par `wafgen provision`. `canonical: <host>`, optionnel et propre à une app (refusé dans `defaults`), redirige en 301 les autres hosts de l'app vers ce host, après le rate limit et Coraza (`WAF_CANONICAL_HOST`). La 301 porte `Cache-Control: max-age=86400`, pour qu'un navigateur l'oublie au bout d'un jour si le canonique est inversé.
  - `edge: cloudflare`, optionnel et propre à une app : `wafgen provision` pose `WAF_EDGE_SECRET` (référence à `EDGE_SECRET_<APP>`, variable d'équipe créée par ops, 32 caractères au moins dans `[A-Za-z0-9_-]`, par exemple `openssl rand -hex 32`) et `WAF_EDGE`, retenue tant que cette variable d'équipe n'est pas remplie pour que l'app reste déployable. Une Transform Rule de chaque zone Cloudflare qui porte un host proxifié de l'app pose ce secret dans `X-Ademe-Edge`, sur les seuls hosts de l'app (`http.host in {...}`) et jamais sur toute la zone, dont les autres origines recevraient le secret. Zone en SSL Full (strict), « Pseudo IPv4 » coupé pour que `CF-Connecting-IP` garde l'IPv6 du visiteur. Avec le secret, `CF-Connecting-IP` devient l'IP du visiteur pour le rate limit, Coraza, `/__waf/ip` et `X-Forwarded-For` ; sans lui, le WAF garde l'IP vue par Traefik. Pour toute app, `edge` ou non, aucun des deux en-têtes n'atteint l'origine, `X-Ademe-Edge` est retiré avant Coraza et des logs de Caddy : une règle posée avant le passage de l'app en `edge` ne fait pas fuir le secret.
  - `vms` : les VM WAF par nom, avec leur stage (`prod` ou `preprod`) et leur IP publique, celle que le firewall des apps autorise. `wafgen provision` ne traite que les apps du stage de `WAF_OPS_VM` et les nomme `waf-<app>-<vm>`. `stage: preprod`, optionnel et propre à une app (refusé dans `defaults`), la place sur les VM de preprod. Une app de même nom sur une autre VM est un jumeau : `provision` vérifie qu'il tourne sur un autre serveur, et ne repasse les domaines avec `force_domain_override` qu'après un 409 de Coolify dont chaque conflit désigne un jumeau. Un conflit avec une autre ressource de l'équipe arrête `provision`. `WAF_OPS_BASE_REF={{server.WAF_BASE}}` donne à chaque VM sa base, par une variable partagée de serveur que `provision` vérifie.
- `tests/exemple-tacct/` : le `waf/` d'exemple de la section 6 ; `tests/e2e/run.sh` : test de bout en bout local (Traefik, WAF, origine HTTPS factice).

## Le waf/ d'une app

`waf/Dockerfile`, identique partout :

```dockerfile
ARG WAF_BASE
FROM ${WAF_BASE}
```

Build local, sans accès au paquet privé :

```sh
docker build -t waf-base:local https://github.com/incubateur-ademe/waf-base.git#main
docker build --build-arg WAF_BASE=waf-base:local waf/
```

## Versions

`release.yml` publie deux familles d'images sur `ghcr.io/incubateur-ademe/waf-base`. Les deux sont attestées (build provenance) par ce workflow, sur `refs/heads/main`, par un runner hébergé par GitHub.

- **`main`.** Chaque push sur `main` qui ne touche pas que `inventaire.yaml` ou des fichiers `.md` construit l'image sur l'arbre du commit, la teste, la pousse sous le tag de travail `pending`, l'atteste, puis la publie sous `main-<sha>`, `<sha>` étant le commit complet (job `build`). Le job `main` déplace ensuite `:main` sur ce digest, seulement vers un commit qui descend de celui que `:main` désigne d'après son attestation. waf-preprod suit cette famille. `pending` ne se tire jamais.
- **Releases.** release-please tient à jour une PR de release, `chore(main): release X.Y.Z`, refaite sur `main` à chaque run (`always-update`). Elle ne touche que `CHANGELOG.md` et `.release-please-manifest.json`. Sa fusion publie `main-<sha>` du commit de fusion comme tout push, puis le job `release` crée le tag git `vX.Y.Z` et la release GitHub. Le job `semver` vérifie que ce tag désigne la fusion d'une PR de release-please et que l'attestation de `main-<sha>` est liée à ce commit, puis pose le tag d'image `vX.Y.Z` sur le même digest. waf-1 ne prend que ces images.

Un re-run ne réécrit rien : `build` échoue si `main-<sha>` existe, `semver` si `vX.Y.Z` existe sur un autre digest. `semver` tourne à chaque run et rattrape la dernière release si son tag d'image manque.

**Prérequis du job `release`**, qui seul lit un secret :
- une App GitHub dédiée, sans webhook, installée sur ce dépôt seul, avec Contents et Pull requests en écriture et rien d'autre (Metadata en lecture est imposé). Une PR ouverte avec `GITHUB_TOKEN` ne lancerait pas la CI ;
- l'environnement `release`, réservé à la branche `main` par une règle de déploiement, qui porte la variable `RELEASE_APP_CLIENT_ID` et le secret `RELEASE_APP_PRIVATE_KEY` de l'App, jamais au niveau du dépôt ni de l'organisation ;
- les labels `autorelease: pending` et `autorelease: tagged`.

Sans eux, `release` échoue à chaque push, et `build` et `main` publient quand même.

**Numéros et notes.** `CHANGELOG.md` ne retient que ce qui change à l'exécution du WAF. Trois filtres :
- le type : `feat`, `fix`, `perf`, `revert`, `deps`, `build`, `chore(deps)` et `build(deps)` ; les autres types sont masqués ;
- le scope : `ops`, `provision`, `inventaire`, `coolify`, `cloudflare`, `ghaudit` et `certs` sont masqués, car ce code part de `main` sans release. Un changement de l'exécution prend le scope du composant (`render`, `runner`, `lint`…) ;
- les dossiers : un commit dont tous les fichiers sont sous un dossier de `exclude-paths` est ignoré. Ce sont les dossiers que l'image n'embarque pas, et les paquets d'outillage. release-please ne compare que des dossiers : un fichier à la racine, le README par exemple, ne s'exclut pas.

Un paquet ou un scope d'outillage nouveau s'ajoute à `release-please-config.json`. Un commit masqué n'ouvre pas de release. `feat` monte le mineur, `fix` le correctif. Un `!` ou un pied `BREAKING CHANGE:` monte le majeur : il est réservé à ce qui casse le `waf/` d'une app.

Les tags `v1.<n>`, numérotés par run de `release.yml` jusqu'à la bascule sur release-please, ne bougent plus, `:v1` non plus. La première release est `v2.0.0` (`initial-version`) :
- elle se classe après tout `v1.<n>`, quel que soit le nombre de builds publiés avant la bascule (`v1.19` au 2026-11-20) ;
- elle ne se confond avec aucun, alors qu'un `v1.19.0` et le `v1.19` déjà publié seraient deux images différentes ;
- le changement de schéma casse la lecture des tags : `:v1` cesse de suivre `main`.

Ses notes partent du commit `0cf7092c` (`v1.11`, `bootstrap-sha`). Les tags git `v2.x` ne sont pas des versions de module Go, le chemin du module n'ayant pas de suffixe `/v2`. Rien n'importe `waf-base` comme module : l'action de lint reconstruit l'image depuis le source.

### Montée

waf-preprod prend chaque image `main-<sha>`, à la main tant que `waf-ops` ne le fait pas. waf-1 ne prend qu'une release. La variable `WAF_BASE` que lisent les apps d'une VM porte toujours un digest, `ghcr.io/incubateur-ademe/waf-base@sha256:<digest>`, jamais un tag. Une montée se finit par un redéploiement forcé des apps : sans `force`, Coolify garde l'image déjà construite.

Avant de monter waf-1 sur `vX.Y.Z`, l'opérateur vérifie, avec `gh` 2.103.3 ou plus récent et un `docker login ghcr.io` par un jeton `read:packages` :
1. les notes de `vX.Y.Z` : rien qui demande un geste sur les apps de waf-1. Chaque commit de `gh api repos/incubateur-ademe/waf-base/compare/<release précédente>...vX.Y.Z` (`0cf7092c` pour `v2.0.0`) y figure ou porte un type ou un scope masqué ;
2. le tag git, qui désigne un commit, fusion d'une PR de la branche `release-please--branches--main` :
   ```sh
   R=incubateur-ademe/waf-base
   gh api repos/$R/git/ref/tags/vX.Y.Z --jq '.object.type + " " + .object.sha'
   gh api repos/$R/commits/<sha>/pulls --jq '.[] | [.head.ref, .merge_commit_sha] | @tsv'
   ```
3. le digest de `vX.Y.Z`, égal à celui de `main-<sha>` :
   ```sh
   docker buildx imagetools inspect ghcr.io/$R:vX.Y.Z --format '{{json .Manifest}}' | jq -r .digest
   docker buildx imagetools inspect ghcr.io/$R:main-<sha> --format '{{json .Manifest}}' | jq -r .digest
   ```
4. l'attestation de ce digest, liée à ce commit, vérifiée sur le manifeste brut, sans que `gh` accède au registre :
   ```sh
   docker buildx imagetools inspect --raw ghcr.io/$R@<digest> > manifest.json
   shasum -a 256 manifest.json
   gh attestation verify manifest.json --repo $R \
     --signer-workflow $R/.github/workflows/release.yml \
     --source-ref refs/heads/main --source-digest <sha> --deny-self-hosted-runners
   ```
   Le SHA-256 du fichier redonne le digest ;
5. waf-preprod a servi ce digest 24 h au moins, pulse au vert, sans hausse des 403 ni des 5xx. Une PR de release se fusionne donc quand aucun autre merge n'est attendu sur `main` dans la journée. Sinon, waf-1 attend une release dont le digest a tenu 24 h.

### Suivi de `main` par `waf-ops`

`waf-ops` suivra `main` pour waf-preprod, et pour elle seule, en lisant :
1. le digest de `ghcr.io/incubateur-ademe/waf-base:main`, par l'API du registre ;
2. le manifeste brut de ce digest, dont le SHA-256 redonne le digest, puis son attestation, vérifiée comme ci-dessus sans `--source-digest`, avec `--format json`. Le commit source se lit dans le certificat, `.[0].verificationResult.signature.certificate.sourceRepositoryDigest`, et non dans le prédicat, que le workflow rédige ;
3. la position de ce commit par rapport à celui du digest que sert waf-preprod, lu de la même façon : `GET /repos/incubateur-ademe/waf-base/compare/<en service>...<nouveau>` doit répondre `ahead`.

Il écrira alors ce digest dans la variable `WAF_BASE` de waf-preprod et redéploiera ses apps avec `force`. Il ne lira jamais `vX.Y.Z` et ne touchera jamais la base de waf-1. Ce suivi demande à `waf-ops` plus d'accès qu'aujourd'hui : un jeton `read:packages` gardé, l'écriture des variables de serveur et le déploiement dans Coolify. Il devra aussi pouvoir se suspendre, pour garder le digest d'une release sur waf-preprod le temps de l'observer.

### Incidents de publication

- `build` ne publie `main-<sha>` qu'après l'attestation : un échec avant se relance tel quel. Une fois `main-<sha>` publié, relancer `build` échoue. On relance alors les jobs `main`, `release` ou `semver` seuls.
- S'il manque `main-<sha>` du commit de release (run de ce commit annulé, en échec, ou remplacé dans la file de concurrence), `semver` échoue dans le run qui crée la release. On relance le run du commit de release : son `semver` pose le tag.
- Une release dont le commit n'a pas d'image, parce que ses tests échouent, ne se monte pas. `semver` le signale en avertissement, et la release suivante la remplace.
- release-please lit l'historique de `main` jusqu'à la dernière release : on fusionne en squash, sans quoi les commits d'une branche plus anciens que cette release seraient perdus pour les notes.

## Développement

```sh
go vet ./... && go test ./...
docker build -t waf-base:local .
tests/e2e/run.sh waf-base:local
```
