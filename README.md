# waf-base

Image de base du WAF Caddy + Coraza des apps de l'incubateur ADEME, publiée sur `ghcr.io/incubateur-ademe/waf-base`, paquet privé : les serveurs la tirent avec un PAT classic `read:packages`, et tout autre usage la reconstruit depuis ce dépôt public.
Le design est dans le dossier finops (`waf-coraza-design.md`, sections 5 à 8).

## Contenu

- `main.go` : Caddy 2.11.9 avec coraza-caddy v2.6.2 et caddy-ratelimit `5625512f`, Coraza épinglé au commit `12c67370`.
- `cmd/wafgen`, `internal/` : `wafgen check` (lint des formes, rendu fictif, `caddy validate`, attaque canonique en mémoire), `wafgen run` (rendu depuis les variables ops, contrôles de démarrage, drain à l'arrêt), `wafgen rev`.
- `caddy/Caddyfile` : options globales, serveur `:2020` (santé, métriques, mode), catch-all 421. Les routes d'une app sont ajoutées en JSON par `wafgen run`.
- `coraza/` : conf recommandée de Coraza 3.8.1 (SHA-256 vérifié au build), `10-moteur`, `20-planchers`, `90-garde-fous`.
- `crs/` : version et SHA-256 de la CRS 4.25.2 LTS, téléchargée et vérifiée au build.
- `policy/` : règles excluables, formes SecLang admises, origines par plateforme, schéma de `waf.yaml`.
- `lint/` : action appelée par les repos des startups, et modèle de workflow.
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

## Développement

```sh
go vet ./... && go test ./...
docker build -t waf-base:local .
tests/e2e/run.sh waf-base:local
```
