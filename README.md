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
- `inventaire.yaml` : apps protégées, lu par `wafgen provision`. `canonical: <host>`, optionnel et propre à une app (refusé dans `defaults`), redirige en 301 les autres hosts de l'app vers ce host, après le rate limit et Coraza (`WAF_CANONICAL_HOST`). La 301 porte `Cache-Control: max-age=86400`, pour qu'un navigateur l'oublie au bout d'un jour si le canonique est inversé.
  - `edge: cloudflare`, optionnel et propre à une app : `wafgen provision` pose `WAF_EDGE_SECRET` (référence à `EDGE_SECRET_<APP>`, variable d'équipe créée par ops, 32 caractères au moins dans `[A-Za-z0-9_-]`, par exemple `openssl rand -hex 32`) et `WAF_EDGE`, retenue tant que cette variable d'équipe n'est pas remplie pour que l'app reste déployable. Une Transform Rule de chaque zone Cloudflare qui porte un host proxifié de l'app pose ce secret dans `X-Ademe-Edge`, sur les seuls hosts de l'app (`http.host in {...}`) et jamais sur toute la zone, dont les autres origines recevraient le secret. Zone en SSL Full (strict), « Pseudo IPv4 » coupé pour que `CF-Connecting-IP` garde l'IPv6 du visiteur. Avec le secret, `CF-Connecting-IP` devient l'IP du visiteur pour le rate limit, Coraza, `/__waf/ip` et `X-Forwarded-For` ; sans lui, le WAF garde l'IP vue par Traefik. Aucun des deux en-têtes n'atteint l'origine, et `X-Ademe-Edge` est retiré des logs de Caddy.
  - `vms` : les VM WAF par nom, avec leur stage (`prod` ou `preprod`) et leur IP publique, celle que le firewall des apps autorise. `wafgen provision` ne traite que les apps du stage de `WAF_OPS_VM` et les nomme `waf-<app>-<vm>`. `stage: preprod`, optionnel et propre à une app (refusé dans `defaults`), la place sur les VM de preprod. Une app de même nom sur une autre VM est un jumeau : ses domaines sont repris avec `force_domain_override`, que Coolify exige pour un domaine déjà porté dans l'équipe. `WAF_OPS_BASE_REF={{server.WAF_BASE}}` donne à chaque VM sa base, par une variable partagée de serveur que `provision` vérifie.
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
