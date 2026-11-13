#!/bin/sh
# Test de bout en bout local : Traefik -> WAF d'un tenant -> origine HTTPS factice.
# Usage : tests/e2e/run.sh <image de base>   (ex. waf-base:local)
set -eu

BASE=${1:?image de base}
TRAEFIK=${TRAEFIK_IMAGE:-traefik:v3.7@sha256:c1ea95f3b3eab04ba8868d201b8494e12284e424f7cec2127e3194bca1c6641c}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d)
NET=waf-e2e-$$
FAILS=0

cleanup() {
	docker rm -f "$NET-origin" "$NET-waf" "$NET-traefik" "$NET-force" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { printf 'OK    %s\n' "$1"; }
ko() { printf 'ÉCHEC %s : %s\n' "$1" "$2"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1" "attendu « $3 », obtenu « $2 »"; fi; }

ORIGIN_HOST=fake.osc-fr1.scalingo.io

# CA et certificat de test pour l'origine factice
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=waf-e2e-ca" \
	-keyout "$WORK/ca.key" -out "$WORK/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$ORIGIN_HOST" \
	-keyout "$WORK/origin.key" -out "$WORK/origin.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$ORIGIN_HOST" >"$WORK/san.ext"
openssl x509 -req -in "$WORK/origin.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
	-days 1 -extfile "$WORK/san.ext" -out "$WORK/origin.pem" >/dev/null 2>&1
cat >"$WORK/origin.caddy" <<EOF
{
	admin off
	auto_https off
}
https://:443 {
	tls /e2e/origin.pem /e2e/origin.key
	respond "host={host} xff={header.X-Forwarded-For} xfp={header.X-Forwarded-Proto} uri={uri}" 200
}
EOF
# Sous Linux, le conteneur WAF tourne en uid 10001 : le dossier de test doit lui être traversable.
chmod -R a+rX "$WORK"

docker network create "$NET" >/dev/null
docker run -d --name "$NET-origin" --network "$NET" --network-alias "$ORIGIN_HOST" --user root \
	-v "$WORK:/e2e:ro" --entrypoint /usr/bin/caddy "$BASE" run --config /e2e/origin.caddy --adapter caddyfile >/dev/null

# Build du tenant comme Coolify : contexte waf/, WAF_BASE en --build-arg.
docker build -q --build-arg WAF_BASE="$BASE" -t "$NET-tenant" "$ROOT/tests/exemple-tacct" >/dev/null
ok "build du waf/Dockerfile à deux lignes"

docker run -d --name "$NET-waf" --network "$NET" --memory 512m \
	-e WAF_TENANT=tacct -e WAF_HOSTS=tacct.example.org,www.tacct.example.org,facili-tacct.example.org,www.facili-tacct.example.org \
	-e UPSTREAM="https://$ORIGIN_HOST" -e WAF_PLATFORM=scalingo -e WAF_HOST_HEADER=visitor \
	-e SSL_CERT_FILE=/e2e/ca.pem -v "$WORK:/e2e:ro" -p 127.0.0.1::2020 "$NET-tenant" >/dev/null

cat >"$WORK/dyn.yaml" <<EOF
http:
  routers:
    waf:
      rule: "Host(\`tacct.example.org\`) || Host(\`www.tacct.example.org\`)"
      entryPoints: [http]
      service: waf
    waf-tls:
      rule: "Host(\`tacct.example.org\`) || Host(\`www.tacct.example.org\`)"
      entryPoints: [https]
      service: waf
      tls: {}
  services:
    waf:
      loadBalancer:
        servers:
          - url: "http://$NET-waf:8080"
EOF
docker run -d --name "$NET-traefik" --network "$NET" -v "$WORK:/e2e:ro" -p 127.0.0.1::80 -p 127.0.0.1::443 "$TRAEFIK" \
	--entrypoints.http.address=:80 --entrypoints.https.address=:443 --providers.file.filename=/e2e/dyn.yaml >/dev/null

P80=$(docker port "$NET-traefik" 80/tcp | head -1 | sed 's/.*://')
P443=$(docker port "$NET-traefik" 443/tcp | head -1 | sed 's/.*://')
P2020=$(docker port "$NET-waf" 2020/tcp | head -1 | sed 's/.*://')

i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2020/healthz")" = 200 ]; do
	i=$((i + 1))
	if [ $i -gt 120 ]; then
		docker logs "$NET-waf" 2>&1 | grep -v '^{"transaction"' | tail -30
		ko "démarrage" "healthz jamais à 200"
		exit 1
	fi
	sleep 0.5
done
ok "démarrage : healthz à 200 après l'attaque canonique ($i demi-secondes)"
docker logs "$NET-waf" 2>&1 | grep -E 'wafgen: (attaque|origine|GOMEMLIMIT|tenant)' | sed 's/^/      /'

# Traefik termine le TLS comme sur waf-1 en v1 ; le SNI porte le host.
H=tacct.example.org
T="https://$H:$P443"
c() { curl -sk --resolve "$H:$P443:127.0.0.1" "$@"; }
i=0
until [ "$(c -o /dev/null -w '%{http_code}' "$T/")" = 200 ]; do
	i=$((i + 1))
	[ $i -gt 60 ] && { ko "routage Traefik" "pas de 200 sur $T/"; exit 1; }
	sleep 0.5
done
body=$(c "$T/")
case "$body" in "host=tacct.example.org "*) ok "Host du visiteur transmis à l'origine";; *) ko "Host transmis" "$body";; esac
case "$body" in *"xfp=https "*) ok "X-Forwarded-Proto forcé à https";; *) ko "X-Forwarded-Proto" "$body";; esac

ip=$(c "$T/__waf/ip")
forged=$(c -H 'X-Forwarded-For: 1.2.3.4' "$T/__waf/ip")
check "{client_ip} inchangé par un X-Forwarded-For forgé ($ip)" "$forged" "$ip"
[ "$forged" != "1.2.3.4" ] && ok "X-Forwarded-For forgé ignoré" || ko "XFF forgé" "1.2.3.4 pris pour l'IP client"
body=$(c -H 'X-Forwarded-For: 1.2.3.4' "$T/")
case "$body" in *"xff=$ip xfp"*) ok "X-Forwarded-For vers l'origine = {client_ip}";; *) ko "XFF vers l'origine" "$body";; esac

check "attaque XSS en query bloquée" "$(c -o /dev/null -w '%{http_code}' "$T/?q=%3Cscript%3Ealert(1)%3C/script%3E")" 403
trav=$(c --path-as-is "$T/a/%2e%2e/b")
case "$trav" in *"uri=/b"*) ok "traversée %2e%2e nettoyée par Traefik avant le WAF ($trav)";; *) check "traversée %2e%2e via Traefik" "$trav" "403";; esac
for p in '/a/%2e%2e/b' '/a/../b' '/a/./b' '/a/%2E%2e/admin' '/a/..;/admin' '/a/..%5Cadmin' '/a/%2e%2e;/admin'; do
	code=$(docker exec "$NET-waf" wget -S -qO- --header "Host: $H" --header 'X-Forwarded-Proto: https' "http://127.0.0.1:8080$p" 2>&1 | grep -o 'HTTP/1.1 [0-9]*' | head -1)
	check "traversée $p en direct sur Caddy : 403 (10050)" "$code" "HTTP/1.1 403"
done
check ".well-known non gêné par 10050" "$(docker exec "$NET-waf" wget -S -qO- --header "Host: $H" --header 'X-Forwarded-Proto: https' "http://127.0.0.1:8080/.well-known/security.txt" 2>&1 | grep -o 'HTTP/1.1 [0-9]*' | head -1)" "HTTP/1.1 200"
python3 -c 'import json; print(json.dumps({"q": "<script>alert(1)</script>" * 20000}))' >"$WORK/big.json"
check "gros corps d'attaque (ligne d'audit de plusieurs Mio) bloqué" "$(c -m 20 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/big.json" "$T/")" 403
check "le WAF répond encore après une ligne d'audit géante" "$(c -m 10 -o /dev/null -w '%{http_code}' "$T/?q=%3Cscript%3Ealert(1)%3C/script%3E")" 403
check "méthode TRACE refusée" "$(c -o /dev/null -w '%{http_code}' -X TRACE "$T/")" 403
check "host inconnu : 421 du catch-all" "$(docker exec "$NET-waf" wget -S -qO- --header 'Host: autre.example.org' http://127.0.0.1:8080/ 2>&1 | grep -o 'HTTP/1.1 [0-9]*' | head -1)" "HTTP/1.1 421"

check "accès en clair par le port 80 : 301 de Caddy vers https" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $H" "http://127.0.0.1:$P80/x?y=1")" "301 https://$H/x?y=1"
hdr=$(c -I "$T/")
case "$hdr" in *"Server:"*) ko "en-tête Server retiré" "présent";; *) ok "en-tête Server retiré";; esac
case "$hdr" in *[Ss]trict-[Tt]ransport-[Ss]ecurity*) ok "HSTS posé";; *) ko "HSTS" "absent";; esac

codes=$(seq 1 80 | xargs -P 40 -I{} curl -sk --resolve "$H:$P443:127.0.0.1" -o /dev/null -w '%{http_code}\n' "$T/" | sort | uniq -c | tr '\n' ' ')
case "$codes" in *" 429"*) ok "rate limit défaut (40/s) : $codes";; *) ko "rate limit" "$codes";; esac
sleep 1.1
tiles=$(seq 1 80 | xargs -P 40 -I{} curl -sk --resolve "$H:$P443:127.0.0.1" -o /dev/null -w '%{http_code}\n' "$T/api/map-proxy" | sort | uniq -c | tr '\n' ' ')
case "$tiles" in *" 429"*) ko "zone tuiles (100/s)" "$tiles";; *) ok "zone tuiles à 100/s : $tiles";; esac

metrics=$(curl -s "http://127.0.0.1:$P2020/metrics")
if printf '%s' "$metrics" | grep -q 'key="'; then ko "métriques sans label key" "label key présent"; else ok "aucune série /metrics avec le label key"; fi
printf '%s' "$metrics" | grep -q 'caddy_http_request_duration_seconds_count{.*host="tacct.example.org"' && ok "métriques par host" || ko "métriques par host" "absentes"
mode=$(curl -s "http://127.0.0.1:$P2020/mode")
case "$mode" in *'mode="block"'*) ok "mode block publié sur :2020/mode";; *) ko "mode" "$mode";; esac
case "$mode" in *"base=\"$BASE\""*) ok "référence de base publiée sur :2020/mode ($BASE)";; *) ko "référence de base" "$mode";; esac
lim=$(docker logs "$NET-waf" 2>&1 | grep -o 'GOMEMLIMIT=[0-9]*' | head -1)
check "GOMEMLIMIT à 80 % de 512 Mio" "$lim" "GOMEMLIMIT=429496729"

# Arrêt : /healthz passe en 503 avant que Caddy ne s'arrête.
start=$(date +%s)
docker kill -s TERM "$NET-waf" >/dev/null
sleep 1
check "healthz en 503 pendant le drain" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2020/healthz")" 503
check "trafic encore servi pendant le drain" "$(c -o /dev/null -w '%{http_code}' "$T/")" 200
docker wait "$NET-waf" >/dev/null
dur=$(($(date +%s) - start))
[ "$dur" -ge 10 ] && ok "arrêt après le délai de drain (${dur} s)" || ko "drain" "arrêt en ${dur} s"

# Détection forcée : l'attaque passe, le mode le dit.
until=$(date -u -v+2H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)
docker run -d --name "$NET-force" --network "$NET" \
	-e WAF_TENANT=tacct -e WAF_HOSTS=tacct.example.org -e UPSTREAM="https://$ORIGIN_HOST" \
	-e WAF_FORCE_DETECTION="$until" -e SSL_CERT_FILE=/e2e/ca.pem -v "$WORK:/e2e:ro" "$NET-tenant" >/dev/null
i=0
until docker exec "$NET-force" wget -qO- http://127.0.0.1:2020/healthz >/dev/null 2>&1; do
	i=$((i + 1)); [ $i -gt 60 ] && break; sleep 0.5
done
code=$(docker exec "$NET-force" wget -S -qO- --header "Host: $H" --header 'X-Forwarded-Proto: https' "http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E" 2>&1 | grep -o 'HTTP/1.1 [0-9]*' | head -1)
check "détection forcée : XSS relayé à l'origine" "$code" "HTTP/1.1 200"
code=$(docker exec "$NET-force" wget -S -qO- --header "Host: $H" --header 'X-Forwarded-Proto: https' "http://127.0.0.1:8080/a/../b" 2>&1 | grep -o 'HTTP/1.1 [0-9]*' | head -1)
check "détection forcée : 10050 bloque toujours" "$code" "HTTP/1.1 403"
fmode=$(docker exec "$NET-force" wget -qO- http://127.0.0.1:2020/mode 2>/dev/null)
case "$fmode" in *'mode="force"'*) ok "mode force publié sur :2020/mode";; *) ko "mode force" "$fmode";; esac
docker rm -f "$NET-force" >/dev/null

# Refus au build et au démarrage
mkdir -p "$WORK/hostile/coraza"
cp "$ROOT/tests/exemple-tacct/Dockerfile" "$WORK/hostile/"
printf '# Retrait du blocage pour tester le verrou du build\nSecRuleRemoveById 949110\n' >"$WORK/hostile/coraza/after.conf"
if docker build -q --build-arg WAF_BASE="$BASE" "$WORK/hostile" >/dev/null 2>&1; then ko "build d'un waf/ hostile" "accepté"; else ok "build d'un waf/ hostile refusé"; fi
if docker build -q "$ROOT/tests/exemple-tacct" >/dev/null 2>&1; then ko "build sans WAF_BASE" "accepté"; else ok "build sans WAF_BASE refusé"; fi
if docker run --rm -e WAF_TENANT=tacct -e WAF_HOSTS=tacct.example.org -e 'UPSTREAM={{team.UPSTREAM_TACCT}}' "$NET-tenant" >/dev/null 2>&1; then ko "variable partagée introuvable" "démarrage accepté"; else ok "démarrage refusé sur une variable « {{ »"; fi
if docker run --rm -e WAF_TENANT=tacct -e WAF_HOSTS=tacct.example.org -e UPSTREAM=http://10.0.0.1 "$NET-tenant" >/dev/null 2>&1; then ko "origine hors liste blanche" "démarrage accepté"; else ok "démarrage refusé sur une origine hors liste blanche"; fi
docker image rm -f "$NET-tenant" >/dev/null 2>&1 || true

echo
if [ "$FAILS" -gt 0 ]; then
	echo "$FAILS échec(s)"
	exit 1
fi
echo "tous les contrôles passent"
