FROM golang:1.27-alpine3.24@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY cmd/ cmd/
COPY internal/ internal/
# inspectFile lance un binaire, rbl une requête DNS : retirés de Coraza à la compilation.
ARG CORAZA_TAGS=coraza.disabled_operators.inspectFile,coraza.disabled_operators.rbl
RUN CGO_ENABLED=0 go build -trimpath -tags "$CORAZA_TAGS" -ldflags="-s -w" -o /out/caddy . \
 && CGO_ENABLED=0 go build -trimpath -tags "$CORAZA_TAGS" -ldflags="-s -w" -o /out/wafgen ./cmd/wafgen

FROM build AS crs
COPY crs/ crs/
RUN V=$(cat crs/VERSION) \
 && wget -q -O /tmp/crs.tgz "https://github.com/coreruleset/coreruleset/releases/download/v$V/coreruleset-$V-minimal.tar.gz" \
 && (cd /tmp && sha256sum -c /src/crs/SHA256SUMS) \
 && mkdir -p /out/crs && tar -xzf /tmp/crs.tgz -C /out/crs --strip-components=1

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates tini \
 && adduser -D -H -u 10001 caddy \
 && install -d -o caddy /var/lib/waf
COPY --from=build /out/caddy /out/wafgen /usr/bin/
COPY --from=crs /out/crs /etc/waf/crs
COPY caddy/ /etc/waf/caddy/
COPY coraza/ /etc/waf/coraza/
COPY plugins/ /etc/waf/plugins/
COPY policy/ /etc/waf/policy/
RUN (cd /etc/waf/coraza && sha256sum -c SHA256SUMS) \
 && /usr/bin/caddy adapt --config /etc/waf/caddy/Caddyfile > /etc/waf/caddy/base.json
ARG SOURCE_COMMIT=dev
ENV WAF_BASE_VERSION=${SOURCE_COMMIT} XDG_CONFIG_HOME=/tmp XDG_DATA_HOME=/tmp
USER caddy
EXPOSE 8080 2020
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s \
  CMD wget -qO- http://127.0.0.1:2020/healthz >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/wafgen", "run", "--etc", "/etc/waf"]
# Exécutés au build de chaque app, juste après son FROM, avec waf/ pour contexte.
ONBUILD ARG WAF_BASE
ONBUILD ENV WAF_BASE_REF=${WAF_BASE}
ONBUILD COPY . /etc/waf/tenant/
ONBUILD RUN ["/usr/bin/wafgen", "check", "--etc", "/etc/waf"]
