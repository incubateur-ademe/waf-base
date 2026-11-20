# Image du conteneur waf-ops d'outils : boucle des contrôles (wafgen ops), wafgen provision à la demande.
# Contexte de build : racine du repo, docker build -f ops/Dockerfile .
FROM golang:1.27-alpine3.24@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
ARG CORAZA_TAGS=coraza.disabled_operators.inspectFile,coraza.disabled_operators.rbl
RUN CGO_ENABLED=0 go build -trimpath -tags "$CORAZA_TAGS" -ldflags="-s -w" -o /out/wafgen ./cmd/wafgen

# gh 2.103.3 au moins : les versions antérieures comparent --signer-workflow par préfixe.
# Somme tirée de gh_<version>_checksums.txt de la release.
FROM build AS gh
ARG GH_VERSION=2.104.0
ARG GH_SHA256=98cb101ad87dbbd3f6b2f2bfcbd43197ccd07643140121d8a9cfaa91eadbc24e
RUN wget -q -O /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
 && echo "${GH_SHA256}  /tmp/gh.tgz" | sha256sum -c - \
 && mkdir -p /out && tar -xzf /tmp/gh.tgz -C /tmp \
 && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /out/gh

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates tini \
 && adduser -D -H -u 10001 -h /var/lib/waf-ops waf-ops \
 && install -d -o waf-ops -m 0700 /var/lib/waf-ops
COPY --from=build /out/wafgen /usr/bin/wafgen
COPY --from=gh /out/gh /usr/bin/gh
COPY policy/ /etc/waf/policy/
ENV HOME=/var/lib/waf-ops GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1
VOLUME /var/lib/waf-ops
USER waf-ops
WORKDIR /var/lib/waf-ops
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/bin/wafgen", "ops"]
