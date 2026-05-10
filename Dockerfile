# syntax=docker/dockerfile:1.7
# Multi-stage build per spec §4.4: Go build stage, then alpine:3 with ca-certificates.
#
# Both base images are pinned by sha256 digest in addition to the floating tag.
# The tag is kept for grep-ability and for tooling that wants the human-friendly
# name; the digest is what Docker actually fetches.
#
# To bump (no Docker needed; pin must point at a multi-arch INDEX, not a
# single-arch manifest):
#
#   TOKEN=$(curl -sL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" | jq -r .token)
#   curl -s -D - -o /dev/null \
#     -H "Authorization: Bearer $TOKEN" \
#     -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
#     "https://registry-1.docker.io/v2/library/alpine/manifests/3"
#
# Verify the response headers include Content-Type: application/vnd.oci.image.index.v1+json
# (or the legacy manifest.list.v2+json); single-arch manifest.v2+json means the
# pin would lock the image to one architecture. Then copy the
# Docker-Content-Digest value into the @sha256: slot below.
#
# Resolved 2026-05-10.

FROM golang:1.25-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secret-proxy ./cmd/secret-proxy

FROM alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates
COPY --from=build /out/secret-proxy /usr/local/bin/secret-proxy
USER nobody
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/secret-proxy"]
CMD ["serve"]
