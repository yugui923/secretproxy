# syntax=docker/dockerfile:1.7
# Multi-stage build per spec §4.4: Go build stage, then alpine:3 with ca-certificates.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secret-proxy ./cmd/secret-proxy

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /out/secret-proxy /usr/local/bin/secret-proxy
USER nobody
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/secret-proxy"]
CMD ["serve"]
