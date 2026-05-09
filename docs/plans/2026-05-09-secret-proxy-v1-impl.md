# Secret Proxy v1 — Implementation Plan

> Created 2026-05-09. Implements the v1 design at `docs/specs/2026-05-08-secret-proxy.md`.
>
> Wire protocol: relative-URL endpoint (`POST /v1/forward`) with `X-Upstream-URL` / `X-Sealed-Secret` / `X-Auth-Bearer` headers. Chosen over absolute-form `HTTP_PROXY` semantics so the proxy traverses reverse-proxy CDNs (Render, Cloud Run, Heroku, App Runner). See spec §3.1.

## Layout

```
cmd/secret-proxy/main.go      CLI dispatch + serve / seal / unseal / request / gen-tls-cert / gen-keypair
internal/seal/seal.go         Sealed-secret type, marshal validation, NaCl box ops, typed PrivateKey/PublicKey
internal/seal/seal_test.go    Round-trip + validation unit tests
internal/proxy/proxy.go       /v1/forward handler, validators, processor, egress guard
internal/proxy/proxy_test.go  Handler unit tests
internal/proxy/tlscert.go     gen-tls-cert helper (Ed25519 self-signed, dev only)
internal/proxy/integration_test.go  End-to-end (proxy + httptest upstream + pkg/client)
pkg/client/client.go          NewTransport + options (drives the v1 wire envelope)
pkg/client/client_test.go     Client transport unit tests
go.mod / go.sum
Dockerfile                    Multi-stage Alpine build (per spec §4.4)
render.yaml                   Render Blueprint (uses TRUST_TLS_TERMINATOR)
.env.production.example       Generic env template for K8s / Fargate / VPS
CLAUDE.md                     Repo-specific agent instructions (no-URLs rule)
```

Target: ~1100 LOC of source + ~1000 LOC of tests.

## Build sequence

1. `go mod init github.com/yugui923/secretproxy` — done (`go 1.25` floor pulled by `golang.org/x/crypto`).
2. Pin third-party: `golang.org/x/crypto`. Stdlib only beyond that.
3. `internal/seal` first — types are used everywhere downstream.
4. `internal/proxy` — `/v1/forward` handler, validators, egress guard, processor.
5. `internal/proxy/tlscert.go` — Ed25519 self-signed cert generator for dev.
6. `pkg/client` — `RoundTripper` that POSTs to `proxyURL/v1/forward` with control headers.
7. `cmd/secret-proxy` — main entry + subcommands.
8. Tests, then integration tests (over a real TLS proxy listener + httptest upstream).
9. `go build ./...` clean; `go vet ./...` clean; `go test ./...` (and `-race`) clean; `gofmt -l .` empty.

## Component contracts

### `internal/seal`

```go
type PrivateKey [32]byte
type PublicKey  [32]byte

func GenerateKeypair() (PublicKey, PrivateKey, error)
func ParsePrivateKey(hex string) (PrivateKey, error)
func ParsePublicKey(hex string) (PublicKey, error)
func ReadPrivateKeyFile(path string) (PrivateKey, error)
func (priv PrivateKey) Public() PublicKey
func (k PrivateKey) Hex() string
func (k PublicKey)  Hex() string

type Secret struct {
    BearerAuth   *BearerAuth   `json:"bearer_auth,omitempty"`
    NoAuth       *NoAuth       `json:"no_auth,omitempty"`
    InjectHeader *InjectHeader `json:"inject_header,omitempty"`

    AllowedHosts        []string `json:"allowed_hosts,omitempty"`
    AllowedHostPattern  string   `json:"allowed_host_pattern,omitempty"`
    AllowedPathPrefixes []string `json:"allowed_path_prefixes,omitempty"`
    AllowedPathPattern  string   `json:"allowed_path_pattern,omitempty"`
    AllowedMethods      []string `json:"allowed_methods,omitempty"`
}

func (s *Secret) Validate() error
func Seal(s *Secret, pub PublicKey) (string, error)
func Open(blob string, priv PrivateKey, fallback ...PrivateKey) (*Secret, usedFallback bool, error)
```

`Open` rejects unknown JSON fields (per §2.2) and signals which key opened the seal so operators can observe rotation drain. `Secret.LogValue` returns a redacted view for `slog`.

### `internal/proxy`

```go
type Server struct {
    PrivateKey         *seal.PrivateKey
    PreviousPrivateKey *seal.PrivateKey   // optional, dual-key rotation
    AllowNoAuth        bool
    AllowPassthrough   bool
    FilteredHeaders    []string
    SelfHostnames      map[string]struct{}
    Logger             *slog.Logger
    Transport          http.RoundTripper  // test override
    DisableEgressGuard bool                // test override
}

func (s *Server) Handler() http.Handler
```

Handler flow per request:

1. Dispatch by `r.URL.Path`: `/healthz`, `/readyz` → 200; `/public-key` → hex public key; `/v1/forward` → handleForward; else 404.
2. `handleForward`:
   1. Parse `X-Upstream-URL` → URL object.
   2. Reject multiple `X-Sealed-Secret` headers.
   3. Read sealed blob (with optional `; <json-override>` suffix).
   4. `seal.Open` against primary key, fallback to previous if set; emit `seal_opened_via_previous_key` warn on fallback success.
   5. Verify `X-Auth-Bearer` against the seal's digest (constant-time, decodes Basic password half).
   6. Apply runtime override (only `format` / `header_name`, only within `allowed_formats` / `allowed_header_names`; never mutates the decrypted secret).
   7. Reject non-443 ports on the upstream URL (per-host passthrough is deferred).
   8. Validate upstream host / path / method against the seal's allowlists.
   9. Build outbound request via `httputil.ReverseProxy.Director`: scheme→`https`, port→443, strip control + hop-by-hop + filtered headers, inject configured header.
   10. Forward via guarded transport. `guardedDial` blocks RFC 1918 / loopback / link-local / self before dialing, and dials by resolved IP to defeat DNS-rebinding TOCTOU.
   11. Stream response back; access log captures real upstream status via a `statusWriter` wrapper.

### `internal/proxy/tlscert.go`

```go
func GenerateSelfSignedTLS(outDir string, extraSANs []string) (certPath, keyPath string, err error)
```

Ed25519 keypair, x509 self-signed, 90-day validity, SANs `localhost` + `127.0.0.1` + `::1` + extras. Writes `cert.pem` (0644) and `key.pem` (0600).

### `pkg/client`

```go
type Option func(*transport)

func NewTransport(proxyURL string, opts ...Option) (http.RoundTripper, error)
func WithSealedSecret(blob string) Option
func WithAuth(token string) Option
func WithProxyTLS(cfg *tls.Config) Option
```

`RoundTrip` clones the request, retargets it at `proxyURL/v1/forward`, copies the original URL into `X-Upstream-URL`, and adds `X-Sealed-Secret` + `X-Auth-Bearer`. Method, body, and remaining headers pass through.

### `cmd/secret-proxy`

Subcommands:

- `serve` — load private key (file or env), TLS material (file mount, or skip if `--trust-tls-terminator`), build `Server`, listen via `ListenAndServeTLS` or `ListenAndServe`. Honors `$PORT` for PaaS deployments. Drains the listener goroutine on shutdown so listener errors aren't lost.
- `seal` — build `Secret`, `Validate()`, `Seal()`, print blob. Public key resolved from `--public-key`, `--public-key-url` (https-only, status-checked), or `SECRET_PROXY_PUBLIC_KEY` env.
- `unseal` — debug; reads private key per §4.1, sealed secret from `--token` or stdin, prints JSON.
- `request` — wraps `pkg/client` for one-shot test requests. `--proxy-insecure` skips proxy TLS verification (dev only).
- `gen-tls-cert` — wraps `tlscert.GenerateSelfSignedTLS`.
- `gen-keypair` — generates a Curve25519 keypair, prints `private:` and `public:` hex to stdout.

## Test plan

### Unit (`go test ./internal/... ./pkg/...`)

- `seal_test.go`:
  - `Validate` rejects: missing/multi auth, missing/multi processor, both host fields, both path fields, missing host, missing token/digest.
  - Round-trip: `Seal` → `Open` recovers the original `Secret`.
  - Tampered ciphertext rejected; wrong key rejected; fallback key opens (and `usedFallback=true`).
  - `Open` rejects unknown JSON fields.
  - `VerifyBearer` is constant-time, decodes its digest before compare; malformed digest fails closed.
  - Hex parsers: length and validity errors.
- `proxy_test.go`:
  - Header parsing: `parseSealedHeader`, `extractBearer` (Bearer + Basic with password half).
  - Override resolution: accepted, rejected (outside allowed list), already-set, unknown key. **Does not mutate** the seal.
  - Validators: host (exact + pattern), path (segment-aware prefix), method (case-sensitive).
  - `rejectNonStandardPort` blocks anything that isn't `:443`.
  - `isPrivateOrLocal` covers RFC 1918 / loopback / link-local / IPv6 `::1`.
  - `guardedDial` blocks loopback, blocks self-loop hostnames.
  - `statusWriter` captures the first `WriteHeader`, defaults to 200 on bare `Write`.
  - `/healthz`, `/readyz`, `/public-key` handlers.
  - Unknown paths return 404.
- `client_test.go`:
  - `NewTransport` rejects non-http/https proxy URLs.
  - `RoundTrip` retargets to `/v1/forward`, sets the three control headers, mirrors method.

### Integration (`internal/proxy/integration_test.go`)

Single test file spins up:

1. `httptest.NewTLSServer` upstream that records the request it receives.
2. The proxy in TLS mode with a self-signed cert (`gen-tls-cert`).
3. A test transport on the proxy's `Server.Transport` that hijacks all dials to the test upstream's address (so the real egress guard stays enabled in unit tests).
4. A client built via `pkg/client` driving requests through the proxy.

Cases:

- Happy path: upstream sees `Authorization: Bearer <unsealed token>`, no control headers leaked.
- Wrong host → 403.
- Wrong method → 403.
- Wrong bearer → 401.
- Dual-key rotation: seal under old key, both keys loaded — fallback opens, request succeeds, upstream sees the injected credential.
- No seal + no passthrough → 400.
- Passthrough mode: forwards without injection.
- Multiple `X-Sealed-Secret` headers → 400.
- Non-443 port in `X-Upstream-URL` → 403.
- Behind-terminator deployment: plaintext listener, same handler — covered by spinning the proxy on a plain `http.Server`.

## Acceptance

- `go build ./...` exits 0.
- `go vet ./...` exits 0.
- `go test ./...` and `go test -race ./...` exit 0.
- `gofmt -l .` produces no output.
- `secret-proxy gen-keypair | secret-proxy seal | secret-proxy unseal` round-trips end-to-end via the binary.
- A live deployment behind a reverse-proxy CDN (Render Web Service) returns 200 on `/healthz`, the published public key on `/public-key`, and successfully forwards a sealed request through to a public upstream.

Stop when the above are green.
