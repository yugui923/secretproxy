# Secret Proxy v1 — Implementation Plan

> Created 2026-05-09. Implements the v1 design at `docs/specs/2026-05-08-secret-proxy.md`.

## Layout

```
cmd/secret-proxy/main.go      CLI dispatch + serve/seal/unseal/request/gen-tls-cert
internal/seal/seal.go         Sealed-secret type, marshal validation, NaCl box ops
internal/seal/seal_test.go    Round-trip + validation unit tests
internal/proxy/proxy.go       HTTP handler, validators, processor, egress guard
internal/proxy/proxy_test.go  Handler unit tests
internal/proxy/tlscert.go     gen-tls-cert helper (Ed25519 self-signed)
internal/proxy/integration_test.go  End-to-end (proxy + httptest upstream)
pkg/client/client.go          NewTransport + options
pkg/client/client_test.go     Client transport unit tests
go.mod / go.sum
```

Target: ~800–1000 LOC of source + ~500 LOC of tests.

## Build sequence

1. `go mod init github.com/yugui923/secretproxy`
2. Pin deps: `golang.org/x/crypto`. Stdlib only beyond that.
3. `internal/seal` first — pure data; everything else depends on it.
4. `internal/proxy` — handler, validators, egress guard, processor.
5. `internal/proxy/tlscert.go` — Ed25519 self-signed gen for dev.
6. `pkg/client` — RoundTripper that injects headers and rewrites `https://` → `http://`.
7. `cmd/secret-proxy` — main entry + subcommands.
8. Tests, then integration tests.
9. `go build ./...` clean; `go test ./...` clean; `go vet ./...` clean.

## Component contracts

### `internal/seal`

```go
type Secret struct {
    BearerAuth   *BearerAuth   `json:"bearer_auth,omitempty"`
    NoAuth       *struct{}     `json:"no_auth,omitempty"`
    InjectHeader *InjectHeader `json:"inject_header,omitempty"`

    AllowedHosts        []string `json:"allowed_hosts,omitempty"`
    AllowedHostPattern  string   `json:"allowed_host_pattern,omitempty"`
    AllowedPathPrefixes []string `json:"allowed_path_prefixes,omitempty"`
    AllowedPathPattern  string   `json:"allowed_path_pattern,omitempty"`
    AllowedMethods      []string `json:"allowed_methods,omitempty"`
}

type BearerAuth struct { Digest string `json:"digest"` }
type InjectHeader struct {
    Token              string   `json:"token"`
    Format             string   `json:"format,omitempty"`
    HeaderName         string   `json:"header_name,omitempty"`
    AllowedFormats     []string `json:"allowed_formats,omitempty"`
    AllowedHeaderNames []string `json:"allowed_header_names,omitempty"`
}

func (s *Secret) Validate() error           // exactly-one auth, exactly-one processor, no both-fields
func Seal(s *Secret, pub *[32]byte) (string, error)
func Open(blob string, priv *[32]byte) (*Secret, error)
func KeypairFromHex(hex32 string) (*[32]byte, *[32]byte, error)
func GenerateKeypair() (*[32]byte, *[32]byte, error)
```

`MarshalJSON` enforces the redaction invariant: token/digest/key fields always serialize to `"REDACTED"` for log paths; the seal path uses a dedicated wire-marshal that bypasses redaction.

### `internal/proxy`

```go
type Server struct {
    PrivateKey         *[32]byte
    PreviousPrivateKey *[32]byte // optional, dual-key rotation
    AllowNoAuth        bool
    AllowPassthrough   bool
    FilteredHeaders    []string
    SelfHostnames      map[string]struct{} // pre-resolved IP set + hostnames
    Logger             *slog.Logger
}

func (s *Server) Handler() http.Handler  // /public-key, /healthz, /readyz + forward proxy
```

Handler flow per request:
1. If `host == /public-key|/healthz|/readyz` → serve.
2. Else expect absolute-form URL with `Proxy-Secret` + (`Proxy-Authorization` if bearer).
3. Open seal (try primary key, fall back to previous if set).
4. Validate `bearer_auth` digest (constant-time).
5. Apply request-time JSON overrides (only `format`/`header_name`, only within allowed sets).
6. Validate host / path / method against seal.
7. Egress guard: refuse RFC 1918, loopback, link-local, self.
8. Rewrite scheme `https→http→https` (target hop is always TLS to upstream after rewrite).

Wait — step 8 is wrong. Re-reading the spec: target stays `http://` from the client; proxy must dial upstream over TLS. So actual flow:

8. Strip `Proxy-Secret`, `Proxy-Authorization`, hop-by-hop, and filtered headers.
9. Run processor (`inject_header`): set `Authorization` (or configured) header on outbound.
10. Rewrite request URL scheme to `https://` (proxy → upstream is forced TLS).
11. Forward via `httputil.ReverseProxy`-style transport. Stream response back unchanged.

### `internal/proxy/tlscert.go`

```go
func GenerateSelfSignedTLS(outDir string, extraSANs []string) (certPath, keyPath string, err error)
```

Ed25519 keypair, x509 self-signed, 90-day validity, SANs `localhost` + `127.0.0.1` + `::1` + extras. Writes `cert.pem`, `key.pem` with `0600` on key.

### `pkg/client`

```go
type Option func(*transport)

func NewTransport(proxyURL string, opts ...Option) http.RoundTripper
func WithSealedSecret(blob string) Option
func WithAuth(token string) Option
func WithProxyTLS(cfg *tls.Config) Option
```

Transport wraps `*http.Transport`. RoundTrip clones the request, rewrites `https://target` → `http://target`, sets the two proxy headers, and delegates. Proxy URL drives TLS to the proxy via `http.ProxyURL`.

### `cmd/secret-proxy`

Subcommands via simple flag.Parse switch on os.Args[1]:

- `serve` — load private key + TLS, build `Server`, `http.ListenAndServeTLS`.
- `seal` — read all flags, build `Secret`, `Validate()`, `Seal()`, print blob.
- `unseal` — open and pretty-print (debug; redaction off).
- `request` — `pkg/client` driving a one-shot request; `--proxy-insecure` flips TLS verify off.
- `gen-tls-cert` — wraps `tlscert.GenerateSelfSignedTLS`.

## Test plan

### Unit (`go test ./internal/...`)

- `seal_test.go`:
  - Validate: rejects multiple auth tags, multiple processor tags, both host fields, both path fields, missing host, unknown tag.
  - Round-trip: seal → open recovers original.
  - Tampered ciphertext rejected.
  - Wrong key rejected.

- `proxy_test.go`:
  - Bearer digest mismatch → 401.
  - Allowed-hosts exact + pattern.
  - Allowed-path-prefix segment-aware (`/v1/charges` matches `/v1/charges/abc` but not `/v1/charges-list`).
  - Allowed-method case-sensitive uppercase.
  - Egress guard rejects RFC 1918 / loopback / link-local / self.
  - `inject_header` writes the right value; `Proxy-*` and hop-by-hop headers stripped.
  - Runtime overrides honored only within allowed sets.

- `client_test.go`:
  - Request through transport sets both proxy headers.
  - Target `https://` rewritten to `http://`.

### Integration (`go test ./internal/proxy -tags=integration -run Integration`)

Single integration test process spins up:
1. An `httptest.NewTLSServer` upstream that asserts on the injected header + body.
2. The proxy server with a self-signed TLS cert (generated via `tlscert.GenerateSelfSignedTLS`).
3. A client (via `pkg/client`) that sends a sealed request through the proxy to the upstream.

Cases:
- Happy path: sealed Stripe-like secret → upstream sees `Authorization: Bearer sk_live_xxx`.
- Wrong host: proxy returns 403.
- Wrong method: proxy returns 403.
- Dual-key rotation: seal under new key, both old and new keys loaded — request succeeds via fallback after the test re-seals against new key.

## Acceptance

- `go build ./...` exits 0.
- `go vet ./...` exits 0.
- `go test ./...` exits 0 with all tests passing.
- `go test ./... -tags=integration` exits 0.
- `gofmt -l .` produces no output.

Stop when the above are green. Do not commit.
