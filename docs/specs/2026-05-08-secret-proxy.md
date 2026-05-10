# Secret Proxy — Design Spec

> Draft v0. Last updated 2026-05-09. Prototype-stage — wire format may change without notice.

## 1. Concept

### 1.1 Overview

A stateless Go HTTP proxy that decrypts client-sealed credentials in-process and injects them into outbound requests to third-party APIs (Stripe, Twilio, OpenAI, etc.). The proxy holds a Curve25519 keypair; the public key is published, and operators seal credentials offline against it via a CLI. Sealed secrets travel on every request in a header. **No server-side credential store** — every request is independent.

**Request lifecycle.** The application sends a normal HTTP request to the proxy's `/v1/forward` endpoint. The method, body, and most headers mirror the upstream request; three control headers carry the proxy contract: `X-Upstream-URL` (the destination), `X-Sealed-Secret` (the base64 sealed envelope), `X-Auth-Bearer` (a bearer token whose digest is bound into the seal). The proxy verifies the bearer against the digest, unseals the envelope, checks the upstream URL's host/path and the request method against the sealed allowlists, injects the unsealed credential, strips the control headers, and forwards to the upstream over TLS. The response streams back unchanged.

This relative-URL envelope was chosen over an absolute-form `HTTP_PROXY`-style protocol because reverse-proxy CDNs (Cloudflare and friends, which front PaaS Web Services like Render and Cloud Run) reject absolute-form requests at the edge. A normal POST/GET to a relative path traverses any standard CDN.

### 1.2 Goals & Non-Goals

**Goals.** Keep vendor credentials out of application processes, env vars, and logs. ~500–1000 LOC of Go, single static binary. Reusable sealed credentials, scoped to a specific upstream host + bearer-token holder. Deployable on any platform that serves HTTP(S) — including reverse-proxy-fronted PaaS (Render, Cloud Run, Heroku, App Runner).

**Non-goals.** Credential rotation as a service. Webhook verification. Replay protection. OAuth refresh management. Multi-tenant UI / control plane. Transparent integration with vendor SDKs that use `HTTP_PROXY` env-var semantics — that path was considered during prototyping and dropped because absolute-form HTTP doesn't traverse reverse-proxy CDNs (see §3.1).

### 1.3 Threat Model

Rows ordered by mitigation status (Yes → Partial → No):

| Attacker                                     | Mitigated? | How                                                                                                                                                                                                                        |
| -------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reads sealed secrets at rest (config, git)   | Yes        | Useless without the proxy private key.                                                                                                                                                                                     |
| Network observer (client → proxy)            | Yes        | TLS 1.3 server-authenticated, either by the proxy itself or by an upstream TLS terminator (§3.2).                                                                                                                          |
| Network observer (proxy → upstream)          | Yes        | Forced TLS, system trust store.                                                                                                                                                                                            |
| Operator with log access                     | Yes        | The proxy never logs the unmarshaled `Secret` as a whole; only the `seal_euid` / `seal_name` / `auth` / `processor` fields surface, via `Secret.LogValue`. Tokens, digests, and the sealed blob never appear in log lines. |
| Steals sealed secret + replays from new host | Partial    | `bearer_auth` digest also requires the matching plaintext token.                                                                                                                                                           |
| Steals both sealed secret and bearer token   | Partial    | `allowed_hosts` (+ optional `allowed_path_prefixes` / `allowed_methods`) blocks redirect to attacker-controlled hosts; narrows but does not eliminate abuse via legitimate-shaped requests.                                |
| Crafts upstream URL with `..` path traversal | Yes        | `validatePath` refuses any decoded path containing a `.` or `..` segment before consulting the allowlist; `url.Parse` decodes `%2e%2e` to `..` in `Path` so the guard catches the percent-encoded variant too.             |
| Operator with proxy host access              | Partial    | Plaintext credentials exist transiently in-process; standard host hardening applies.                                                                                                                                       |
| Compromises proxy host                       | No         | Curve25519 + TLS private keys in memory; rotate both to recover.                                                                                                                                                           |

## 2. Sealed Secret

### 2.1 Cryptographic Design

NaCl sealed box (`golang.org/x/crypto/nacl/box`) — Curve25519 + XSalsa20-Poly1305, anonymous sender. Per-message ephemeral sender keys provide forward secrecy.

- **Private key** (`SECRET_PROXY_PRIVATE_KEY`): 32 random bytes hex-encoded; held only by the proxy.
- **Public key** (`SECRET_PROXY_PUBLIC_KEY`): derived via `curve25519.ScalarBaseMult`; served at `GET /public-key` as `text/plain` hex.
- **Sealed-secret wire format**: `base64.StdEncoding(box.SealAnonymous(JSON(secret)))`.

### 2.2 Format

```jsonc
{
  "bearer_auth": { "digest": "<base64(sha256(token))>" }, // exactly one auth tag
  "inject_header": {
    // exactly one processor tag
    "token": "sk_live_xxx",
    "format": "Bearer %s",
    "header_name": "Authorization",
    "allowed_formats": ["Bearer %s"],
    "allowed_header_names": ["Authorization"],
  },
  "allowed_hosts": ["api.stripe.com"], // required: host or host_pattern
  "allowed_path_prefixes": ["/v1/charges", "/v1/refunds"], // optional: prefix or pattern
  "allowed_methods": ["POST"], // optional
  "name": "stripe-prod-charges", // optional human label, surfaced in logs
  "euid": "f47ac10b-58cc-4372-a567-0e02b2c3d479", // UUIDv4, auto-stamped by Seal() when empty
}
```

Marshaling rejects: more than one auth tag, more than one processor tag, both host fields, both path fields, unknown tags.

`name` and `euid` are observability-only — they participate in no validation or
authorization decisions. `euid` is generated with `crypto/rand` UUIDv4 at seal
time (or accepted from `--euid` for tests/imports); the proxy logs both on every
request so an operator can correlate upstream calls back to a sealed credential
without ever logging the secret itself.

### 2.3 Authorizers

- **`bearer_auth`** — sealed `digest = sha256(token)`. Client sends `X-Auth-Bearer: Bearer <token>` (or `Basic …`; password half is compared). Constant-time compare.
- **`no_auth`** — disables proxy-side auth. Refused unless server has `--allow-no-auth`.

Macaroon-based authorization and platform-issued machine-identity tokens deferred (additive, no wire-format break).

### 2.4 Processors

**`inject_header`** (only processor at v1):

- `token`, `format` (default `"Bearer %s"`), `header_name` (default `"Authorization"`).
- Computes `fmt.Sprintf(format, token)`, sets `request.Header[header_name]`.

HTTP Basic at v1: pre-encode `user:pass` with base64 at seal time and store as `token` with `format = "Basic %s"`. A dedicated `inject_basic_auth` processor is deferred — pre-encoding keeps the processor surface single-purpose.

Deferred (wire-compatible additive changes): `inject_hmac`, `inject_body`, `oauth2`, `oauth2_body`, `sigv4`, `jwt_exchange`, `client_credentials`, `github_app`, `multi`.

### 2.5 Request-Time Parameter Overrides

`X-Sealed-Secret: <blob> ; {"header_name":"X-Custom","format":"%s"}` — JSON object after `;`.

Override only `format` and `header_name`, only within `allowed_formats` / `allowed_header_names`. If a config field is set non-empty, runtime override is rejected. Overrides cannot change processor type, auth, or host/path/method allowlists.

### 2.6 Request Validators

**Host** (mandatory; CLI rejects sealing without one):

- `allowed_hosts` — case-sensitive exact match against `request.Host` (port-aware).
- `allowed_host_pattern` — RE2 regex; anchor with `^...$`.

**Path** (optional, at most one):

- `allowed_path_prefixes` — segment-aware prefix match: `/v1/charges` matches `/v1/charges` and `/v1/charges/abc`, not `/v1/charges-list`.
- `allowed_path_pattern` — RE2 regex.

Independent of either allowlist, any decoded path containing a `.` or `..`
segment is refused before the allowlist runs. `url.Parse` decodes `%2e%2e` to
`..` in the `Path` field but does not normalize, so a literal prefix or regex
match would otherwise admit `/v1/charges/../admin` and let the upstream resolve
it to `/admin`.

**Method** (optional):

- `allowed_methods` — uppercase, case-sensitive.

**Server-side egress guard** (independent of sealed secret): refuses to dial RFC 1918, loopback, link-local, and `SECRET_PROXY_SELF_HOSTNAMES`. No allowlist at v1 — internal/VPC vendor support is deferred (see §5.2).

## 3. Wire & Transport

### 3.1 Wire Protocol

The proxy serves a single forward endpoint at `POST/GET/etc /v1/forward`. Method, body, and pass-through headers mirror the upstream request 1:1; three control headers carry the proxy contract:

```http
<METHOD> /v1/forward HTTP/1.1
Host: <proxy-host>
X-Upstream-URL: https://api.stripe.com/v1/charges
X-Sealed-Secret: <base64> [; <json-override>]
X-Auth-Bearer: Bearer <client-token>          (or Basic <b64(user:pass)>)
Content-Type: application/x-www-form-urlencoded

amount=4200&currency=usd
```

| Header            | Purpose                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `X-Upstream-URL`  | Required. Full URL to forward to (host validated against the seal's allowlists; scheme rewritten to `https` before dialing).         |
| `X-Sealed-Secret` | Required (unless `--allow-passthrough`). Base64 sealed secret, optionally `; <json-override>` for runtime overrides (§2.5).          |
| `X-Auth-Bearer`   | Required if the seal's auth config is `bearer_auth`. `Bearer <token>` or `Basic <b64(user:pass)>` (password half compared per §2.3). |

All three control headers are stripped before forwarding. Hop-by-hop headers (RFC 7230 §6.1) and `SECRET_PROXY_FILTERED_HEADERS` also stripped. Response streams back unchanged. Special endpoints (`/healthz`, `/readyz`, `/public-key`) bypass the forward path.

**Why a relative-URL endpoint, not absolute-form HTTP_PROXY semantics?** Absolute-form HTTP (`GET http://api.stripe.com/... HTTP/1.1`) is the wire pattern of a forward proxy, but reverse-proxy CDNs (Cloudflare, the layer in front of every PaaS Web Service) reject it at the edge. A normal relative POST to `/v1/forward` traverses any standard CDN, so the proxy can be deployed on Render, Cloud Run, Heroku, App Runner, K8s + ingress, or bare VPS without protocol gymnastics. The trade-off: vendor SDKs cannot use `HTTP_PROXY` env-var transparency — they must wire through the Go client library at `pkg/client` (or an equivalent).

A `CONNECT` MITM mode (on-the-fly cert generation, lets clients tunnel TLS through us) is deferred — see §5.2.

### 3.2 Transport Security

**Client → proxy:** TLS 1.3 only (server-authenticated). Two listener modes:

- **Bundled (default).** The proxy terminates TLS itself. Cert and key are provisioned via `--tls-cert-file` / `--tls-key-file` (§4.1); platform secret systems mount the PEM files. For local development, `secret-proxy gen-tls-cert` emits a self-signed pair (§4.2).
- **Behind a TLS terminator** (`--trust-tls-terminator` / `SECRET_PROXY_TRUST_TLS_TERMINATOR=1`). The proxy listens plaintext on `$PORT` (or `--listen-address`). Required when deploying on a PaaS that terminates TLS at the edge (Render Web Service, Cloud Run, Heroku, App Runner) or behind a mesh sidecar / K8s ingress that does. The deployment **must** guarantee the proxy is unreachable except via the terminator — see §5.1.

mTLS / client cert auth is out of scope at v1 — bearer tokens carry client identity.

**Proxy → upstream:** always TLS, system trust store, no pinning. Non-443 ports are rewritten to 443; per-host port passthrough is deferred (see §5.2).

**Listener wire version:** the proxy's own listener is HTTP/1.1 only (`NextProtos: ["http/1.1"]`, `TLSNextProto` zeroed). HTTP/2 is disabled deliberately: under HTTP/2, `httputil.ReverseProxy` panics with `http.ErrAbortHandler` on body-copy failure and the panic is silently recovered by `net/http`, hiding mid-stream upstream truncations from per-request logs. HTTP/1.1 keeps that signal observable.

## 4. Operation

### 4.1 Server Configuration

Env vars and CLI flags (flag wins). All env vars are `SECRET_PROXY_*` prefixed. **Required to start: a Curve25519 private key, plus a TLS cert/key pair (or `SECRET_PROXY_TRUST_TLS_TERMINATOR=1` to delegate TLS to an upstream terminator). Everything else has a safe default.**

The Curve25519 private key resolves in this order: `--private-key-file` → `--private-key` → `SECRET_PROXY_PRIVATE_KEY_FILE` → `SECRET_PROXY_PRIVATE_KEY`. File-mount paths are preferred in production; the inline form is a dev fallback. The previous private key (rotation) follows the same order. TLS cert and key are file-mount only.

| Env                                      | Flag                          | Type                          | Default                                          | Purpose                                                                                                                                                                                                                     |
| ---------------------------------------- | ----------------------------- | ----------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECRET_PROXY_PRIVATE_KEY_FILE`          | `--private-key-file`          | path                          | required¹                                        | PEM/hex file holding the Curve25519 private key. Preferred.                                                                                                                                                                 |
| `SECRET_PROXY_PRIVATE_KEY`               | `--private-key`               | hex (32 B)                    | required¹                                        | Curve25519 private key inline. Dev fallback / PaaS-only.                                                                                                                                                                    |
| `SECRET_PROXY_PREVIOUS_PRIVATE_KEY_FILE` | `--previous-private-key-file` | path                          | empty                                            | Optional second private key tried during rotation (§4.4).                                                                                                                                                                   |
| `SECRET_PROXY_PREVIOUS_PRIVATE_KEY`      | `--previous-private-key`      | hex (32 B)                    | empty                                            | Inline form of the previous key (PaaS / env-only secret stores).                                                                                                                                                            |
| `SECRET_PROXY_TLS_CERT_FILE`             | `--tls-cert-file`             | path                          | required²                                        | PEM cert chain for the HTTPS listener.                                                                                                                                                                                      |
| `SECRET_PROXY_TLS_KEY_FILE`              | `--tls-key-file`              | path                          | required²                                        | PEM private key for the HTTPS listener.                                                                                                                                                                                     |
| `SECRET_PROXY_TRUST_TLS_TERMINATOR`      | `--trust-tls-terminator`      | bool                          | `false`                                          | Listen plaintext (PaaS edge / mesh / ingress terminates TLS). §3.2.                                                                                                                                                         |
| `SECRET_PROXY_LISTEN_ADDRESS`            | `--listen-address`            | host:port                     | `:$PORT` if set, else `:8443`                    | Bind address. PaaS platforms inject `PORT`.                                                                                                                                                                                 |
| `SECRET_PROXY_FILTERED_HEADERS`          | `--filtered-headers`          | comma list                    | empty                                            | Extra headers to strip.                                                                                                                                                                                                     |
| `SECRET_PROXY_ALLOW_PASSTHROUGH`         | `--allow-passthrough`         | bool                          | `false`                                          | Forward requests without a sealed secret.                                                                                                                                                                                   |
| `SECRET_PROXY_SELF_HOSTNAMES`            | `--self-hostnames`            | comma list                    | auto: `localhost`, loopback IPs, `os.Hostname()` | Loop guard. User values merged with auto-detected set.                                                                                                                                                                      |
| `SECRET_PROXY_ALLOW_NO_AUTH`             | `--allow-no-auth`             | bool                          | `false`                                          | Permit `no_auth` sealed secrets.                                                                                                                                                                                            |
| `SECRET_PROXY_ALLOWED_CLIENT_CIDRS`      | `--allowed-client-cidrs`      | comma list of CIDR / IP       | empty (off)                                      | Ingress IP allowlist on `/v1/forward`. See §5.2 and §5.1 footgun #9.                                                                                                                                                        |
| `SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS`  | `--trust-cloudflare-headers`  | bool                          | `false`                                          | CDN-fronted: read `CF-Connecting-IP` for the ingress allowlist instead of rightmost-XFF, and strip `CF-*` / `True-Client-IP` from upstream forwarding. Requires `SECRET_PROXY_TRUST_TLS_TERMINATOR=1`. See §5.1 footgun #9. |
| `SECRET_PROXY_LOG_LEVEL`                 | `--log-level`                 | `debug`/`info`/`warn`/`error` | `info`                                           | Log level. `debug` also enables verbose proxy-internal logging.                                                                                                                                                             |

¹ Exactly one of the four private-key sources is required. TLS 1.3 is enforced at the listener; there is no version-downgrade flag.
² Required unless `SECRET_PROXY_TRUST_TLS_TERMINATOR=1`, in which case the proxy listens plaintext on `--listen-address` and trusts the upstream terminator.

**CDN-fronted deployments.** When a CDN (Cloudflare) sits in front of the TLS terminator (e.g. Cloudflare → Render → proxy), the terminator appends Cloudflare's egress IP to `X-Forwarded-For`, so the rightmost entry the proxy sees is a Cloudflare IP — not the real client. Enabling `SECRET_PROXY_ALLOWED_CLIENT_CIDRS` in this topology fails closed against every legitimate request. Set `SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS=1` (alongside `SECRET_PROXY_TRUST_TLS_TERMINATOR=1`) so the proxy reads `CF-Connecting-IP` for the allowlist match. Cloudflare's edge unconditionally strips and rewrites `CF-Connecting-IP`, so clients cannot spoof it _through_ Cloudflare. **The flag is a declaration that the proxy is unreachable except via Cloudflare** — same trust posture as `--trust-tls-terminator` (footgun #4). If the origin is also reachable directly, an attacker can set `CF-Connecting-IP` to any allowlisted value. The `CF-Connecting-IP`, `CF-Ray`, `CF-IPCountry`, `CF-Visitor`, and `True-Client-IP` headers are auto-stripped from upstream requests so they cannot leak to vendor APIs.

### 4.2 CLI

Single `secret-proxy` binary, multiple subcommands:

- **`serve`** — runs the HTTPS daemon. Resolves private key + TLS cert/key per §4.1.
- **`seal`** — seals a credential. Public key resolved from `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY` env (in that order). Outputs base64 to stdout.
- **`unseal`** — debug; resolves the private key per §4.1, reads sealed secret from stdin or `--token`.
- **`request`** — test wrapper. Defaults: `--proxy-url` to `https://localhost:8443`; sealed secret from `SEALED_SECRET` env; bearer token from `AUTH_TOKEN` env. `--proxy-insecure` skips proxy cert verification (dev only).
- **`gen-tls-cert`** — generates a self-signed Ed25519 cert + key pair to `--out-dir` (default `.`), valid for 90 days, with SANs `localhost`, `127.0.0.1`, `::1`, plus any extras passed via `--san`. **Dev only** — never use the output in production.
- **`gen-keypair`** — generates a fresh Curve25519 keypair and prints `private:` and `public:` hex to stdout. Used for initial keypair provisioning and for rotation.

```bash
SECRET_PROXY_PUBLIC_KEY=$(curl -s https://secret-proxy/public-key) \
  secret-proxy seal \
    --token "$STRIPE_LIVE_KEY" --auth-bearer "$CLIENT_TOKEN" \
    --allow-host api.stripe.com --allow-path-prefix /v1/charges --allow-method POST
```

Seal-time flag categories:

- **Required:** `--token`; one of `--auth-bearer` / `--no-auth`; one of `--allow-host` / `--allow-host-pattern`; public key (via `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY`).
- **Defaulted:** `--processor` → `inject-header`; `--format` → `"Bearer %s"`; `--header-name` → `"Authorization"`.
- **Optional:** `--allowed-format`, `--allowed-header-name`, `--allow-path-prefix` / `--allow-path-pattern`, `--allow-method`, `--name`, `--euid` (random UUIDv4 generated when omitted).

Go client library at `pkg/client`: `NewTransport(proxyURL, WithSealedSecret(blob), WithAuth(token))` returns an `http.RoundTripper` that retargets every request to `proxyURL/v1/forward`, copies the original URL into `X-Upstream-URL`, and adds `X-Sealed-Secret` and `X-Auth-Bearer`. Method, body, and remaining headers pass through. `WithProxyTLS(*tls.Config)` overrides the default TLS config for the proxy hop (e.g. to trust a dev CA).

### 4.3 Observability

Structured JSON logs (stdlib `log/slog`), one line per request. The proxy emits one of these event names:

| `msg`                          | Level | When                                                                                                                            |
| ------------------------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------- |
| `proxied`                      | INFO  | Forward request fully relayed.                                                                                                  |
| `proxied_truncated`            | WARN  | Forward request: response headers flushed but body copy errored mid-stream. Status was already sent — the client got a partial. |
| `passthrough`                  | INFO  | `--allow-passthrough` mode, no seal, fully relayed.                                                                             |
| `passthrough_truncated`        | WARN  | Same shape as `proxied_truncated` for the passthrough path.                                                                     |
| `proxy_reject`                 | WARN  | Pre-forward refusal (bad header, validator failure, ingress allowlist, bearer mismatch, …). Carries `reason`.                   |
| `seal_opened_via_previous_key` | WARN  | Seal decrypted with `--previous-private-key`, not the current key. Wire to a metric — its rate is the rotation-progress signal. |
| `egress_refused_at_dial`       | WARN  | `guardedDial` refused the upstream IP (self-loop or private/loopback/link-local). Logged separately from `upstream_error`.      |
| `upstream_error`               | WARN  | Genuine upstream failure (dial timeout, TLS handshake failure, etc.). Distinct bucket from the egress-refusal signal above.     |

Per-request fields: `method`, `host`, `path`, `query_keys` (keys only), `status`, `dur_ms`, `auth`, `processor`, `seal_euid`, `seal_name`, plus `reason` / `error` on rejects. `seal_euid` is the per-seal UUIDv4 stamped at seal time; `seal_name` is the operator-supplied label (empty if `--name` was not used).

**Redaction.** Tokens, digests, the sealed blob, and the proxy's private key never appear in log lines. The mechanism is `Secret.LogValue` plus the convention that the unmarshaled `Secret` is never logged whole — only the four fields enumerated above flow into per-request log lines. The `secret-proxy unseal` debug subcommand legitimately prints cleartext to stdout and is the only path that surfaces sealed contents.

Prometheus metrics and OpenTelemetry tracing are deferred (see §5.2).

### 4.4 Deployment

Multi-stage Dockerfile: Go build stage, then `alpine:3` with `ca-certificates`. Stateless, scale horizontally; `GET /healthz` and `GET /readyz` (ready only after private-key load, TLS cert load — skipped under `--trust-tls-terminator` — and listener bind). Health endpoints serve over the active listener — HTTPS by default, plaintext in trust-terminator mode (the platform's terminator handles TLS to the world).

**Dependencies.** Third-party: `golang.org/x/crypto/nacl/box`, `golang.org/x/crypto/curve25519`. Stdlib only beyond that: `net/http`, `net/http/httputil` (`ReverseProxy`), `crypto/tls`, `crypto/subtle`, `crypto/ed25519` (for `gen-tls-cert`), `log/slog`, `regexp`. No DB, no secret-manager SDK. Single static binary.

**Client integration.** Applications wire through the Go client library (`pkg/client`), which wraps an `http.Client` so application code can keep calling vendor SDKs with the original upstream URL. For non-Go runtimes, the equivalent is ~20 LOC: send the request to `<proxy-url>/v1/forward`, set `X-Upstream-URL` / `X-Sealed-Secret` / `X-Auth-Bearer`, mirror the body and method.

**Private-key provisioning.** File mount populated by the platform secret system (Kubernetes Secrets, Vault Agent, etc.) is the recommended path: `--private-key-file` reads PEM/hex from disk. The inline env var (`SECRET_PROXY_PRIVATE_KEY`) is a dev fallback; avoid in production since environment is visible in `/proc/<pid>/environ` and crash dumps. The binary intentionally does not link any cloud secret-manager SDK.

**TLS cert + key provisioning.** Same file-mount model — `--tls-cert-file` / `--tls-key-file` only. No env-inline form for cert material.

**Private-key rotation (zero-downtime).** Provision the new keypair, set `--previous-private-key-file` to the _old_ key on every replica, roll the fleet so all replicas accept both keys, re-seal client secrets against the new public key, then redeploy without `--previous-private-key-file`. The proxy tries the primary first and falls back to the previous; both attempts use constant-time decryption and fail closed.

**TLS cert rotation.** Replace the cert/key files and restart the proxy (K8s deployments typically handle this via Secret-checksum annotations on the Pod template).

## 5. Caveats

### 5.1 Footguns

1. **No replay protection.** A captured `(sealed-secret, bearer)` pair is reusable indefinitely. Mitigation: rotate seals on suspected leak.
2. **Self-signed dev certs.** `gen-tls-cert` is for local development only. Do not carry `INSECURE_SKIP_VERIFY` (or equivalents) into production — a forged proxy cert means harvested bearer tokens.
3. **Private key in env var leaks via `/proc`.** Prefer `--private-key-file` in production; the inline form is fine for local dev or for PaaS platforms whose only secret-delivery channel is env vars (Render, Heroku, Cloud Run).
4. **`--trust-tls-terminator` is a one-way door.** Only safe when the proxy is unreachable except via the upstream TLS terminator. If the proxy port is exposed (firewall hole, K8s NodePort, public ingress without TLS), bearer tokens cross the wire in cleartext.
5. **Loop guard auto-detects local hostnames and IPs.** Add CNAMEs or LB-fronted hostnames to `SECRET_PROXY_SELF_HOSTNAMES` if the proxy can be reached under them.
6. **Trust-anchor headers must be filtered.** Any header the proxy itself trusts (`X-Forwarded-For`, sidecar identity) must appear in `SECRET_PROXY_FILTERED_HEADERS` or clients can spoof.
7. **Host allowlist is mandatory in practice** — the CLI refuses to seal without one.
8. **No body size cap.** Add `--max-request-bytes` if large bodies are observed.
9. **Ingress IP allowlist depends on a single trusted-edge topology.**
   - **No CDN.** `SECRET_PROXY_ALLOWED_CLIENT_CIDRS` reads the rightmost XFF entry when `SECRET_PROXY_TRUST_TLS_TERMINATOR=1`, which assumes the terminator overwrites/appends XFF from the real TCP source. Without the terminator flag, the allowlist matches the TCP `RemoteAddr` instead — on a PaaS that means the edge LB IP, which is _not_ the client. Don't enable the allowlist behind a terminator without enabling terminator trust, and vice-versa: a misconfigured pair fails open against the wrong identity.
   - **CDN in front of the terminator.** When Cloudflare fronts the terminator, the rightmost-XFF entry is a Cloudflare egress IP and the allowlist fails closed against every real client. `SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS=1` switches the allowlist to `CF-Connecting-IP` and strips the CF trust headers (`CF-Connecting-IP`, `CF-Ray`, `CF-IPCountry`, `CF-Visitor`, `True-Client-IP`) from upstream forwarding. The proxy does **not** validate that the request came through Cloudflare — same trust model as `--trust-tls-terminator`. The deployment must guarantee the origin is unreachable except via Cloudflare (Cloudflare-only firewall rules, authenticated origin pulls, or platform "only accept Cloudflare traffic" controls). If the origin is exposed and the flag is on, clients can spoof `CF-Connecting-IP` to any allowlisted value. The flag does not bypass `--trust-tls-terminator`; both must be set.

### 5.2 Out of Scope at v1

Items not built in v1. Rationale recorded where a future contributor might reopen the decision.

- **Additive features without rationale:** rate limiting; request body size cap; OAuth/HMAC/body/SigV4/macaroon processors; multi-processor chains; response-side credential extraction; web UI / control plane.
- **Ingress IP CIDR allowlist** — _promoted in v1.x_, see `SECRET_PROXY_ALLOWED_CLIENT_CIDRS` in §4.1. Rationale: a public PaaS deployment exposes `/v1/forward` to the internet, and the seal+bearer pair is the only ingress check. Operators who run the proxy from a known set of client-app egress IPs (NAT pool, VPC NAT gateway, fixed-egress add-on) can shrink the attack surface to those IPs without changing the wire protocol. Defaults to off (empty list) so existing deployments are unaffected.
- **Cloudflare-aware ingress identity** — _promoted in v1.x_, see `SECRET_PROXY_TRUST_CLOUDFLARE_HEADERS` in §4.1 and footgun #9. Same shape as the CIDR allowlist promotion: a CDN-fronted deployment couldn't use the rightmost-XFF rule because the rightmost hop is a Cloudflare egress IP, not the real client. The flag switches the ingress identity source to `CF-Connecting-IP` and strips the CF trust headers from upstream forwarding. Off by default; requires `--trust-tls-terminator`.
- **Absolute-form HTTP forward-proxy protocol** (§3.1) — considered during prototyping for transparent `HTTP_PROXY` env-var integration with vendor SDKs. Dropped because reverse-proxy CDNs (Cloudflare, the layer in front of every PaaS Web Service) reject absolute-form HTTP at the edge, making PaaS deployments impossible. The relative-URL `/v1/forward` envelope traverses any CDN.
- **`CONNECT` MITM mode** (§3.1) — adds on-the-fly cert minting + CA distribution; revisit when a vendor SDK refuses to be wrapped via `pkg/client`.
- **`inject_basic_auth` processor** (§2.4) — pre-encoding `user:pass` at seal time keeps the processor surface single-purpose.
- **Internal/VPC egress allowlist** (§2.6) — RFC 1918 hard-refuse is the v1 default; revisit when a real internal-vendor driver appears.
- **Per-host port passthrough** (§3.2) — vendors are uniformly on 443; add a per-secret override only on demand.
- **mTLS / client cert auth** (§1.3, §3.2) — bearer + TLS-server-auth meets the v1 threat model; mTLS-augments-bearer is a clean wire-format additive when zero-trust becomes a requirement.
- **Prometheus metrics + OpenTelemetry tracing** (§4.3) — additive; ship when an ops driver appears.
- **`goproxy` dependency** (§4.4) — stdlib `httputil.ReverseProxy` + a thin forward-proxy shim covers v1 needs without the dep.
- **Cloud secret-manager SDK integration** (§4.4) — file mount + env covers the deployments we care about; SDK coupling adds vendor lock-in.
