# Secret Proxy — Design Spec

> Draft v0. Last updated 2026-05-09.

## 1. Overview

A stateless Go HTTP proxy that decrypts client-sealed credentials in-process and injects them into outbound requests to third-party APIs (Stripe, Twilio, OpenAI, etc.). The proxy holds a Curve25519 keypair; the public key is published, and operators seal credentials offline against it via a CLI. Sealed secrets travel on every request in a header. **No server-side credential store** — every request is independent.

## 2. Goals & Non-Goals

**Goals.** Keep vendor credentials out of application processes, env vars, and logs. ~500–1000 LOC of Go, single static binary. Transparent to existing vendor SDKs. Reusable sealed credentials, scoped to a specific upstream host + bearer-token holder.

**Non-goals.** Credential rotation as a service. Webhook verification. Replay protection. OAuth refresh management. Multi-tenant UI / control plane.

## 3. Threat Model

| Attacker                                     | Mitigated? | How                                                                                                                                                                                         |
| -------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reads sealed secrets at rest (config, git)   | Yes        | Useless without the proxy private key.                                                                                                                                                      |
| Steals sealed secret + replays from new host | Partial    | `bearer_auth` digest also requires the matching plaintext token.                                                                                                                            |
| Steals both sealed secret and bearer token   | Partial    | `allowed_hosts` (+ optional `allowed_path_prefixes` / `allowed_methods`) blocks redirect to attacker-controlled hosts; narrows but does not eliminate abuse via legitimate-shaped requests. |
| Compromises proxy host                       | No         | Curve25519 + TLS private keys in memory; rotate both to recover.                                                                                                                            |
| Network observer (client → proxy)            | Yes        | TLS 1.3 server-authenticated; cert + key provisioned by platform secret system.                                                                                                             |
| Network observer (proxy → upstream)          | Yes        | Forced TLS, system trust store.                                                                                                                                                             |
| Operator with log access                     | Yes        | All credential, key, and digest fields redacted at marshal time (`Redact`).                                                                                                                 |
| Operator with proxy host access              | Partial    | Plaintext credentials exist transiently in-process; standard host hardening applies.                                                                                                        |

## 4. Cryptographic Design

NaCl sealed box (`golang.org/x/crypto/nacl/box`) — Curve25519 + XSalsa20-Poly1305, anonymous sender. Per-message ephemeral sender keys provide forward secrecy.

- **Private key** (`SECRET_PROXY_PRIVATE_KEY`): 32 random bytes hex-encoded; held only by the proxy.
- **Public key** (`SECRET_PROXY_PUBLIC_KEY`): derived via `curve25519.ScalarBaseMult`; served at `GET /public-key` as `text/plain` hex.
- **Sealed-secret wire format**: `base64.StdEncoding(box.SealAnonymous(JSON(secret)))`.

## 5. Wire Protocol

Forward HTTP proxy reached over TLS. Clients set `HTTP_PROXY=https://secret-proxy:8443` and send absolute-form HTTP. The _target_ URL stays `http://` because the proxy needs plaintext to inject headers; the _proxy_ URL is `https://` so the client→proxy hop is encrypted. Modern HTTP clients (curl, Go `net/http`, Node 20+, Python `httpx`/`aiohttp`, JVM `HttpClient`) support HTTPS forward proxies natively.

```
HTTP_PROXY=https://secret-proxy:8443  curl -X POST http://api.stripe.com/v1/charges  \
    -H 'Proxy-Authorization: Bearer <client-token>'                                   \
    -H 'Proxy-Secret: <sealed-secret>'                                                \
    --data 'amount=4200&currency=usd'
```

| Header                | Purpose                                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `Proxy-Secret`        | Required. Base64 sealed secret, optionally `; <json-params>` for runtime overrides (§9). May repeat to chain processors. |
| `Proxy-Authorization` | Required if auth config is `bearer_auth`. `Bearer <token>` or `Basic <b64(user:pass)>`.                                  |

Both stripped before forwarding. Hop-by-hop headers (RFC 7230 §6.1) and `SECRET_PROXY_FILTERED_HEADERS` also stripped. Response forwarded unchanged.

SDKs that refuse to downgrade to plaintext HTTP are unsupported at v1; a `CONNECT` MITM mode (on-the-fly cert generation) is deferred — see §15 / §19.

## 6. Sealed Secret Format

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
}
```

Marshaling rejects: more than one auth tag, more than one processor tag, both host fields, both path fields, unknown tags.

## 7. Authorizers

- **`bearer_auth`** — sealed `digest = sha256(token)`. Client sends `Proxy-Authorization: Bearer <token>` (or `Basic …`; password half is compared). Constant-time compare.
- **`no_auth`** — disables proxy-side auth. Refused unless server has `--allow-no-auth`.

Macaroon-based authorization and platform-issued machine-identity tokens deferred (additive, no wire-format break).

## 8. Processors

**`inject_header`** (only processor at v1):

- `token`, `format` (default `"Bearer %s"`), `header_name` (default `"Authorization"`).
- Computes `fmt.Sprintf(format, token)`, sets `request.Header[header_name]`.

HTTP Basic at v1: pre-encode `user:pass` with base64 at seal time and store as `token` with `format = "Basic %s"`. A dedicated `inject_basic_auth` processor is deferred — pre-encoding keeps the processor surface single-purpose.

Deferred (wire-compatible additive changes): `inject_hmac`, `inject_body`, `oauth2`, `oauth2_body`, `sigv4`, `jwt_exchange`, `client_credentials`, `github_app`, `multi`.

## 9. Request-Time Parameter Overrides

`Proxy-Secret: <blob> ; {"header_name":"X-Custom","format":"%s"}` — JSON object after `;`.

Override only `format` and `header_name`, only within `allowed_formats` / `allowed_header_names`. If a config field is set non-empty, runtime override is rejected. Overrides cannot change processor type, auth, or host/path/method allowlists.

## 10. Request Validators

**Host** (mandatory; CLI rejects sealing without one):

- `allowed_hosts` — case-sensitive exact match against `request.Host` (port-aware).
- `allowed_host_pattern` — RE2 regex; anchor with `^...$`.

**Path** (optional, at most one):

- `allowed_path_prefixes` — segment-aware prefix match: `/v1/charges` matches `/v1/charges` and `/v1/charges/abc`, not `/v1/charges-list`.
- `allowed_path_pattern` — RE2 regex.

**Method** (optional):

- `allowed_methods` — uppercase, case-sensitive.

**Server-side egress guard** (independent of sealed secret): refuses to dial RFC 1918, loopback, link-local, and `SECRET_PROXY_SELF_HOSTNAMES`. No allowlist at v1 — internal/VPC vendor support is deferred (see §15 / §19).

## 11. Transport Security

**Client → proxy:** TLS 1.3 only (server-authenticated). The listener is HTTPS-only — there is no plaintext fallback. Cert and key are provisioned via `--tls-cert-file` / `--tls-key-file` (§12); platform secret systems mount the PEM files. For local development, `secret-proxy gen-tls-cert` emits a self-signed pair (§13). mTLS / client cert auth is out of scope at v1 — bearer tokens carry client identity.

**Proxy → upstream:** always TLS, system trust store, no pinning. Non-443 ports are rewritten to 443; per-host port passthrough is deferred (see §15 / §19).

## 12. Server Configuration

Env vars and CLI flags (flag wins). All env vars are `SECRET_PROXY_*` prefixed. **Required to start: a Curve25519 private key plus a TLS cert/key pair. Everything else has a safe default.**

The Curve25519 private key resolves in this order: `--private-key-file` → `--private-key` → `SECRET_PROXY_PRIVATE_KEY_FILE` → `SECRET_PROXY_PRIVATE_KEY`. File-mount paths are preferred in production; the inline form is a dev fallback. TLS cert and key are file-mount only.

| Env                                      | Flag                          | Type                          | Default                                          | Purpose                                                         |
| ---------------------------------------- | ----------------------------- | ----------------------------- | ------------------------------------------------ | --------------------------------------------------------------- |
| `SECRET_PROXY_PRIVATE_KEY_FILE`          | `--private-key-file`          | path                          | required¹                                        | PEM/hex file holding the Curve25519 private key. Preferred.     |
| `SECRET_PROXY_PRIVATE_KEY`               | `--private-key`               | hex (32 B)                    | required¹                                        | Curve25519 private key inline. Dev fallback.                    |
| `SECRET_PROXY_PREVIOUS_PRIVATE_KEY_FILE` | `--previous-private-key-file` | path                          | empty                                            | Optional second private key tried during rotation (§17).        |
| `SECRET_PROXY_TLS_CERT_FILE`             | `--tls-cert-file`             | path                          | required                                         | PEM cert chain for the HTTPS listener.                          |
| `SECRET_PROXY_TLS_KEY_FILE`              | `--tls-key-file`              | path                          | required                                         | PEM private key for the HTTPS listener.                         |
| `SECRET_PROXY_LISTEN_ADDRESS`            | `--listen-address`            | host:port                     | `:8443`                                          | Bind address.                                                   |
| `SECRET_PROXY_FILTERED_HEADERS`          | `--filtered-headers`          | comma list                    | empty                                            | Extra headers to strip.                                         |
| `SECRET_PROXY_ALLOW_PASSTHROUGH`         | `--allow-passthrough`         | bool                          | `false`                                          | Forward requests without a sealed secret.                       |
| `SECRET_PROXY_SELF_HOSTNAMES`            | `--self-hostnames`            | comma list                    | auto: `localhost`, loopback IPs, `os.Hostname()` | Loop guard. User values merged with auto-detected set.          |
| `SECRET_PROXY_ALLOW_NO_AUTH`             | `--allow-no-auth`             | bool                          | `false`                                          | Permit `no_auth` sealed secrets.                                |
| `SECRET_PROXY_LOG_LEVEL`                 | `--log-level`                 | `debug`/`info`/`warn`/`error` | `info`                                           | Log level. `debug` also enables verbose proxy-internal logging. |

¹ Exactly one of the four private-key sources is required. TLS 1.3 is enforced at the listener; there is no version-downgrade flag.

## 13. CLI

Single `secret-proxy` binary, multiple subcommands:

- **`serve`** — runs the HTTPS daemon. Resolves private key + TLS cert/key per §12.
- **`seal`** — seals a credential. Public key resolved from `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY` env (in that order). Outputs base64 to stdout.
- **`unseal`** — debug; resolves the private key per §12, reads sealed secret from stdin or `--token`.
- **`request`** — test wrapper. Defaults: `--proxy-url` to `https://localhost:8443`; sealed secret from `SEALED_SECRET` env; bearer token from `AUTH_TOKEN` env. `--proxy-insecure` skips proxy cert verification (dev only).
- **`gen-tls-cert`** — generates a self-signed Ed25519 cert + key pair to `--out-dir` (default `.`), valid for 90 days, with SANs `localhost`, `127.0.0.1`, `::1`, plus any extras passed via `--san`. **Dev only** — never use the output in production.

```
SECRET_PROXY_PUBLIC_KEY=$(curl -s https://secret-proxy/public-key) \
  secret-proxy seal \
    --token "$STRIPE_LIVE_KEY" --auth-bearer "$CLIENT_TOKEN" \
    --allow-host api.stripe.com --allow-path-prefix /v1/charges --allow-method POST
```

Seal-time flag categories:

- **Required:** `--token`; one of `--auth-bearer` / `--no-auth`; one of `--allow-host` / `--allow-host-pattern`; public key (via `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY`).
- **Defaulted:** `--processor` → `inject-header`; `--format` → `"Bearer %s"`; `--header-name` → `"Authorization"`.
- **Optional:** `--allowed-format`, `--allowed-header-name`, `--allow-path-prefix` / `--allow-path-pattern`, `--allow-method`.

Go client library at `pkg/client`: `NewTransport(proxyURL, WithSealedSecret(blob), WithAuth(token))` returns an `http.RoundTripper` that injects headers and rewrites `https://` → `http://` in target URLs (the _proxy_ hop itself runs TLS — driven by the scheme of `proxyURL`). `WithProxyTLS(*tls.Config)` overrides the default TLS config for the proxy hop (e.g. to trust a dev CA).

## 14. Observability

Structured JSON logs, one line per request: `source`, `method`, `host`, `path`, `query_keys` (keys only), `status`, `dur_ms`, `bytes_in`, `bytes_out`, `processor`, `auth`, `error`. Never log tokens, digests, or keys.

`Redact` invariant: every credential/key/digest field implements `MarshalJSON → "REDACTED"`; the `Secret` struct is never logged whole.

Logger: stdlib `log/slog`. Prometheus metrics and OpenTelemetry tracing are deferred (see §15 / §19).

## 15. Out of Scope at v1

IP CIDR allowlist; rate limiting; request body size cap; OAuth/HMAC/body/SigV4/macaroon processors; multi-processor chains; response-side credential extraction; web UI / control plane; mTLS / client cert auth; `CONNECT` MITM mode; internal/VPC egress allowlist; per-host port passthrough; Prometheus metrics; OpenTelemetry tracing; cloud secret-manager SDK integration.

## 16. Dependencies

Third-party: `golang.org/x/crypto/nacl/box`, `golang.org/x/crypto/curve25519`. Stdlib only beyond that: `net/http`, `net/http/httputil` (`ReverseProxy` plus a thin forward-proxy shim — no `goproxy` dep), `crypto/tls`, `crypto/subtle`, `crypto/ed25519` (for `gen-tls-cert`), `log/slog`, `regexp`. No DB, no secret-manager SDK. Single static binary.

## 17. Deployment

Multi-stage Dockerfile: Go build stage, then `alpine:3` with `ca-certificates`. Stateless, scale horizontally; `GET /healthz` and `GET /readyz` (ready only after private-key load, TLS cert load, and listener bind). Health endpoints serve over the HTTPS listener — configure K8s probes with `scheme: HTTPS` (and skip-verify in dev where the cert isn't trusted).

**Private-key provisioning.** File mount populated by the platform secret system (Kubernetes Secrets, Vault Agent, etc.) is the recommended path: `--private-key-file` reads PEM/hex from disk. The inline env var (`SECRET_PROXY_PRIVATE_KEY`) is a dev fallback; avoid in production since environment is visible in `/proc/<pid>/environ` and crash dumps. The binary intentionally does not link any cloud secret-manager SDK.

**TLS cert + key provisioning.** Same file-mount model — `--tls-cert-file` / `--tls-key-file` only. No env-inline form for cert material.

**Private-key rotation (zero-downtime).** Provision the new keypair, set `--previous-private-key-file` to the _old_ key on every replica, roll the fleet so all replicas accept both keys, re-seal client secrets against the new public key, then redeploy without `--previous-private-key-file`. The proxy tries the primary first and falls back to the previous; both attempts use constant-time decryption and fail closed.

**TLS cert rotation.** Replace the cert/key files and restart the proxy (K8s deployments typically handle this via Secret-checksum annotations on the Pod template).

## 18. Footguns

1. **No replay protection.** A captured `(sealed-secret, bearer)` pair is reusable indefinitely. Mitigation: rotate seals on suspected leak.
2. **Self-signed dev certs.** `gen-tls-cert` is for local development only. Do not carry `INSECURE_SKIP_VERIFY` (or equivalents) into production — a forged proxy cert means harvested bearer tokens.
3. **Private key in env var leaks via `/proc`.** Prefer `--private-key-file` in production; the inline form is fine for local dev.
4. **Loop guard auto-detects local hostnames and IPs.** Add CNAMEs or LB-fronted hostnames to `SECRET_PROXY_SELF_HOSTNAMES` if the proxy can be reached under them.
5. **Trust-anchor headers must be filtered.** Any header the proxy itself trusts (`X-Forwarded-For`, sidecar identity) must appear in `SECRET_PROXY_FILTERED_HEADERS` or clients can spoof.
6. **Host allowlist is mandatory in practice** — the CLI refuses to seal without one.
7. **No body size cap.** Add `--max-request-bytes` if large bodies are observed.

## 19. Deferred Decisions

Resolved in this revision and explicitly **not** revisited at v1; recorded so future contributors see the rationale before reopening.

1. **`CONNECT` MITM mode** (§5) — adds on-the-fly cert minting + CA distribution; revisit when a vendor SDK refuses `HTTP_PROXY` downgrade.
2. **`inject_basic_auth` processor** (§8) — pre-encoding `user:pass` at seal time keeps the processor surface single-purpose.
3. **Internal/VPC egress allowlist** (§10) — RFC 1918 hard-refuse is the v1 default; revisit when a real internal-vendor driver appears.
4. **Per-host port passthrough** (§11) — vendors are uniformly on 443; add a per-secret override only on demand.
5. **mTLS / client cert auth** (§3, §11) — bearer + TLS-server-auth meets the v1 threat model; mTLS-augments-bearer is a clean wire-format additive when zero-trust becomes a requirement.
6. **Prometheus metrics + OpenTelemetry tracing** (§14) — additive; ship when an ops driver appears.
7. **`goproxy` dependency** (§16) — stdlib `httputil.ReverseProxy` + a thin forward-proxy shim covers v1 needs without the dep.
8. **Cloud secret-manager SDK integration** (§17) — file mount + env covers the deployments we care about; SDK coupling adds vendor lock-in.
