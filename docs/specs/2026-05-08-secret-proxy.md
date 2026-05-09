# Secret Proxy — Design Spec

> Draft v0. Open items marked **`[OPEN]`**. Last updated 2026-05-08.

## 1. Overview

A stateless Go HTTP proxy that decrypts client-sealed credentials in-process and injects them into outbound requests to third-party APIs (Stripe, Twilio, OpenAI, etc.). The proxy holds a Curve25519 keypair; the public key is published, and operators seal credentials offline against it via a CLI. Sealed secrets travel on every request in a header. **No server-side credential store** — every request is independent.

## 2. Goals & Non-Goals

**Goals.** Keep vendor credentials out of application processes, env vars, and logs. ~500–1000 LOC of Go, single static binary. Transparent to existing vendor SDKs. Reusable sealed credentials, scoped to a specific upstream host + bearer-token holder.

**Non-goals.** Credential rotation as a service. Webhook verification. Replay protection. OAuth refresh management. Multi-tenant UI / control plane.

## 3. Threat Model

| Attacker                                     | Mitigated?   | How                                                                                                                                                                                         |
| -------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reads sealed secrets at rest (config, git)   | Yes          | Useless without the proxy private key.                                                                                                                                                      |
| Steals sealed secret + replays from new host | Partial      | `bearer_auth` digest also requires the matching plaintext token.                                                                                                                            |
| Steals both sealed secret and bearer token   | Partial      | `allowed_hosts` (+ optional `allowed_path_prefixes` / `allowed_methods`) blocks redirect to attacker-controlled hosts; narrows but does not eliminate abuse via legitimate-shaped requests. |
| Compromises proxy host                       | No           | Private key in memory; rotate keypair to recover.                                                                                                                                           |
| Network observer (client → proxy)            | Out of scope | Plaintext HTTP — assumes secure transport (mTLS terminator, mesh, VPN).                                                                                                                     |
| Network observer (proxy → upstream)          | Yes          | Forced TLS, system trust store.                                                                                                                                                             |
| Operator with log access                     | Yes          | All credential, key, and digest fields redacted at marshal time (`Redact`).                                                                                                                 |
| Operator with proxy host access              | Partial      | Plaintext credentials exist transiently in-process; standard host hardening applies.                                                                                                        |

## 4. Cryptographic Design

NaCl sealed box (`golang.org/x/crypto/nacl/box`) — Curve25519 + XSalsa20-Poly1305, anonymous sender. Per-message ephemeral sender keys provide forward secrecy.

- **Private key** (`SECRET_PROXY_PRIVATE_KEY`): 32 random bytes hex-encoded; held only by the proxy.
- **Public key** (`SECRET_PROXY_PUBLIC_KEY`): derived via `curve25519.ScalarBaseMult`; served at `GET /public-key` as `text/plain` hex.
- **Sealed-secret wire format**: `base64.StdEncoding(box.SealAnonymous(JSON(secret)))`.

## 5. Wire Protocol

Forward HTTP proxy. Clients set `HTTP_PROXY=http://secret-proxy:8080` and send absolute-form HTTP — not HTTPS, since the proxy needs plaintext to inject:

```
HTTP_PROXY=http://secret-proxy:8080  curl -X POST http://api.stripe.com/v1/charges  \
    -H 'Proxy-Authorization: Bearer <client-token>'                                  \
    -H 'Proxy-Secret: <sealed-secret>'                                               \
    --data 'amount=4200&currency=usd'
```

| Header                | Purpose                                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `Proxy-Secret`        | Required. Base64 sealed secret, optionally `; <json-params>` for runtime overrides (§9). May repeat to chain processors. |
| `Proxy-Authorization` | Required if auth config is `bearer_auth`. `Bearer <token>` or `Basic <b64(user:pass)>`.                                  |

Both stripped before forwarding. Hop-by-hop headers (RFC 7230 §6.1) and `SECRET_PROXY_FILTERED_HEADERS` also stripped. Response forwarded unchanged.

A second mode — `CONNECT` MITM with on-the-fly cert generation — covers SDKs that can't downgrade to HTTP. **`[OPEN: ship in v1?]`**

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

HTTP Basic at v1: pre-encode `user:pass` with base64 at seal time and store as `token` with `format = "Basic %s"`. **`[OPEN: alternative is a dedicated `inject_basic_auth` processor — recommend pre-encode for minimum code.]`**

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

**Server-side egress guard** (independent of sealed secret): refuses to dial RFC 1918, loopback, link-local, and `SECRET_PROXY_SELF_HOSTNAMES`. **`[OPEN: opt-in allowlist for VPC vendors?]`**

## 11. Transport Security

**Client → proxy:** plaintext; front with mTLS terminator, mesh, or VPN. **`[OPEN: bundle TLS termination?]`**

**Proxy → upstream:** always TLS, system trust store, no pinning. Non-443 ports rewritten to 443. **`[OPEN: allow port-passthrough?]`**

## 12. Server Configuration

Env vars and CLI flags (flag wins). All env vars are `SECRET_PROXY_*` prefixed. **Only `SECRET_PROXY_PRIVATE_KEY` is required to start; everything else has a safe default.**

| Env                              | Flag                  | Type                          | Default                                          | Purpose                                                         |
| -------------------------------- | --------------------- | ----------------------------- | ------------------------------------------------ | --------------------------------------------------------------- |
| `SECRET_PROXY_PRIVATE_KEY`       | `--private-key`       | hex (32 B)                    | required                                         | Curve25519 private key.                                         |
| `SECRET_PROXY_LISTEN_ADDRESS`    | `--listen-address`    | host:port                     | `:8080`                                          | Bind address.                                                   |
| `SECRET_PROXY_FILTERED_HEADERS`  | `--filtered-headers`  | comma list                    | empty                                            | Extra headers to strip.                                         |
| `SECRET_PROXY_ALLOW_PASSTHROUGH` | `--allow-passthrough` | bool                          | `false`                                          | Forward requests without a sealed secret.                       |
| `SECRET_PROXY_SELF_HOSTNAMES`    | `--self-hostnames`    | comma list                    | auto: `localhost`, loopback IPs, `os.Hostname()` | Loop guard. User values merged with auto-detected set.          |
| `SECRET_PROXY_ALLOW_NO_AUTH`     | `--allow-no-auth`     | bool                          | `false`                                          | Permit `no_auth` sealed secrets.                                |
| `SECRET_PROXY_LOG_LEVEL`         | `--log-level`         | `debug`/`info`/`warn`/`error` | `info`                                           | Log level. `debug` also enables verbose proxy-internal logging. |

## 13. CLI

Single `secret-proxy` binary, multiple subcommands:

- **`serve`** — runs the daemon. With `SECRET_PROXY_PRIVATE_KEY` set, takes no flags.
- **`seal`** — seals a credential. Public key resolved from `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY` env (in that order). Outputs base64 to stdout.
- **`unseal`** — debug; reads `SECRET_PROXY_PRIVATE_KEY` from env, sealed secret from stdin or `--token`.
- **`request`** — test wrapper. Defaults: `--proxy-url` to `http://localhost:8080`; sealed secret from `SEALED_SECRET` env; bearer token from `AUTH_TOKEN` env.

```
SECRET_PROXY_PUBLIC_KEY=$(curl -s http://secret-proxy/public-key) \
  secret-proxy seal \
    --token "$STRIPE_LIVE_KEY" --auth-bearer "$CLIENT_TOKEN" \
    --allow-host api.stripe.com --allow-path-prefix /v1/charges --allow-method POST
```

Seal-time flag categories:

- **Required:** `--token`; one of `--auth-bearer` / `--no-auth`; one of `--allow-host` / `--allow-host-pattern`; public key (via `--public-key`, `--public-key-url`, or `SECRET_PROXY_PUBLIC_KEY`).
- **Defaulted:** `--processor` → `inject-header`; `--format` → `"Bearer %s"`; `--header-name` → `"Authorization"`.
- **Optional:** `--allowed-format`, `--allowed-header-name`, `--allow-path-prefix` / `--allow-path-pattern`, `--allow-method`.

Go client library at `pkg/client`: `NewTransport(proxyURL, WithSealedSecret(blob), WithAuth(token))` returns an `http.RoundTripper` that injects headers and rewrites `https://` → `http://`.

## 14. Observability

Structured JSON logs, one line per request: `source`, `method`, `host`, `path`, `query_keys` (keys only), `status`, `dur_ms`, `bytes_in`, `bytes_out`, `processor`, `auth`, `error`. Never log tokens, digests, or keys.

`Redact` invariant: every credential/key/digest field implements `MarshalJSON → "REDACTED"`; the `Secret` struct is never logged whole.

**`[OPEN: stdlib slog vs logrus? Prometheus metrics? OpenTelemetry tracing?]`**

## 15. Out of Scope at v1

IP CIDR allowlist; rate limiting; request body size cap; OAuth/HMAC/body/SigV4/macaroon processors; multi-processor chains; response-side credential extraction; built-in TLS termination; web UI / control plane.

## 16. Dependencies

`golang.org/x/crypto/nacl/box`, `golang.org/x/crypto/curve25519`, `github.com/elazarl/goproxy` (forward proxy + CONNECT MITM; **`[OPEN: vs hand-rolled httputil.ReverseProxy]`**), structured logger (`logrus` or stdlib `log/slog`), stdlib `crypto/subtle` / `net/http` / `crypto/tls` / `regexp`. No DB, no secret-manager SDK. Single static binary.

## 17. Deployment

Multi-stage Dockerfile: Go build stage, then `alpine:3` with `ca-certificates`. Stateless, scale horizontally; `GET /healthz` and `GET /readyz` (ready only after keypair load + listener bind).

Private-key provisioning: file mount populated by the platform secret system (preferred). **`[OPEN: env var or secret-manager SDK?]`**

Key rotation: generate keypair → re-seal (CLI fetches new public key via `--public-key-url`) → roll fleet → replace sealed secrets in clients. **`[OPEN: dual-key decrypt during rollover?]`**

## 18. Footguns

1. **Plaintext client→proxy hop.** Without a fronting TLS terminator, sealed secrets and bearer tokens cross the wire in cleartext.
2. **No replay protection.** A captured `(sealed-secret, bearer)` pair is reusable indefinitely. Mitigation: rotate seals on suspected leak.
3. **Loop guard auto-detects local hostnames and IPs.** Add CNAMEs or LB-fronted hostnames to `SECRET_PROXY_SELF_HOSTNAMES` if the proxy can be reached under them.
4. **Trust-anchor headers must be filtered.** Any header the proxy itself trusts (`X-Forwarded-For`, sidecar identity) must appear in `SECRET_PROXY_FILTERED_HEADERS` or clients can spoof.
5. **Host allowlist is mandatory in practice** — the CLI refuses to seal without one.
6. **No body size cap.** Add `--max-request-bytes` if large bodies are observed.

## 19. Open Decisions

1. §5 — `CONNECT` MITM in v1 or defer.
2. §8 — HTTP Basic: pre-encode (A) vs `inject_basic_auth` processor (B).
3. §10 — Egress guard: hard-refuse RFC 1918 vs opt-in allowlist.
4. §11 — Bundle TLS termination?
5. §11 — Hard-rewrite ports vs port-passthrough?
6. §14 — slog vs logrus; Prometheus; OTel.
7. §16 — `goproxy` vs hand-rolled.
8. §17 — Private-key provisioning; dual-key rotation support.
