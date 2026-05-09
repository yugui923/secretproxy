# Project CLAUDE.md — secretproxy

Repo-specific instructions. Read alongside the user's global CLAUDE.md.

## Public repository — no deployment-identifying strings

This repository is **public**. Never commit:

- Custom domains, subdomains, or any hostnames that identify a real
  deployment
- Service-specific URLs (Render-issued names like `<service>-<hash>.onrender.com`,
  Fly app URLs, ECS endpoints, etc.)
- Container registry paths that point at a real account
- IP addresses, DNS targets, ASN-identifying values
- Any other string that ties a file in this repo to a particular running
  instance of the proxy

Use placeholders instead: `<your-service>.example.com`, `<custom-domain>`,
`<your-account>/secret-proxy:tag`. The spec, README, render.yaml, and
.env.production.example all use placeholder language.

When real values are needed for local dev or deployment work, save them to
a `*.local.md` file (gitignored). `docs/render-deploy.local.md` is the
canonical home for the operator's actual hostnames and dashboard
configuration. The pattern `*.local.md` is in `.gitignore`.

If a deployment-identifying value ever lands in a commit, scrub it: amend
or rebase the commit, then force-push (with lease) to overwrite remote
history. Don't just add a "fix: remove leaked hostname" follow-up commit —
the original commit still carries the leak.

## Protocol & spec

The wire protocol is the relative-endpoint mode (`POST /v1/forward` with
`X-Upstream-URL` / `X-Sealed-Secret` / `X-Auth-Bearer` headers). This is
the only mode at v1; absolute-form HTTP_PROXY semantics were considered
during prototyping but rejected because they don't traverse reverse-proxy
CDNs (Cloudflare, etc.). Spec §3.1 is canonical — keep it in sync with
the code when the wire envelope changes.

## Deferred decisions

`docs/specs/2026-05-08-secret-proxy.md` §5.2 lists everything explicitly
not built at v1, with rationale. Add to that section before opening any
follow-up that reintroduces a deferred item.
