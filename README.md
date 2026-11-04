# monaca

Monaca is a full-stack identity & access management system for the AI-agent era: an OIDC/OAuth 2.1
protocol engine, a developer platform (SDK, hosted sign-in, admin console), and an agent-native
authorization layer (delegation chains, scope attenuation, approvals, audit forensics). The core is
Rust for the hot paths and the protocol engine; a Bun/Hono gateway hosts modules, the console BFF and
the dev proxy; PostgreSQL stores one database per tenant and one schema per organization.

**Status: M0 walk-through complete.** The repository skeleton, the binding contract, the module
system, the MCP guard and the UI package are in place, and the Rust side now implements the M0
surface: three migration sets with tenant/org provisioning, ES256 keys and JWKS, the OIDC
authorization-code + interaction + refresh + client-credentials flows, agent grants with
`private_key_jwt`/RAR and scope attenuation, the `/v1` management API, and the per-org audit hash
chain with verification. `monaca-server migrate`, `bootstrap`, `serve` and `audit verify` are real
commands. See [docs/contracts/m0.md](docs/contracts/m0.md) §12 for the acceptance criteria.

## Architecture at a glance

```
browser / agent ──► monaca-gateway (Bun/Hono, :8080)  ── the single public dev origin
                        │  ├─ /bff/*      console BFF, session cookie, bearer kept server-side
                        │  ├─ /mcp/demo   demo MCP resource server
                        │  └─ dev proxy   /t/*  /.well-known/*  /v1/*  → monaca-server (never /internal/*)
                        └──napi──► @monaca/core   in-process token verification and scope decisions

monaca-server (Rust/axum, :8081) ──sqlx──► PostgreSQL   control DB + one DB per tenant
                                                         (schema `tenant` + one schema per org)
```

* [docs/architecture.md](docs/architecture.md) — the approved M0–M4 architecture (authoritative).
* [docs/contracts/m0.md](docs/contracts/m0.md) — the binding M0 contract: names, ports, DDL, token
  formats, API shapes, CI artifacts. Read this before changing anything.

## Social sign-in and account linking

Social connectors are tenant-level configuration. `provider: "github"` and `provider: "google"`
use server-owned endpoints, scopes and userinfo mapping; `generic` keeps tenant-supplied URLs and
the OIDC-shaped userinfo contract. Every connector carries a `link_policy` for a verified provider
email: `auto_link_verified_email`, `confirm_link`, or `create_new_only`.

New connectors default to `confirm_link`. It is the most conservative policy that can still link:
nothing is associated silently, and the visitor explicitly accepts the address's existing account
on the hosted page. `create_new_only` cannot create a second account with an address that is
already taken, because `accounts.primary_email` is unique per tenant; it therefore refuses that
case with `409 MONACA_SOCIAL_EMAIL_TAKEN` instead of weakening the identity model.

## Production configuration

`MONACA_ENV=prod` removes every credential default. The server refuses to start unless
`MONACA_KEK` (32 bytes as 64 hex characters) and `MONACA_INTERNAL_SECRET` are explicit and are not
the documented dev defaults; `MONACA_DEV_KEK` is refused. `monaca-server bootstrap` additionally
requires `MONACA_BOOTSTRAP_ADMIN_PASSWORD`, `MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET` and
`MONACA_CONSOLE_CLIENT_SECRET`, but a `serve` restart does not: the seeds are read only when the
seeded rows do not exist, and an existing password or client secret is never overwritten.

The plaintext outbox reader `/internal/mail` is mounted only in dev/CI; in prod the route answers
404. **The KEK cannot be rotated in M0** — it derives every tenant DEK, so changing it makes
existing sealed signing keys and account secrets unreadable. Backups, the restore drill and the
RPO/RTO limits are in [docs/contracts/m0.md](docs/contracts/m0.md) §10.7 and
[deploy/README.md](deploy/README.md).

## Prerequisites

| need | why |
|---|---|
| [Bun](https://bun.sh) ≥ 1.3 | every TypeScript package, the gateway, the dev orchestration |
| `gh` CLI | `bun run fetch:native` and `bun run verify:ci` talk to GitHub Actions |
| PostgreSQL | **not needed** — mode A downloads a real PostgreSQL into `.monaca/pg` via `embedded-postgres` |
| Rust toolchain | **not installed locally, by design** — Rust compiles only in GitHub Actions |

Rust is built in CI, so this machine never needs `cargo`. `bun run fetch:native` downloads the
artifacts of the current commit (the server binary, the napi `.node`, the generated `index.d.ts`,
`openapi.json` and the event schemas).

## Dev modes

Three modes, one entry point. The first run without `--mode` asks once and records the answer in
`.monaca/dev.json`; `--mode a|b|c` (or `MONACA_DEV_MODE`) overrides it for one run.

### Mode A — local full stack

Everything runs locally: the fetched server binary, PostgreSQL, the gateway, and both Vue dev
servers. No Docker, no admin rights.

```bash
bun run fetch:native          # once per commit: pull the CI build of the server + napi module
bun run dev --mode a
```

If `.monaca/bin/monaca-server(.exe)` is missing, `bun run dev` prints exactly
`run: bun run fetch:native` and exits 1. It uses `DATABASE_URL` when set (that role needs `CREATEDB`
and `CREATEROLE`), otherwise it starts embedded PostgreSQL on 127.0.0.1:54329. Then it opens:

| URL | what |
|---|---|
| http://localhost:5173 | console (admin UI) |
| http://localhost:5174 | hosted sign-in |
| http://localhost:8080 | gateway — the single public origin, issuer `http://localhost:8080/t/demo` |
| http://127.0.0.1:8081 | server, internal only — never referenced by a browser or a token |

Ctrl-C stops every child and the database.

### Mode B — remote dev

Only the Vue apps run locally; Vite proxies to the deployed dev gateway. This is the mode for
frontend work without a Rust build.

```bash
MONACA_REMOTE_URL=https://dev.monaca.example bun run dev --mode b
bun run dev --mode b --with-gateway   # also run the local gateway, for module development
```

### Mode C — CI only

Typechecks and unit tests locally; builds and the end-to-end walk-through happen on GitHub Actions.

```bash
bun run dev --mode c          # runs `bun run typecheck` and `bun test`, then prints what to do next
bun run verify:ci             # dispatch rust.yml + web.yml on this branch, watch them, print results
```

## Commands

| command | what it does |
|---|---|
| `bun run dev [--mode a\|b\|c] [--with-gateway]` | start the local stack for the chosen mode |
| `bun run fetch:native [--run <id>] [--branch <b>] [--fmt] [--dry-run]` | download CI artifacts into their destinations |
| `bun run verify:ci` | mode C: run the workflows and report per-job conclusions |
| `bun run e2e:skeleton --base-url <url>` | the single acceptance script (contract §12) |
| `bun run typecheck` | every workspace package, then `scripts/` |
| `bun test` | unit tests across the repo |
| `bun run build` | build every package |

`bun run e2e:skeleton` is environment-agnostic: it takes `--base-url` for localhost, the remote dev
gateway or the CI server. It runs the whole M0 walk-through (contract §12): setup through the
management API, the agent's `private_key_jwt` grant, the over-request refusal, the allowed and
denied MCP tool calls, the audit chain and its verification, plus the console's browser flow. Steps
4 and 4b report `skip` against the bare server, because only the gateway mounts `/mcp/demo`.

## Repo layout

| path | package | what |
|---|---|---|
| `crates/` | `monaca-*` | Rust workspace: types, crypto, store, oidc, agent, policy, audit, core, napi, server |
| `packages/core/` | `@monaca/core` | napi loader + generated `index.d.ts` — in-process verification |
| `packages/kernel/` | `@monaca/kernel` | module system: registry, graph, config, verifier |
| `packages/mcp/` | `@monaca/mcp` | MCP resource-server guard (RFC 9728, bearer, problem+json) |
| `packages/sdk/` | `@monaca/sdk` | OpenAPI-derived client + agent helpers |
| `packages/ui/` | `@monaca/ui` | shadcn-vue components and domain components |
| `modules/mcp-demo/` | `@monaca/module-mcp-demo` | demo MCP server mounted at `/mcp/demo` |
| `apps/gateway/` | `@monaca/gateway` | Hono-on-Bun module host, console BFF, dev proxy |
| `apps/console/` | `@monaca/console` | admin console (Vite, :5173) |
| `apps/auth-ui/` | `@monaca/auth-ui` | hosted sign-in (Vite, :5174) |
| `scripts/` | — | `dev.ts`, `fetch-native.ts`, `verify-ci.ts`, `e2e/skeleton.ts`, `lib/`, `spikes/` |
| `spec/` | — | generated, committed `openapi.json` and event JSON Schemas |
| `deploy/` | — | Dockerfiles and the dev compose file |
| `docs/` | — | architecture, contracts, ADRs |

## Conventions

* **Only edit what you own.** Each path has an owner; cross-cutting files (root `Cargo.toml`,
  root `package.json`, `packages/tsconfig/*`, `docs/contracts/m0.md`) change only through the
  contract owner.
* TypeScript is strict ESM with small focused modules. Rust uses explicit types and one
  `thiserror`-style error enum per crate.
* **Never** commit `.monaca/` (fetched binaries, embedded PostgreSQL data, reports) — it is ignored.
* Every identifier in the public API is a typed string (`acc_…`, `agt_…`, `grt_…`); see contract §5.2.
