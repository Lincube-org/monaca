# Post-M0 hardening roadmap

This document sequences the work after the M0 feature build. The batches are ordered by what
breaks first in a real deployment, not by what is easiest to write.

Each capability in every batch closes the same way: contract update + migration (when storage
changes) + a positive e2e step + a negative e2e step that fails when the capability is bypassed.
A configuration switch alone is not acceptance.

## Batch A — Functional and security correctness

These are defects in behavior that M0 already promises. They come first because a production
deployment cannot compensate for them with operational tooling.

1. **Revocation propagation.** `/t/{tenant}/oauth2/revoke` records an access token's `jti` in
   `tenant.revoked_access_tokens`, and `userinfo` consults it, but the `/v1` management verifier
   does not. A revoked admin or automation token still opens the management API. The fix is a
   revocation check in `management::authorize_admin`; the negative e2e mints two tokens, revokes
   one, and proves the revoked token is `401` while the other still works.
2. **Rate limiting.** No layer currently bounds request volume. Add a configurable gate with a
   tenant-wide layer and a per-client layer for the `authorize`, `token`, `userinfo` and
   management endpoint classes. Config lives in the tenant schema (`rate_limits`), is managed
   through `/v1/rate-limits`, and is enforced in-process with a bounded bucket cache. A rejected
   request is `429 MONACA_TOO_MANY_ATTEMPTS` with `Retry-After`. Defaults are deliberately
   generous so an existing deployment is not throttled on upgrade.
3. **Interaction state persistence.** `interactions`, pending TOTP enrollments and WebAuthn
   challenges live in process memory (`AppState`). A restart loses in-flight sign-ins, and a
   second instance cannot complete a flow that started on the first. Move all three to the tenant
   schema (`interactions`, `totp_enrollments`, `passkey_challenges`), seal the pending TOTP seed
   with the tenant DEK, and make every transition a transactional row update. The e2e proves a
   flow that starts on one server process and finishes on a freshly started one; replay after
   restart must still be `409`, and an unknown interaction `404`.
4. **Bounded caches.** After (3) the remaining process maps are the signing-key cache and the
   rate-limit buckets. Both get an explicit capacity with eviction, so a long-lived process cannot
   grow without a bound.

Why first: (1) is a security bypass, (2) is availability, (3) breaks single-instance restarts and
blocks horizontal scaling. All three change protocol/management contracts, so doing them before B
keeps the contract surface stable while metrics and roles are layered on.

## Batch B — Operability and contracts

1. **Structured logs and metrics.** Request count, latency (P50/P95/P99), error rate, and the
   answer to "which client/tenant/endpoint is slow", covering the new rate-limit rejections and
   revocation failures. Includes OTLP export from the existing `MONACA_OTLP_ENDPOINT`.
2. **Least-privilege `monaca_app` role.** Tenant pools currently reuse the control database DSN
   (a superuser) for request-path work. The runtime login must be `monaca_app`, granted only the
   org roles it needs; provisioning and migrations keep the admin DSN.
3. **OpenAPI completeness.** `ApiDoc` only registers `/healthz` and `/version`, and
   `packages/sdk` is `export {}`. Register the protocol/management surface and generate the SDK
   from it, with the drift check enforcing both.

Why second: metrics should observe the gates added in A rather than be rewritten around them, and
the DB role change touches provisioning, pools and migrations — after A, those paths have
regression coverage. OpenAPI is a contract artifact; it is cheaper once the A endpoints are final.

## Batch C — Performance

1. **A repeatable benchmark first.** `bun run bench --profile smoke|full` builds a fresh fixture
   through the same CLI/API the acceptance walk-through uses, then measures P50/P95/P99, throughput
   and error rate for `authorize`, `token`, `userinfo`, `management`, the revoked-token `/v1` path
   and the full interactive flow. It also records queries per request (`pg_stat_statements`), a
   rate-limit concurrency ramp, tenant-pool cold/warm behavior at 50/198 tenants, and a
   control-pool vs `monaca_app` comparison. The script is in `scripts/bench/`, the fixture and
   PostgreSQL parameters are fixed per profile, and the CI `bench (smoke)` job runs it on a clean
   Linux runner with a disposable `postgres:18` that preloads `pg_stat_statements`.
2. **Baseline first, optimize only what it names.** The full profile was run on a Windows
   workstation (`docs/bench/results/full-windows-2026-11-04.json`, 200 tenants / 200 created
   accounts / 20 created clients / 1000 iterations; demo also holds the bootstrap admin account
   and the two seeded clients) and the smoke profile on CI
   (`docs/bench/results/smoke-ci-41820073251.json`, 10 tenants / 100 iterations). The 198 extra
   tenant databases are deliberately empty: they exist for the pool section, not for per-tenant
   account volume. Both runs use one server instance, `fsync=off`, `synchronous_commit=off` and
   `max_connections=500`; the numbers are comparative, not a production SLO.

### Results

Full profile, concurrency 1, Windows workstation:

| path | P50 ms | P95 ms | P99 ms | rps | DB queries/request |
|---|---:|---:|---:|---:|---:|
| `authorize` | 4.94 | 8.41 | 16.29 | 169 | 7.0 |
| `token` (`client_credentials`) | 42.31 | 53.18 | 66.84 | 23 | 4.0 |
| `userinfo` | 2.62 | 4.77 | 5.39 | 345 | 5.0 |
| `management` (`GET /v1/accounts?limit=1`) | 3.73 | 6.46 | 15.84 | 232 | 7.0 |
| `management-revoked` | 2.00 | 4.38 | 5.47 | 431 | 3.0 |
| `flow` (authorize → sign-in → code exchange) | 101.03 | 132.65 | 182.69 | 10 | 50.0 |

The Linux CI smoke run is faster in absolute terms (`token` P50 19.1 ms, `management` P50 2.4 ms)
but the query counts are identical.

**Where the queries go** (each path, per request):

* `management` 7: control tenant row, signing keys, client, the caller's roles, revocation lookup,
  rate-limit upsert, and the endpoint's own account read.
* `userinfo` 5: control tenant row, signing keys, revocation lookup, rate-limit upsert, account.
* `token` 4: control tenant row, client, org lookup, rate-limit upsert. The 42 ms is dominated by
  Argon2 verification of the client secret, not by the database.
* `authorize` 7: control tenant row, client, org, redirect URI, interaction INSERT, expired
  interaction DELETE, rate-limit upsert.
* `management-revoked` 3: control tenant row, signing keys, revocation lookup — the revocation
  check returns before the rate gate and the endpoint query.
* `flow` 50: the interactive path dominates. It includes five `interactions` statements, session
  and auth-code writes, org/member/role reads, and the audit-chain head/insert/update in an org
  transaction. The 101 ms is two Argon2 verifications (password and client secret) plus those
  writes.

**Rate-limit hot row** (one tenant counter row, `GET /v1/accounts?limit=1`, 1000 requests per
level):

| concurrency | P50 ms | P99 ms | rps |
|---:|---:|---:|---:|
| 1 | 3.50 | 9.26 | 250 |
| 4 | 3.64 | 7.58 | 974 |
| 16 | 12.86 | 58.53 | 1128 |
| 64 | 46.22 | 69.98 | 1350 |

The knee is at 16 concurrent requests: throughput continues to rise to 64, but P50 grows 13× and
P99 9×. The configured tenant defaults are 600/min (10 rps) and 1200/min for `userinfo`, so normal
traffic is below the knee. The rejection path is cheaper than an accepted request (it returns after
the counter check), which is the desired behavior under abuse.

**Tenant pool** (one public `sign-in-experience` request per tenant, cold then warm):

| tenants | phase s | cold P50/P99 ms | warm P50/P99 ms | warm hit rate | connections | cold / warm connect avg |
|---:|---:|---:|---:|---:|---:|---:|
| 50 | 11.35 | 182.9 / 426.9 | 5.46 / 143.1 | 100% | 102 | 145.1 / 0.0 ms |
| 198 | 138.22 | 344.6 / 678.1 | 414.1 / 682.2 | 32.5% | 127 | 131.0 / 118.9 ms |

The 50-tenant case fits the default cache cap (`MONACA_TENANT_POOL_CACHE=64`) and warms to 5.5 ms
P50. The 198-tenant case does not: the mailer polls every active tenant every 5 s
(`active_tenants` plus one `email_connector` query per tenant), so the 64-entry cache is swept
continuously; the warm pass sees a 32.5% hit rate, 118.9 ms average pool creation, and 414 ms P50.
The phase is also long enough (138 s) that the mailer tick is part of the measurement. This is a
configuration/design issue, not a micro-optimization: either
`MONACA_TENANT_POOL_CACHE` must be at least the active tenant count with `max_connections` sized
for it, or the mailer's all-tenant sweep needs a control-plane connector index (or a negative-cache
TTL). Both change deployment or visibility semantics, so they are not in M0.

**`monaca_app` vs control pool** (mean of two control passes, 300 iterations per scenario):

| scenario | P50 control → app | P50 delta | rps control → app | rps delta |
|---|---:|---:|---:|---:|
| `management` | 3.19 → 2.96 ms | −7.4% | 281 → 257 | −8.6% |
| `authorize` | 2.65 → 2.39 ms | −9.7% | 317 → 359 | +13.3% |
| `token` | 38.18 → 42.06 ms | +10.2% | 26 → 23 | −11.7% |
| `userinfo` | 2.71 → 2.67 ms | −1.3% | 306 → 273 | −10.5% |

The app pool has no material P50 or throughput penalty; P99 differences swing by tens of
milliseconds because 300 samples are noisy. The opt-in role is not a performance reason to keep
the privileged login.

### Optimization decision

**No implementation changed in this batch.** Every candidate the baseline points at either changes
semantics or is outside M0:

* The request-path query count is dominated by freshness-critical lookups: the control tenant row,
  signing keys, client/account/roles, and the revocation row. Caching any of them changes how
  quickly a suspension, key rotation or revocation takes effect; the contract does not authorize
  that, so it is a separate decision, not a silent optimization.
* `token` and `flow` are expensive because of Argon2 client-secret and password verification.
  Weakening or caching that is a security-policy change; the absolute cost (23 rps at one process
  on Windows, 47 rps on the Linux runner) is acceptable for M0.
* `authorize` pays one `DELETE … WHERE expires_at <= now()` per request. Moving it to a periodic
  cleanup would save one of seven queries; not worth a new background task in M0.
* The 198-tenant pool degradation is the mailer sweep plus the 64-pool cap. Fixing it changes
  either the mailer's delivery latency or the connection budget; that is a design decision and is
  recorded above rather than coded here.

**Redis: not for M0.** The shared DB counter is correct and the measured knee (16 concurrent
requests) is above the configured 600/min (10 rps). Redis would add a second failure domain,
credentials, HA and a split-brain story to remove contention that only appears under a burst far
above the enforced limit. Revisit if sustained per-tenant concurrency becomes a product
requirement, or if a future limit is raised by orders of magnitude.

Why last: A and B change the query mix and request instrumentation, so a benchmark taken before
them measures the wrong program. No optimization lands without a before/after number, and no
semantic change lands without a contract decision.

## Not in these batches

Consent/interaction storage beyond the three state tables, per-IP limiting, Redis-backed rate
limiting (the database counter is the M0 shared gate), WAL/PITR, KMS-backed KEK, KMS key rotation,
and a console UI for rate-limit configuration. They are either follow-ups to B/C or require
infrastructure decisions outside this repository.
