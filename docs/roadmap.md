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
  on Windows, 53 rps on the Linux runner) is acceptable for M0.
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

## Batch D — Capacity from the baseline

The C baseline said the 198-tenant pool phase was the capacity risk. This batch only changes
mechanisms whose effect is invisible to a request: the mailer's work list, the pool cache's
eviction order, and the measured connection budget. It does not cache tenant/key/client/role/
revocation data, weaken Argon2, or rewrite the interaction flow.

### Scale curve, before → after

`bun run bench --profile scale --only-pool` on the same Windows fixture: 400 tenant databases, one
server instance, `max_connections=500`, `fsync=off`, 50/100/200/400 active tenants. Before is the
C-era binary; after is the mailer index plus LRU eviction. Full reports:
`docs/bench/results/scale-before-windows-2026-11-04.json`,
`docs/bench/results/scale-after-windows-2026-11-04.json`, and the comparison
`scale-compare-windows-2026-11-04.json`.

| tenants | phase s before → after | cold P50 before → after | hot P50 before → after | hot hit before → after | mixed hit before → after |
|---:|---:|---:|---:|---:|---:|
| 50 | 10.2 → 13.0 | 182 → 237 ms | 1.4 → 1.3 ms | 100% → 100% | n/a |
| 100 | 131.7 → 84.6 | 254 → 235 ms | 130 → 1.5 ms | 65% → 100% | 62.5% → 60% |
| 200 | 208.7 → 113.1 | 460 → 240 ms | 336 → 1.6 ms | 39.3% → 100% | 37.3% → 60% |
| 400 | 304.1 → 171.0 | 459 → 252 ms | 257 → 1.5 ms | 29.2% → 100% | 30.3% → 60% |

Mailer work per phase:

| tenants | connector queries before → after | index/active-list queries | activation peak connections before → after | steady tenant connections |
|---:|---:|---:|---:|---:|
| 50 | 104 → 0 | 1/tick | 20 → 1 | 100 |
| 100 | 1,644 → 0 | 1/tick | 19 → 3 | 128 |
| 200 | 1,358 → 0 | 1/tick | 21 → 0 | 128 |
| 400 | 1,620 → 0 | 1/tick | 24 → 3 | 128 |

The mailer index removes every per-tenant connector query when the tenant has no connector. The
active list is now `tenants_with_email_connector` (one control query per 5 s tick, same as the old
`active_tenants`), not `active_tenants` plus N tenant-database opens. Hot P50 and hit rate improve
by an order of magnitude because the background sweep no longer evicts the 50-tenant working set.

Honest trade-offs:

* **Cold start at 50 tenants is slower** (182 → 237 ms P50) and the cold hit rate drops from 84.6%
  to 50%: the old mailer prewarmed pools as a side effect of scanning every tenant; the index stops
  that. Each request still does two pool lookups (the first creates, the second hits), hence 50%.
* **Mixed at 100 tenants is slower** (114 → 225 ms P50) for the same reason: the hot 50 plus a
  50-tenant churn working set exceed the 64-entry cache, so the churn evicts hot pools. At 200/400
  the mixed P50 improves (342/314 → 233/224 ms) because the old mailer churn was worse. The mixed
  hit rate plateaus at 60% — this is a capacity limit (working set > cache), not an eviction-order
  bug. A deployment whose hot set is 100 tenants needs a larger cache and more connections, not
  just LRU.
* `phase s` and `mailer_ticks` are not comparable across the two reports (the hot/mixed passes
  lengthen the phase); `connector_queries` and the per-pass latency/hit metrics are.

### Connection budget

Observed steady state after the fix: ~2 live tenant connections per cached pool, so 64 cached pools
hold ~128 tenant connections independent of the registered tenant count; the activation step itself
now creates 0–3 (the mailer no longer prewarms). The ceiling depends on both knobs:

    max_connections >= MONACA_TENANT_POOL_CACHE × MONACA_TENANT_POOL_SIZE + control/admin headroom

With the defaults (cache 64, pool size 5) the worst case is 320 + ~12 control/admin. A
`max_connections=100` server is already below the observed 128 at 100 active tenants, and the
C-era all-tenant mailer stalled a 198-tenant fixture at `max_connections=200`. The safe choices are:

* **Keep 5:** `max_connections >= 400` (the dev compose now sets 400).
* **Keep 100–200 connections:** `MONACA_TENANT_POOL_SIZE=2` and a cache of at most ~32–64
  (observed ~2 connections per pool; 64 × 2 + 12 = 140, so 200 is safe).
* **Large tenant counts:** size the cache to the hot working set, not to all tenants. Covering 400
  tenants at pool size 5 would require 2,000 connections.

### What changed

1. **Mailer work list.** Control migration `control_2.sql` adds `tenant_email_connectors`; connector
   writes maintain it and `migrate` reconciles pre-index connectors. The five-second cadence and
   delivery semantics are unchanged. The mailer queries only indexed tenants.
2. **Pool eviction.** The tenant-pool map now records a last-use tick and evicts the least recently
   used entry on a miss; the hit path only updates that entry. Hot hit rate reached 100% at every
   scale point; mixed hit rate improved at 200/400 (37/30 → 60%).
3. **Activation.** Activation of N tenants now creates 0–3 connections; the old 19–24 peak and the
   1,300–1,600 connector queries per phase are gone. No batching code was added because the
   connection slope from activation is flat; the cold sweep still creates one pool per first
   request, which is the real workload.

### Not done (semantic or infrastructure decisions)

* **Tenant row cache:** would delay tenant-state changes (suspension, reactivation, archiving) by
  the TTL; a multi-instance invalidation channel is needed for correctness. Not implemented.
* **Signing-key cache:** would delay a new key in JWKS and therefore token verification by the
  TTL; safe only if rotation is versioned or invalidated. Not implemented.
* **Client/role cache:** would delay secret rotation and permission removal; security-sensitive,
  needs invalidation across instances. Not implemented.
* **Revocation cache:** would delay revocation propagation. The current per-request lookup is
  the contract; not implemented.
* **Argon2 relaxation:** `token` is 23 rps on Windows / 53 rps on Linux because of client-secret
  verification; changing the KDF parameters or caching verified secrets trades security for
  throughput. Not implemented.
* **Flow query reduction:** the interactive path is 50 statements; the interaction read/consume,
  session/auth-code writes, org/role reads and audit chain are all part of the current semantics.
  A merged query set needs a transaction/consistency design, not a benchmark-driven edit.

### Regression check

`bun run bench:compare --baseline <json> --candidate <json> --threshold X` compares scenario
P50/P95/P99, throughput, error rate, queries per request, the rate-limit ramp, pool cold/hot/mixed
latency and hit rates, activation connections, connector queries and app-pool latency. CI runs it
non-blocking against the committed smoke baseline with a 20% threshold, archives the JSON/text and
writes the comparison to the job summary.

## Batch E — Security debt and two capacity questions

Batch D closed the capacity line. This batch fixes an account-takeover path in social sign-in,
checks the neighbouring surfaces for the same class of defect, and re-runs the request-path
profile whose fixtures predate the Batch D mailer. No request-path semantics change.

### Google ID token verification

Before, the Google callback read the `id_token` without checking its signature and took `sub`,
`email` and `email_verified` from the payload. With `auto_link_verified_email`, a forged payload
naming an existing address was enough to sign in as that account. The callback now:

* fetches Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`; the dev/CI mock's
  `/google/jwks` outside production), caches it for one hour per process and serialises refreshes
  behind a mutex;
* refreshes once when the token's `kid` is not in the cached set — the rotation path — and falls
  back to the stale set only when a refresh fails; if no key then matches, the sign-in fails;
* accepts **only** `alg=RS256` before selecting a key, so `none`, `HS256/384/512` and an ES256
  token minted by our own issuer are refused (algorithm confusion). A JWK whose `alg` is not
  RS256 is refused too;
* requires `kid`, `exp` (60 s leeway), `aud` equal to the connector's client id (string or array),
  `iss` one of the two Google spellings, `iat` within [now − 10 min, now + 60 s] and the `nonce`
  minted into the state row;
* builds the identity (`sub`, `email`, `email_verified`, `name`) from the verified token only;
  a boolean `email_verified=true` is required before an unlinked identity may attach to an
  existing address. Google no longer reads userinfo.

GitHub has no equivalent path: it exchanges the code for an access token and reads `/user` plus
`/user/emails`, where only an entry that is both `primary` and `verified` supplies an address. There
is no unsigned token to verify there.

Negative coverage, step 59 unless noted:

| token / request | expected | what it proves |
|---|---|---|
| `alg=none` | 502 | unsigned tokens are refused before key lookup |
| `HS256` signed with public material | 502 | algorithm confusion is closed |
| rogue RSA key under a published `kid` | 502 | the signature is actually checked |
| wrong `aud` | 502 | a token minted for another client cannot be replayed |
| wrong `iss` | 502 | another issuer cannot be substituted |
| `exp` in the past | 502 | expired tokens are refused |
| unknown `kid` | 502 after one refresh | an attacker cannot name an unpublished key |
| `nonce` from another flow | 502 | a captured token cannot be replayed |
| `email_verified=false`, unlinked | 403 `MONACA_SOCIAL_UNLINKED` | no auto-link to an existing address |
| published key added after the cache filled | 302 → token 200 | `kid` rotation works without the TTL |

Unit tests in `monaca-crypto` refuse `none`, `HS256`, an ES256 token under the RS256 verifier and an
unknown `kid` (`cargo test -p monaca-crypto`).

### State/CSRF and link policies

The callback already redeemed a server-side, single-use `state` with a conditional
`UPDATE … WHERE consumed_at IS NULL AND expires_at > now()`, so concurrent or repeated callbacks
have exactly one winner. It now also mints an `HttpOnly`, `SameSite=Lax`, path-scoped
`monaca_social_state` cookie and requires the callback to carry the same id before redeeming the
state. A callback URL copied to another browser is `400` and audited `state_invalid`; a replay is
`400` for the same reason; a wrong/malformed state is `400`. PKCE `S256` and the Google `nonce`
remain part of the same flow. No hole found.

Both binding policies only run for an unlinked provider subject, and both require a verified
address:

* `auto_link_verified_email` links or creates only after `email_verified=true`.
* `confirm_link` parks the interaction and hands out a one-time, expiring token; `POST …/confirm`
  still requires a verified address, refuses a subject already linked elsewhere and finishes the
  sign-in. The token is unguessable, single-use and is the CSRF token for that POST. A disabled
  connector is `404`. The check consumes the token before testing `enabled`, so a disabled
  connector burns a pending confirmation; fail-closed, no bypass, left as is.
* `create_new_only` refuses any existing address with `409 MONACA_SOCIAL_EMAIL_TAKEN`; the
  per-tenant unique `lower(primary_email)` closes the create race.
* An unrecognised `link_policy` string on input falls back to `confirm_link`, not to auto-link.

Residual trust boundary: all three policies trust the configured provider's `email_verified`
assertion. A connector that can assert an arbitrary verified address can still be linked by the
browser that starts the flow. That is why the built-ins only take GitHub's `primary && verified`
entry and Google's verified `id_token`.

### `/internal/*`

Every internal handler now takes an `InternalAuth` extractor as its first argument:
`/internal/audit` (GET and POST), `/internal/tenants/{slug}/jwks`, `/internal/tenants/{slug}/issuer`,
`/internal/health` and (dev/CI only) `/internal/mail`. The extractor runs the shared-secret
comparison with the constant-time byte loop before the path, query or JSON extractors, so an
unauthenticated request with a malformed body is `401`, not `422`, and the endpoint shape stays
hidden. A router middleware was tried first and leaked onto `/mcp/demo` after the internal router
was merged, which is why the authentication is an extractor. CI stage 2 loops every endpoint
without the secret expecting `401`; e2e steps 4 and 4b cover the gateway/server pair. No hole found.

### Request-path profile after the Batch D mailer

The Batch C full profile was captured while the mailer still scanned every tenant. It was re-run
with the `8f1a03e` binary and the same fixtures (200 tenants / 198 extra / 200 accounts /
20 clients / 1000 iterations):
`docs/bench/results/full-after-security-windows-2026-11-04.json`, comparison
`full-compare-after-security-windows-2026-11-04.json`.

| path | P50 before → after | P95 before → after | P99 before → after | rps before → after | DB queries |
|---|---:|---:|---:|---:|---:|
| `authorize` | 4.94 → 3.77 | 8.41 → 6.35 | 16.29 → 8.03 | 169 → 237 | 7.0 → 7.0 |
| `token` | 42.31 → 50.12 | 53.18 → 57.87 | 66.84 → 67.55 | 23 → 20 | 4.0 → 4.0 |
| `userinfo` | 2.62 → 2.84 | 4.77 → 5.26 | 5.39 → 6.25 | 345 → 313 | 5.0 → 5.0 |
| `management` | 3.73 → 3.55 | 6.46 → 5.80 | 15.84 → 6.51 | 232 → 262 | 7.0 → 7.0 |
| `management-revoked` | 2.00 → 1.88 | 4.38 → 3.88 | 5.47 → 4.48 | 431 → 471 | 3.0 → 3.0 |
| `flow` | 101.03 → 102.44 | 132.65 → 117.44 | 182.69 → 124.27 | 10 → 10 | 50.0 → 50.0 |

Queries per request are unchanged; the mailer change is not on the request path. `authorize` and
`management` P99 halved because the background sweep no longer competes for the tenant pool cache.
`token` P50 moved 42 → 50 ms, under the comparison's 20% threshold and inside the Argon2
verification variance (the same path was 19–24 ms on the CI Linux runner). The full report's pool
section is not comparable with Batch C: its schema changed in Batch D, and this run's pool phase
overlapped a local `cargo test`/`tsc`; use the Batch D `scale` report for pool trends.

### All tenants with a connector

The worst case for the control index is every tenant having a connector. `bun run bench --profile
scale --only-pool --all-connectors` builds 400 tenant databases, gives each an enabled HTTP
connector, and measures the 400-tenant pool phase:
`docs/bench/results/scale-all-connectors-windows-2026-11-04.json`.

| metric | value |
|---|---:|
| activation connections, base → peak (6.7 s) | 4 → 25 |
| connections after cold / hot / mixed | 189 / 186 / 110 |
| cold P50 / P99 | 282.9 / 601.4 ms |
| hot P50 / P99, hit rate | 3.4 / 100.9 ms, 98.5% |
| mixed P50, hit rate | 198.0 ms, 70.7% |
| control-index / `tenant.email_connector` statements, 164 s | 3 / 561 |
| errors | 0 |

The index cannot narrow a tenant set in which every row matches: the poller still opens a pool
per tenant every tick, and the 64-entry cache rations what it keeps. The measured connection peak
was **189** (the activation window caught only the first 25; the peak appears after the cold sweep).
That is well below the bench's `max_connections=500` and the dev compose's 400, so the connection
budget is not breached at these defaults. The cost shows up as cadence and latency instead: three
index queries in 164 s means a tick takes tens of seconds, not five; hot P99 spikes to ~100 ms and
mixed P50 is ~198 ms while the poller evicts and reopens pools (the tenant-pool mutex is held across
`connect`).

Configuration advice, without changing semantics:

* Connections: `max_connections >= MONACA_TENANT_POOL_CACHE × MONACA_TENANT_POOL_SIZE + headroom`
  still describes the retained pools (~128 live at cache 64 × size 5). At 400 all-connector tenants
  the observed peak was 189, so a 400-connection ceiling has headroom; do not shrink it to the
  ~128 steady figure.
* Cadence: when the connector count approaches the tenant count, expect the poller's 5 s cadence to
  degrade roughly with N × pool-connect time. Lowering `MONACA_TENANT_POOL_SIZE` reduces live
  connections per pool; raising `MONACA_TENANT_POOL_CACHE` stops the churn but raises retained
  connections to ~2 per pool (not viable for 400 tenants on a 400-connection database). Giving the
  poller its own connection budget or process is a design change outside this batch.
* Latency: the cache mutex is held across pool `connect`, so a churning poller adds cold-request
  P99. Moving the connect outside the lock is a shared-mechanism change, not done here.
  (**Closed in Batch F** — see below.)

## Batch F — pool single-flight, per-IP gate, contract and console

Batch F moves one shared mechanism (the tenant-pool cache) and adds three pieces of surface: a
per-IP request gate, a console page for the existing rate limits, and typed OpenAPI schemas for the
management resources an SDK actually calls. No request-path semantics change.

### Tenant-pool single flight

Before, `Store::tenant_pool` held the cache mutex for the whole `connect`: every lookup for another
tenant waited behind the pool being opened, and a churning workload (the mailer visiting 400
connector tenants) turned that lock into a request-path bottleneck (`lookup_avg_ms` 41 ms on the
cold sweep). Each cache entry now holds an `Arc<tokio::sync::OnceCell<Result<PgPool, StoreError>>>`;
the map lock covers only the lookup and the insertion. The caller that installs the cell runs
`connect` outside the lock; every concurrent caller for the same tenant awaits that one attempt.
When the attempt fails, all of those waiters receive the same error and the entry is removed — a
request that arrives *after* the failure starts a new attempt, so a failing database is not
hammered by a retry burst. In-flight entries are never chosen for LRU eviction, so a concurrent
lookup cannot create a second pool for the same tenant.

The pool DSN, `max_connections`, timeouts and every caller are unchanged. Suspension, key rotation
and revocation are read from the tenant row and tables on each request; none of them is cached in
the pool entry, so the time at which a suspension or revocation takes effect does not move. New
unit tests in `monaca-store` cover one shared attempt for two callers, the same error reaching a
waiter, the failed entry being dropped, and a later request retrying.

Both fixtures below run `bun run bench --profile scale --only-pool --reuse`, 400 tenants, pool size
5, cache 64, on the same Windows host. The four reports are
`docs/bench/results/pool-{before,after}-{regular,all-connectors}-windows-2026-11-05.json`.

| fixture | metric | before | after |
|---|---|---:|---:|
| regular 400 | cold P50 / P99 | 258.4 / 530.2 ms | 315.8 / 911.3 ms |
| regular 400 | hot P50 / P99 | 1.8 / 31.8 ms | 1.7 / 4.6 ms |
| regular 400 | hot / mixed hit rate | 100% / 60% | 100% / 60% |
| regular 400 | mixed P50 | 219.1 ms | 223.6 ms |
| regular 400 | connections after cold/hot/mixed | 128 / 128 / 128 | 128 / 128 / 128 |
| all connectors 400 | cold P50 / P99 | 474.3 / 1728.6 ms | 329.4 / 945.3 ms |
| all connectors 400 | hot P50 / P99 | 6.3 / 148.9 ms | 5.4 / 15.7 ms |
| all connectors 400 | hot / mixed hit rate | 98.1% / 71.0% | 99.0% / 71.5% |
| all connectors 400 | mixed P50 | 285.2 ms | 342.4 ms |
| all connectors 400 | lookup avg, cold/hot/mixed | 41.0 / 4.2 / 35.5 ms | 0.001 / 0.002 / 0.001 ms |
| all connectors 400 | connect avg, cold/hot/mixed | 315.3 / 272.2 / 195.5 ms | 194.5 / 65.3 / 189.1 ms |
| all connectors 400 | phase duration | 297.8 s | 200.4 s |
| all connectors 400 | connections after cold/hot/mixed | 189 / 185 / 108 | 188 / 188 / 128 |

The mechanism being gone shows up in `lookup_avg_ms` (41 → 0.001 ms) and in hot P99 (149 → 15.7 ms
with all 400 connectors active). The mixed phase is a churn test, not a cache-hit test: each
cold request inserts a pool and the LRU eviction that follows removes a hot entry, so roughly half
of the measured hot requests are misses by construction and the p50 tracks `connect` time. Its
+20% move in the all-connector fixture (p95 573.7 → 524.8 ms, p99 671.7 → 677.9 ms) is within the
run-to-run spread of that phase; the warm regular fixture moved 219.1 → 223.6 ms (+2%). Cold
numbers are noisier still (the regular before/after swap direction), because each run's first
sweep opens 400 pools on a machine that also had other work.

### Per-IP request gate

The tenant and client layers count in PostgreSQL so every instance shares them; an IP layer cannot
follow that pattern. There is one row per (address, endpoint) for the whole internet, which would
mean a write on every unauthenticated request and a table whose growth is outside the deployment's
control. The gate therefore counts in a **bounded, per-process** map: fixed 60 s windows,
16,384 entries, oldest window evicted when full, IPv6 keyed by its `/64` network so a client
cannot rotate its interface identifier past the limit. It covers `authorize`, `token` and the
`interaction` POSTs (sign-in, sign-up, consent, abort, MFA and passkey verification), where an
unauthenticated caller can force expensive work; `/v1` remains protected by its admin token and
the tenant/client layers. The default is 600/min and `MONACA_IP_RATE_LIMIT_PER_MINUTE=0` disables
it. It is a flood gate, not a deployment-wide quota: two instances each allow up to the limit. A
rejected request returns the existing `429` + `Retry-After` contract (`MONACA_TOO_MANY_ATTEMPTS`);
the ceiling and the window are exposed on `GET /v1/rate-limits` as `ip`.

`X-Forwarded-For` is attacker-controlled unless the socket peer is a configured proxy.
`MONACA_TRUSTED_PROXY_CIDRS` is the boundary: outside production it defaults to loopback (the dev
and CI gateway is on the same host); in production it defaults to **empty**, and an empty list
means the header is ignored and the peer is the client (with a startup warning). When the peer is
trusted, the header is read right to left, trusted hops are skipped, and the first untrusted address
wins, so a forged value at the left cannot outweigh what the last proxy saw. Unparseable entries are
skipped and an unusable header falls back to the peer. The dev gateway appends the peer address it
observed, so a browser cannot pre-fill the header. IPv4-mapped IPv6 peers are normalised before
matching either an IPv4 CIDR or the bucket key.

Negative and positive coverage: unit tests in `client_ip.rs` (untrusted peer ignores a forged
header, trusted peer adopts it, forged prefix loses to the rightmost address, unparseable header
falls back, IPv4-mapped peer matches an IPv4 network) and in `ip_limit.rs` (per-address and
per-endpoint buckets, window reset, `/64` aggregation); acceptance step 66 reads the configured
limit, sends `limit+1` token requests for a nonexistent tenant from distinct addresses via
`X-Forwarded-For`, and checks the first `404`, the final `429` + `Retry-After`, a different address
still reaching `404`, the same address on `authorize` still reaching `404` (separate bucket), and
the header shape of the `429`.

### Console rate-limit page

`/rate-limits` in the existing console shows the four built-in endpoint defaults
(`authorize`, `token`, `userinfo`, `management`), the per-IP layer and its scope, the configured
tenant/client overrides with add/delete, and the live counters with a `Limited` / `OK` badge and
the retry hint. A save replaces the whole override list, which is the API's semantic; the page
therefore also clears an override by deleting its row. It reads and writes through the existing
BFF (`GET`/`PATCH /bff/api/rate-limits`), uses the shared TanStack Query keys and i18n strings, and
has a mock implementation so the console can be developed without a server. It is reachable from
the sidebar and needs no new deployment knob.

### Typed OpenAPI for the management resources

The document already listed every mounted path; the management resources a third-party SDK
actually provisions were still summary-only. This batch gives 21 operations real request and
response schemas (utoipa `ToSchema` view structs, `IntoParams` for the list query):

| family | operations | why |
|---|---|---|
| accounts | `GET`/`POST /v1/accounts`, `GET`/`PATCH /v1/accounts/{id}` | the user lifecycle every tenant integrates first; `roles` is a typed sub-object |
| roles | `GET`/`POST /v1/roles` | tenant-role provisioning is needed to create accounts with a role |
| sessions | `GET`/`DELETE /v1/accounts/{id}/sessions`, `DELETE …/sessions/{session}` | session/device inventory and revocation is the operation support desks call |
| clients | `GET`/`POST /v1/clients`, `GET`/`PATCH /v1/clients/{client}`, `POST …/secret` | application registration, rotation and the one-time secret response |
| orgs | `GET`/`POST /v1/orgs`, `GET`/`PATCH /v1/orgs/{org}` | tenant-level organization provisioning |
| connectors | `GET`/`POST /v1/connectors`, `PATCH /v1/connectors/{connector}` | social sign-in configuration, including the built-in provider mapping |
| rate limits | `GET`/`PATCH /v1/rate-limits` | the document the console page consumes, now including `ip` and `status` |

Delete operations, membership/invitation/agent/grant/audit/webhook/email/SSO/resource families
keep their summary-only overlay entries; they are the next slice rather than a 70-operation sweep.
`packages/sdk/src/schema.gen.ts` is regenerated from `spec/openapi.json`, so the SDK gains the same
types, and the codegen drift check compares both.

### Mailer cadence at 400 connectors

Not changed in this batch. Today one loop visits tenants sequentially every 5 s
(`POLL_INTERVAL`), claims up to 20 rows per tenant, and posts them one at a time. With all 400
tenants carrying a connector a tick takes ~100 s in the bench (2 ticks in 200 s), and
`MissedTickBehavior::Delay` simply starts the next tick late; delivery latency is unbounded when
the backlog grows. The options, with their real costs:

| option | change | cost | verdict |
|---|---|---|---|
| lower `MONACA_TENANT_POOL_SIZE` | 5 → 2 shrinks each pool's live connections | cuts tenant-request concurrency (bursts queue behind 2 connections) and does **not** remove the 400 sequential visits, so a tick stays ~100 s | emergency lever for a connection ceiling only |
| poller budget | visit tenants with bounded concurrency (8–16) and stop claiming at a per-tick deadline, resuming from a round-robin cursor next tick | needs a connection budget for the concurrent pools (e.g. 16 × 2 = 32 extra), provider rate limits must be respected, delivery order per tenant still FIFO | **recommended**; bounds latency to one deadline + one batch and keeps the connection peak measurable |
| separate poller process/instance | a dedicated worker running `SKIP LOCKED` claims, own pool cache and connection budget | another deployment unit and config surface, still ~128–400 connections, and no benefit at 400 tenants beyond isolating the poller from the request path | do it when tenant count or provider throughput outgrows one worker |

The recommendation is the poller budget first: it is a local change, it preserves `SKIP LOCKED`
semantics for multiple workers, and it turns "a tick takes 100 s" into a declared deadline that
the next tick continues from. `MONACA_TENANT_POOL_SIZE` stays an operational knob, not a fix.

### Verification

Local: `cargo test -p monaca-store` (19 tests, including the three new cache tests),
`cargo clippy --workspace --all-targets` (no new warnings in the changed files),
`bun run typecheck`, `bun test` (329 tests), `bun run build`, and the acceptance walk-through on a
fresh database (68 steps, all pass; the four skips are the `/mcp/demo` steps and the two
restart/multi-instance steps that need environment this local shell does not export). CI is not
run in this batch because the branch was not pushed.

## Batch G — poller budget and KEK rotation

Batch G bounds the mailer tick and makes the KEK rotatable. Both changes are on the mailer and
sealed-data paths; no request-path semantics change.

### Mailer budget

The poller keeps its 5 s interval, but a tick now stops *starting* tenant visits after a 5 s
budget, runs up to 8 visits concurrently, claims each outbox row immediately before its send, and
carries a round-robin cursor across ticks so a tenant that sorts late cannot be skipped forever.
Each provider call has its own 5 s timeout (the shared client's 10 s would let one hung provider
hold a worker for two ticks). A row claimed before the deadline is always attempted, so a
deadline cannot burn an attempt without a provider call; an in-flight visit finishes at most one
pool acquisition (10 s) plus one delivery timeout (5 s) after the budget.

Fixture: the 400-tenant all-connector scale fixture, one queued mail per tenant, embedded
PostgreSQL with durability off, same Windows host. `bun scripts/bench/mailer.ts`; reports are
`docs/bench/results/mailer-before-windows-2026-11-05.json` and
`docs/bench/results/mailer-after-windows-2026-11-05.json`.

| metric | before (sequential loop) | after (8 workers, 5 s budget) |
|---|---:|---:|
| longest tick | 120.1 s | 7.4 s |
| delivery latency P50 | 58.6 s | 46.2 s |
| delivery latency P99 | 117.5 s | 144.1 s |
| delivery latency max | 120.0 s | 149.3 s |
| connections peak | 129 | 124 |
| delivered | 400 / 400 | 400 / 400 |

The tick is now bounded independently of the tenant count; the sweep is not, because every tenant
still pays a pool open. The shared pool cache holds 64 pools while the fixture indexes 400 tenants,
so a sweep re-opens roughly 336 pools, and that cost dominates both binaries. P50 improved; P99
regressed by 23%, which is the honest cost of spreading the same connect work over many small
ticks instead of one long pass. A 16-worker experiment was worse (P99 214.8 s, tick 15.6 s,
381/400 delivered inside 240 s) and is not the configuration kept.

Failure path: holding one tenant's provider for 30 s kept the longest tick at 11.9–17.9 s across
two runs (the block is one pool acquisition plus the 5 s provider timeout, not the 30 s hold), and
the other tenants kept being visited while that row was retried and eventually abandoned at five
attempts. Throughput is lower while a worker is held — 394 of 400 mails in 300 s in the cleaner
run — because one of the eight slots is out of service; the budget bounds the tick, not the total
sweep. The way to improve the sweep is a poller with its own warm pool cache (the
separate-process option), which is the next step when the connector set outgrows the shared
cache.

The connection budget is `(MONACA_TENANT_POOL_CACHE + 8) × MONACA_TENANT_POOL_SIZE + headroom`;
`deploy/README.md` and `compose.dev.yml` carry the formula (360 tenant connections at the
defaults).

### KEK rotation

The KEK derives each tenant DEK by SHA-256, so a rotation re-seals values rather than re-wrapping
a stored DEK. No schema change was needed and none was made: the key reference is **trial
decryption, current key first and the retiring key second**, not a stored key id. AES-GCM's
authentication tag makes a wrong key fail rather than return other plaintext, and two keys is a
bounded, offline-only cost.

`MONACA_KEK_PREVIOUS` keeps the retiring key configured; `monaca-server rewrap` walks every
sealed column (signing keys, `credentials` rows of kind `totp`/`passkey`, pending TOTP
enrollments, social/SSO/email connector secrets, webhooks, the CAPTCHA secret, pending social
state verifiers) plus the control-plane `clusters` DSNs. Each row is opened with either key and
re-sealed under the current one with a compare-and-swap on its previous bytes. A value that
already opens with the current key is skipped, so an interrupted run resumes by being run again;
a value a concurrent writer replaced is skipped, not overwritten; a value that opens with neither
key is reported by table and row and makes the command exit non-zero.

The drill (`scripts/verify-kek-rotation.ts`, wired into the e2e job) creates an account, a TOTP
factor and an email connector under key A, restarts with key B current and A previous, runs
`rewrap`, then restarts with only B. It passed 14 checks: a management token is minted (signing
key), the account still signs in, a locally computed TOTP code completes the flow and mints
tokens (TOTP seed), the mailer delivers a password-reset mail with the connector's bearer secret
(connector secret), and the connector row is readable. `rewrap` moved 5 values (3 tenant + 2
cluster DSNs) with 0 failures; a second run is a no-op by construction.

### Verification

`cargo test -p monaca-crypto -p monaca-store` (51 + 19 tests, including the rotation and
single-flight tests), `bun run typecheck`, the local KEK drill (14/14), and the mailer experiments
above. The pushed Batch F commit's CI is the last full run; Batch G's CI is observed after the
push and reported with the run number.

## Batch H — poller isolation and the rest of the sealed surface

Batch H gives the mailer its own connection budget and cache, exercises every sealed column the
rotation drill previously only walked, and starts the one-command operations acceptance.

### A second tenant-pool cache for the poller

The P99 regression in Batch G was not the tick bound: it was cache churn. The pool cache held 64
pools while the fixture had 400 connector tenants, and the mailer's sweep re-opened ~336 pools
every pass, evicting the request path's working set on the way. `Store::separate_tenant_cache`
builds a second cache over the same control and provisioning pools; the server keeps one for the
request path (`MONACA_TENANT_POOL_CACHE`, 64 × 5) and one for the mailer
(`MONACA_MAILER_POOL_CACHE`, 128 × `MONACA_MAILER_POOL_SIZE`, 1). A poller visit runs its queries
in order, so one connection is enough, and a 128-entry cache keeps that connection through the
visit's three lookups. `MONACA_MAILER_TENANT_CONCURRENCY` defaults to 8 (bounded 1–32).

Fixture and command unchanged: 400-tenant all-connector scale fixture, one queued mail per tenant,
embedded PostgreSQL, same Windows host, `bun scripts/bench/mailer.ts`. The benchmark now warms a
request-path tenant (`demo`) before the sweep and probes it every 200 ms while the mail runs, so
"the sweep did not disturb the hot path" is measured rather than argued. Reports:
`docs/bench/results/mailer-{before,after}-hot-windows-2026-11-05.json`.

| metric | before (Batch G, shared cache) | after (separate cache, 8 visits) |
|---|---:|---:|
| longest tick | 8.1 s | 7.4 s |
| delivery P50 | 46.3 s | 35.2 s |
| delivery P99 | 167.5 s | **106.9 s** |
| delivery max | 328.0 s | 107.4 s |
| hot-path P50 | 2.3 ms | 2.5 ms |
| hot-path P99 | 80.6 ms | **35.4 ms** |
| hot-path max | 488.4 ms | 118.9 ms |
| hot-pool hit rate | 77.7 % | **100 %** |
| connections peak | 122 | 129 |
| delivered | 400/400 | 400/400 |

The before run is the same fixture and the same probe loop against the Batch G binary; its earlier
148 s sweep (without request-path load) is the number in the Batch G table, and it rose to 328 s
once the probe exercised the shared cache. After the split, the sweep completes in 108 s and the
request pool for `demo` never misses. Configurations that were measured and rejected:

| configuration | result | why rejected |
|---|---|---|
| separate cache, 8 visits, poller cache 64 | 306/400 in 300 s, tick 14.8 s | a visit's three lookups race evictions; each visit re-opened pools |
| separate cache, 16 visits, cache 128 | P99 146.8 s, peak 130 | more concurrent pool opens slow each open; no throughput gain |
| separate cache, 4 visits, cache 128 | P99 105.9 s, max 165.4 s | meets P99 but below the requested 8–16 band and a worse tail |
| slow provider held 30 s | tick max 8.5 s, 399/400 in 320 s, hot P99 73 ms | the hang occupies one worker for one delivery timeout per attempt; only the held tenant's row stays unpublished |

The connection formula is now
`MONACA_TENANT_POOL_CACHE × MONACA_TENANT_POOL_SIZE + MONACA_MAILER_POOL_CACHE ×
MONACA_MAILER_POOL_SIZE + headroom` (455 at the defaults), so `compose.dev.yml` starts PostgreSQL
with `max_connections=500`. The measured peak is 129, seven above the Batch G peak: the split did
not buy latency with a connection surge. What did **not** change: the sweep still opens one pool
per tenant (400 per full pass). The remaining reduction needs a poller with a warm, long-lived
connection set or a control-plane pending-mail index; neither is in this batch.

### The sealed surface beyond signing keys and TOTP

`scripts/verify-kek-rotation.ts` now creates a webhook subscription, a GitHub-shaped social
connector, a CAPTCHA configuration and a parked social round-trip under key A, rotates to B with A
previous, re-wraps, then restarts with only B. The drill proves:

* the webhook's signing key produces a valid `x-monaca-signature` before and after the rotation;
* the social connector's client secret is posted to the provider's token endpoint, and the parked
  social state verifier still completes its callback after the re-wrap;
* the CAPTCHA secret is what the server sends to siteverify, and the sign-in still succeeds;
* the email connector secret still delivers a reset mail;
* for seven sealed columns (signing key, TOTP seed, email/social connector secrets, webhook secret,
  CAPTCHA secret, social state verifier) the old KEK opened the bytes before rotation and **fails**
  to open them afterwards, while the new KEK opens them. That is the negative control: the rows
  really moved, rather than both keys happening to work.

The drill passes 36 checks. `rewrap` migrates 8 tenant values plus the 2 cluster DSNs in this
fixture; the additional business flows write the remaining sealed columns.

### One-command operations acceptance

`deploy/verify-ops.sh` (delegating to `scripts/verify-ops.ts`) runs the deployment sequence an
operator otherwise assembles from four scripts: empty database → `migrate` → `bootstrap` → seed an
account and an email connector through the API → `deploy/backup.sh` for the control and tenant
databases → drop and restore both into fresh database objects with `deploy/restore-drill.sh` →
start the server against the restored copy and verify the account and connector → rotate the KEK →
`rewrap` → restart with only the new key → verify again. Any failing step exits non-zero; the
report is `.monaca/reports/ops-verify.json`. It is wired into the CI e2e job after the acceptance
walk-through, so a change to a deploy script that breaks a step turns the job red.

### Verification

`cargo test -p monaca-store -p monaca-server`, the mailer measurements above, the local KEK drill
(36/36), and the CI e2e job (acceptance + KEK drill + ops acceptance). CI run numbers are reported
with the batch summary.

## Batch I — contract truth, production defaults and tenant lifecycle

### The OpenAPI claim, the KEK statement and the phone placeholder

`spec/openapi.json` had 67 paths while the router mounts 106 non-internal paths. The overlay now
registers every mounted path and method outside `/internal/*`: the account self-service surface,
the interaction sub-steps, the public social/SSO callbacks, the alternate discovery path and the
missing role-assignment operation. The generated document is 110 paths / 152 operations, and
`packages/sdk/src/schema.gen.ts` was regenerated from it. The contract (§6.5) now states the
coverage precisely: paths/methods complete outside `/internal/*`, response schemas still
incremental, and `/internal/*` deliberately absent.

`deploy/README.md` said KEK rotation was unsupported. It now describes the real three-step
procedure (new key + `MONACA_KEK_PREVIOUS`, `monaca-server rewrap`, restart with only the new key)
and names what is not supported: a KMS-hosted KEK, automatic/online rotation, per-ciphertext key
ids and rotating while an instance still runs with only the old key.

`account_identifiers.kind` accepted `phone` although no phone flow existed. `tenant.sql` now
allows only `email` and `username`; `tenant_49` replaces the check on existing databases and
raises if a phone row exists instead of deleting data. The control state check gained `archived`
in `control_3`.

### The least-privilege request path is the default

`serve` now requires `MONACA_APP_DATABASE_URL`, and `bootstrap` creates/updates the login
`LOGIN NOINHERIT`, revokes `CONNECT … FROM PUBLIC` on every tenant database, grants the tenant
schema and every org role. Before binding the listener, `serve` proves the login exists, is not a
superuser, is `NOINHERIT`, and can read `tenant.accounts` in an active tenant. The only path back
to the control DSN is `MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1`, written explicitly; there is no
implicit fallback. Administrative subcommands use an internal owner switch, never the environment.

CI runs both refusals (Stage 0d): a superuser DSN exits non-zero naming the variable and "superuser",
and an unprovisioned role exits non-zero naming the variable and the role. The real message from
the local run was:

    MONACA_APP_DATABASE_URL: role `postgres` is a superuser; MONACA_APP_DATABASE_URL must name
    a least-privilege login, not the control or admin DSN
    MONACA_APP_DATABASE_URL: role `missing_app` does not exist; run `monaca-server bootstrap` ...

`deploy/backup-all.sh` is the recurring backup: one timestamped directory with control and every
`mt_*` database, a manifest, retention pruning (`MONACA_BACKUP_RETENTION_DAYS`, default 14) and
a `BACKUP FAILED:` line forwarded to `MONACA_BACKUP_ALERT_COMMAND`. `deploy/README.md` gives an
hourly cron example and the honest recovery numbers: no WAL/PITR, so RPO is the schedule interval
(up to one hour plus dump time with the example, unbounded without a scheduler); RTO was 1.9 s for
the near-empty CI fixture, dominated by database size in production. CI Stage 0e proves both
dumps and a retention prune.

### Tenant lifecycle

`monaca-server tenant create|suspend|resume|archive` is the offline entry point, every subcommand
with `--dry-run`. `create` provisions the tenant, default `acme` org, admin account and two clients
(management and public sign-in) and grants the app login. `suspend` is `active → suspended`;
`resume` is `suspended|archived → active`; `archive` is `active|suspended → archived`. Transitions
from `provisioning` are refused. `archive` disposes of nothing: the database, schemas, data and
audit chains stay, and `resume` reactivates the tenant; there is no delete command.

`AppState::tenant` and `authorize_admin` enforce `active`: suspended is `403
MONACA_TENANT_SUSPENDED`, archived is `403 MONACA_TENANT_ARCHIVED`, provisioning stays `404`. A
management token minted before suspension is refused while the tenant is suspended. Step 67 of
the walk-through creates `life-<id>`, mints a management token, completes a public-client password
sign-in, dry-runs suspend, suspends (both the token and token issuance answer 403), resumes, archives
(403 and database retained), and resumes again; it passed 13 checks locally and in CI.

### Verification

`cargo test -p monaca-store -p monaca-server`, `bun run typecheck`, the local walk-through
(step 67 passed; the other local failures were environment-only: the scratch server did not set
the CAPTCHA/social mocks or the per-IP limit), and the CI e2e job (walk-through, KEK drill and
ops acceptance). CI run numbers are reported with the batch summary.

## Batch J — delivery channels, SMTP and multilingual copy

### What was actually there before the batch

The outbox was email-only and HTTP-only: `tenant.email_connector` held one `http` route, the
mailer posted JSON with an optional bearer and gave up after five attempts. Copy was nine English
strings in Rust plus a per-tenant override row; there was no locale dimension, no invitation mail
and no SMS. The only locale was `sign_in_experience.language`, used for hosted-page copy. The 60 s
verification cooldown lived in `verification_codes.created_at`, not in the shared
`tenant.rate_limit_counters`. This differs from the audit's assumption that a channel abstraction
already existed: the batch creates it rather than extending one.

### The shared layer and the transports

`tenant_50` renames `email_connector` to `delivery_connector` and keys it by channel (`email` /
`sms`), with `(email: http|smtp, sms: http|twilio)` enforced by a check. `control_4` renames the
control index to `tenant_delivery_connectors`; the mailer visits a tenant once and delivers each
configured channel. Email keeps the existing JSON `http` payload and gains SMTP; SMS gets a JSON
`http` gateway and a Twilio-shaped `twilio` transport (form body, basic `sid:token`,
`/2010-04-01/Accounts/<sid>/Messages.json`). SMTP supports `smtps://` (implicit TLS),
`smtp+starttls://` (STARTTLS required) and `smtp://` only on loopback. Both TLS paths use the
default rustls verification; there is no certificate-skip switch and no plaintext non-loopback
relay. Credentials are sealed with the existing tenant-DEK mechanism.

The shared parts are deliberate: one outbox, one claim path, one backoff schedule, one metric
family, and one per-address cooldown in `tenant.rate_limit_counters` (`verification|email|…` and
`sms|verification|…`). The cooldown is now visible to every server instance instead of being a
per-request check on the latest code row. `outbox_claim` increments `attempts` and schedules
`next_attempt_at` at 5/15/45/135 s (capped at 300 s); after five attempts the row is abandoned.
Metrics add `monaca_delivery_sent_total`, `monaca_delivery_failed_total`,
`monaca_delivery_retries_total` (by channel) and `monaca_template_missing_total` (by purpose and
locale).

SMS verification is fail-closed: `POST /t/{tenant}/verification/sms` answers
`503 MONACA_SMS_NOT_CONFIGURED` before minting a code when no enabled SMS route exists. With a
route it writes the same single-use `verification_codes` row (purpose `sms_verification`), queues
topic `sms.verification`, and `POST …/verify` distinguishes wrong/unknown (`401
MONACA_INVALID_VERIFICATION_CODE`), expired (`401 MONACA_VERIFICATION_CODE_EXPIRED`) and
exhausted (`429`).

### Multilingual copy

Built-in copy now lives in `crates/monaca-store/templates/{en,zh-cn}.json` and is seeded into
`message_templates` by `apply_tenant`; tenant edits live in `message_template_overrides` keyed by
`(purpose, locale)`. Every send resolves user locale → tenant default → `en`, taking an override
before the built-in row at each step. A purpose missing at every level fails `500
MONACA_TEMPLATE_MISSING` naming the purpose and requested locale; there is no English placeholder
and no empty body. Eleven purposes have both languages, including `invitation` and
`sms_verification`; the legacy `/v1/email-templates` surface keeps its nine-purpose English view,
and `/v1/message-templates` exposes the locale-aware list, override writes, built-in removal
(`?builtin=true`) and restore. Accounts store an optional `locale` (set at sign-up or
`PATCH /t/{tenant}/account`); the invitation body and the SMS request accept one too.

### Verification

Steps 68–70 were added to the walk-through and run against local captures:
`scripts/sms-capture.ts` receives the Twilio form and `scripts/smtp-capture.ts` receives the
raw SMTP message. The run is **72 steps** (69 before the batch, plus three) with the same two
gateway-only skips (4/4b); the new steps pass 8, 6 and 6 checks. The generated OpenAPI document is
now 116 paths / 161 operations, and the five new audit actions have their own event schemas. CI
numbers are reported with the batch summary.

The missing-template negative control returns, verbatim:

    status 500
    {"type":"https://monaca.dev/errors/template_missing","title":"Message template missing",
     "status":500,"detail":"template `sign_up` is missing for locale `en` (tried: en)",
     "monaca_error_code":"MONACA_TEMPLATE_MISSING"}

Known limits: the offline providers prove the wire shape, not a real Twilio/SMTP account; SMTP
TLS is implemented with rustls/webpki but no live TLS relay was exercised in CI; SMS is a
verification channel, not a sign-in identifier (accounts still identify by email/username).

## Batch K — operator disposal and real session revocation

### What was actually there before the batch

The audit marked account suspension and session management as done, and the endpoints existed —
but their effect stopped at the database row. `authorize_admin` verified the signature, `jti` and
`monaca:admin`, then loaded the account only to check `is_tenant_admin`; a `disabled` operator's
access token kept working on `/v1` until `exp`. `userinfo` checked the account state but not the
session. `DELETE /v1/accounts/{id}/sessions/{session}` only set `sessions.revoked_at`: the
refresh token had no link to its session, so the kicked browser could rotate a new access token.
There was no administrative delete at all; the self-service mail-code flow was the only path.
Step 23 asserted the cookie and refresh failures but never tried the already-issued access token.

### Session binding

`tenant_51` adds `refresh_tokens.session_id` (nullable, so rows issued before the migration keep
their normal expiry) and a partial index on live rows. Authorization-code and refresh exchanges
pass the session through `issue_refresh`, so every refresh token remembers the browser that
created it. `AccessTokenClaims` gains an optional `sid` claim, absent on client-credentials and
agent tokens.

Three verifiers now consult it:

* `/v1` — `authorize_admin` loads the account before the scope check, refuses a non-`active`
  account and a revoked/expired `sid` session with `401 MONACA_UNAUTHORIZED`;
* `userinfo` — the same account check it already had, plus the session check, as
  `401 invalid_token`;
* introspection — a dead account or session answers `active:false` for both access and refresh
  tokens.

The refresh exchange also re-checks the session, so a rotation racing a kick cannot mint. Suspension
continues to revoke every session and refresh token; reactivation restores new sign-ins but the
withdrawn tokens stay dead because their session rows remain revoked.

### Administrative delete

`DELETE /v1/accounts/{id}` has two deliberate steps. `?dry_run=true` reports the live session and
refresh-token counts and the exact confirmation string; a real call requires
`?confirm=<the account's email>`, and a missing or mismatched value is
`400 MONACA_CONFIRMATION_REQUIRED`. Self-deletion and deleting the last active tenant
administrator are refused. The confirmed call reuses the self-service store path: disable, revoke
sessions and refresh tokens, drop the account's grants, agents and memberships per org, then delete
the tenant row; audit rows are never removed, and `account.deleted` is appended with
`self_service:false`, the operator's actor chain and the revocation counts. Both session handlers
now revoke the matching refresh tokens too, so a kick ends renewal, and `DELETE …/sessions` reports
`{"revoked":n,"refresh_revoked":n}`.

### Verification

Step 23 gained three checks: the pre-suspension access token is `401 MONACA_UNAUTHORIZED` on `/v1`
and `401 invalid_token` on `userinfo`, and it stays refused after reactivation (12 checks total).
Step 71 covers disposal (9 checks: dry-run counts, account kept, missing and mismatched
confirmation, delete counts, `404`, dead access token, dead refresh token, audit still present).
Step 72 covers kick-out (12 checks: two visible sessions, one `204` kick, exactly one browser
dead, the other alive, both introspection answers, renewal refusal, revoke-all counts, both
browsers dead, empty list). The run is **74 steps** (72 before the batch, plus two) with the same
two gateway-only skips (4/4b). The OpenAPI document keeps 116 paths and gains one operation
(162 total); `schema.gen.ts` is regenerated. CI numbers are reported with the batch summary.

Known limits: the per-request account/session lookups mean `/v1`, `userinfo` and introspection now
read the tenant database on every call (they already did for jti/account checks); no cache is
introduced. Multi-instance behaviour is database-backed, so a kick applies to every instance
immediately, but it was exercised on one server plus the two-process rate-limit steps, not on a
separate multi-instance deployment. Tenant-chain audit remains readable only through
`/internal/audit`; a management-API audit reader is still a gap.

## Batch L — operator audit, issued scopes and the liveness read

### Tenant audit is readable from the management API

`GET /v1/audit` reads the tenant chain, which previously had no reader outside
`/internal/audit`: `account.suspended`/`account.deleted`, message-template overrides, connector
writes and the sign-in/experience switches were invisible to an operator. The filters are
`action` (exact), `action_prefix` (anchored and escape-safe: `_` and `%` are data, not LIKE
wildcards), `actor` (any typed id in the chain, matched with `jsonb_path_ops` containment),
`subject` (the canonical `subject.id`), `from`/`to` (RFC 3339, `from` inclusive and `to`
exclusive) and the `before` sequence cursor. A page is clamped to **200 rows** and the response
states the effective `limit` and the filtered `total`, so a client can never ask for the whole
table and still learns how much it has to page through. The org list now returns the same
envelope (`items`, `next`, `limit`, `total`, `head`). `tenant_52` adds the subject and actor
indexes; the action and time indexes already existed.

A read appends no event: both handlers only select, and the acceptance step compares `head.seq`
and `total` across consecutive reads. Non-admins are refused by the same `authorize_admin`
path as every other `/v1` call, with `403 MONACA_INSUFFICIENT_SCOPE`.

### `monaca:admin` is dropped at issuance

The contract said a non-admin's requested `monaca:admin` was silently dropped, but the code
issued it and relied on `/v1` to refuse. The design intent is the contract's: a token should not
carry a capability its subject cannot exercise, and RFC 6749 §3.3 explicitly allows the server
to narrow the granted scope. Authorization-code and refresh exchanges now filter
`monaca:admin` out unless `is_tenant_admin` is true; the refresh path re-evaluates the flag on
every rotation, so a demoted administrator does not get the scope back. `/v1` still re-checks
the flag on every request, because a token minted before a demotion keeps the scope until it is
rotated. Impact: a non-admin token that asks for `monaca:admin` now reports the narrower scope
and gets `403` for the missing scope; the automation client is unchanged (its scopes come from
its registration); no schema or error-code change was needed, and the OpenAPI document was
regenerated unchanged.

### The liveness read

Before this batch, a user token on `/v1` paid for an account row, a session existence check and
the revoked-`jti` lookup as separate round-trips; `userinfo` paid for the account and session
rows; introspection paid for `jti`, account and session. `account_liveness` now answers all of
it in one primary-key statement: the account columns `userinfo` renders plus
`session_live = ($sid IS NULL OR EXISTS live session)` and
`token_revoked = ($jti IS NOT NULL AND EXISTS revoked jti)`. `/v1`, `userinfo` and introspection
call it once; automation tokens (no account row) keep the narrow `jti` lookup.

The measurement is the same `smoke` profile on the same machine, before and after the change.
Before (one run), request paths at concurrency 1:

| scenario | p50 ms | p95 ms | p99 ms | queries/request |
|---|---|---|---|---|
| management (automation) | 4.26 | 5.92 | 6.40 | 7 |
| management-user (account+sid) | 5.01 | 6.71 | 7.29 | 8 |
| userinfo | 3.25 | 4.71 | 5.46 | 6 |
| introspect | 37.99 | 42.76 | 45.98 | 6 |

After (two runs; the first showed a noisy `userinfo`, the second is quoted and the range is in
the report):

| scenario | p50 ms | p95 ms | p99 ms | queries/request |
|---|---|---|---|---|
| management (automation) | 3.14–4.43 | 5.05–6.91 | 5.81–8.32 | 7 |
| management-user | 2.83–2.92 | 4.57–4.95 | 5.54–6.04 | 6 |
| userinfo | 2.54–3.37 | 4.14–5.09 | 4.39–6.78 | 5 |
| introspect | 35.22–36.15 | 39.62–41.79 | 41.12–43.15 | 4 |

The pool/app-role pass shows the same direction: `management-user` p99 9.31 vs 6.35 ms
(-31.7%) and `userinfo` p99 7.41 vs 5.93 ms (-20.0%) on the second after run. Query counts
drop by two for `management-user` and introspection and by one for `userinfo`; the smaller
latency gain on introspection is because its p95 is dominated by client-secret hashing, not by
the three lookups.

No cache, TTL or eventual-consistency window was introduced. Every revocation question is
answered by the same row the write committed, so the delay after a session kick or a disable is
**zero**: the next request that starts after the transaction commits observes it, on any
instance. Step 74 probes `userinfo`, renewal and introspection immediately after the write with
no sleep. A cross-instance deployment was not exercised beyond the existing two-process
rate-limit steps; the bound is a database-visibility argument, not a load-test result.

### Verification

Steps 73 and 74 were added; the run is **76 steps** (74 before the batch, plus two) with the
same two gateway-only skips (4/4b). Step 73 passes 14 checks, step 74 passes 10. The OpenAPI
document is 117 paths / 163 operations; `schema.gen.ts` is regenerated. CI numbers are reported
with the batch summary.

Known limits: the audit `total` is a second `count(*)` over the filtered set; it is indexed for
the filters but still linear in the matching rows. `action_prefix` is anchored only (no
substring search). The liveness row includes the account's profile columns because `userinfo`
renders them; a narrower `/v1`-only query would be possible if `userinfo` ever stopped reading
the row. Bench numbers come from the embedded PostgreSQL fixture, not a production-sized audit
table.

## Not in these batches

Consent/interaction storage beyond the three state tables, Redis-backed rate limiting (the
database counter is the M0 shared gate), WAL/PITR, KMS-backed KEK, KMS key rotation. Per-IP
limiting and a console UI for rate-limit configuration moved into Batch F above. The rest are
either follow-ups to B/C or require infrastructure decisions outside this repository.
