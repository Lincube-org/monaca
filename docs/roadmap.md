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

## Not in these batches

Consent/interaction storage beyond the three state tables, per-IP limiting, Redis-backed rate
limiting (the database counter is the M0 shared gate), WAL/PITR, KMS-backed KEK, KMS key rotation,
and a console UI for rate-limit configuration. They are either follow-ups to B/C or require
infrastructure decisions outside this repository.
