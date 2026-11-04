# `bun run bench`

Repeatable latency/throughput baseline for the M0 request paths, and the source of the numbers in
`docs/roadmap.md` §Batch C.

## One command

```bash
bun run bench --profile smoke     # 10 tenants, 50 accounts, 10 clients, 100 iterations
bun run bench --profile full      # 200 tenants, 200 accounts, 20 clients, 1000 iterations
bun run bench --profile scale --only-pool   # 400 tenant DBs; pool curve at 50/100/200/400
```

Both profiles create their fixtures from an empty database; nothing is reused from `bun run dev` or
the acceptance walk-through. The scenario tenant (`demo`) carries all the accounts and clients;
the extra tenant databases are empty fixtures used only by the pool section, so the pool numbers
measure database count, not per-tenant account volume. The report is
`.monaca/reports/bench-<profile>.json`; pass
`--archive docs/bench/results/<name>.json` to keep a copy in the repository.

`--no-app-role` and `--no-pool` skip the app-pool comparison and tenant-pool phases. `--only-pool`
skips the request paths, ramp and app-pool passes; the `scale` profile uses it because the curve
only needs the tenant fixtures. They exist for debugging one section, not for producing comparable
numbers.

`--all-connectors` gives **every** tenant an enabled HTTP email connector, so the mailer's control
query matches all 400 tenants and the index cannot narrow it; the pool sizes collapse to the single
point `[400]`. This is the worst-case connection scenario, not an optimization target:
`.monaca/reports/bench-scale-all-connectors.json` records the `activation_*_connections` peak.
`--reuse` attaches to the tenant databases a prior `scale` run left in the embedded cluster (`bench-*`
rows in `monaca_control`) instead of provisioning 400 databases again; combine it with
`--profile scale --only-pool` so the fixture is defined by that earlier run.
`--clear-connectors` is its inverse fixture: it deletes every `tenant.email_connector` row and the
control-plane index entry left by an `--all-connectors` run, without re-provisioning the databases.
It is mutually exclusive with `--all-connectors`; together they produce the two comparison fixtures.

## Compare two runs

```bash
bun run bench:compare --baseline docs/bench/results/old.json \
  --candidate .monaca/reports/bench-full.json --threshold 15
```

The comparison covers scenario P50/P95/P99, throughput, error rate and queries per request, the
rate-limit ramp, tenant-pool cold/hot/mixed latency, hit rates, activation connections and mailer
queries, and the app-pool deltas. It prints a table and writes JSON; the exit code is 1 when a
metric moves in the bad direction by more than the threshold. `--warn-only` always exits 0, which is
what the CI `bench` job uses: the comparison is archived and summarized but never blocks a build.
The committed smoke report is the CI baseline; it was produced before the capacity fixes, so a
comparison against it also shows improvements.

## Where it runs

- **Default (workstation or a Linux runner):** the script starts the embedded PostgreSQL package
  under `.monaca/bench/pg` on port 5442, with `pg_stat_statements` preloaded. The cluster is
  disposable; the script drops `monaca_control` and every `mt_*` database before each run.
- **External PostgreSQL:** set `MONACA_BENCH_PG_URL` to an admin DSN whose database is `postgres`,
  for example `postgres://postgres:postgres@127.0.0.1:5440/postgres`. The cluster must be
  **disposable** — the script drops databases in it — and must preload `pg_stat_statements`
  (`shared_preload_libraries=pg_stat_statements`). CI starts exactly such a `postgres:18`
  container; see the `bench` job in `.github/workflows/rust.yml`.
- The server binary is `MONACA_SERVER_BIN`, defaulting to `.monaca/bin/monaca-server{,.exe}` produced
  by `bun run fetch:native`. The benchmark never compiles Rust.

Fixed PostgreSQL parameters for every run (recorded in the report): `fsync=off`,
`synchronous_commit=off`, `full_page_writes=off`, `max_connections=500`, `shared_buffers=256MB`,
`work_mem=8MB`. Durability is off because the cluster is thrown away; the numbers are comparative,
not a production SLO. The connection ceiling is deliberately above the tenant count so the
400-tenant pool phase can finish; the `connections` column still shows how many the fixture
actually holds.

## What is measured

| section | requests |
|---|---|
| `authorize` | `GET /t/demo/oauth2/authorize` without a session (creates an interaction) |
| `token` | `POST /t/demo/oauth2/token`, `client_credentials` with `monaca-admin` |
| `userinfo` | `GET /t/demo/oauth2/userinfo` with a user token minted once |
| `management` | `GET /v1/accounts?limit=1` with a management token (includes the revocation check) |
| `management-revoked` | the same request with a token whose `jti` was revoked; expects `401` |
| `flow` | authorize → interaction sign-in → authorization-code exchange as one operation |
| `rate_limit_ramp` | `GET /v1/accounts?limit=1` at concurrency 1/4/16/64 against one tenant counter row |
| `tenant_pool` | a cold sweep, a 50-tenant hot set, and hot/cold churn at 50/100/200/400 tenants |
| `app_role` | control pass, `monaca_app` pass, control pass again; the same four scenarios |

Every scenario reports P50/P95/P99, throughput, error rate, and (when `pg_stat_statements` is
available) queries per request with the statements grouped by pattern. The mailer's tenant-list and
`email_connector` statements are excluded from the per-request count; they are background work,
not request work.

The tenant-pool phase keeps the extra tenants `provisioning` until the phase starts, waits for the
mailer's first tick, activates the subset being probed, and restores every tenant's previous state
afterwards. It samples `pg_stat_activity` for 6 s after activation (one mailer cycle) and records
the base and peak connection count; then it runs the cold sweep, a hot set (the first 50 tenants,
warmed then measured), and a mixed pass that alternates a hot tenant with a tenant from the cold
remainder. The hot and mixed hit rates are the cache-retention signals; the mixed pass is where an
arbitrary eviction policy loses the working set. `mailer_ticks`, `connector_queries` and
`index_queries` count the poller's statements during the phase.

## Mailer budget

`bun scripts/bench/mailer.ts` measures the delivery loop against the all-connector fixture. It
starts the same embedded cluster, queues one mail per connector tenant, starts the binary named by
`MONACA_SERVER_BIN`, and records the longest tick, the enqueue-to-send latency (P50/P99/max), the
`pg_stat_activity` peak and the delivered count. Run it after
`bun run bench --profile scale --only-pool --all-connectors` has built the fixture:

```bash
MONACA_SERVER_BIN=.monaca/bin/monaca-server bun scripts/bench/mailer.ts \
  --out .monaca/reports/mailer-after.json
```

`--slow-tenant <slug>` makes the mock hold that tenant's delivery past the provider timeout, which
proves one hung provider cannot hold the tick; `--timeout <secs>` caps the wait for the last mail.
The fixture's bench tenants are activated for the run and returned to `provisioning` afterwards.

## Reading the report

- `meta.fixtures` is the fixed data volume and `meta.pg.settings` the fixed PostgreSQL parameters.
- `scenarios[].db.named` is what to follow for an optimization: `revocation_lookup`,
  `rate_limit_counter`, `interaction_state`, `tenant_lookup`, `signing_keys`, `account_lookup`.
- `rate_limit_ramp` is the shared-counter knee: compare P99 and throughput as concurrency rises.
- `tenant_pool[].cold/hot/mixed` are the latency summaries; `hot_pool.hit_rate` and
  `mixed_pool.hit_rate` come from the `monaca_tenant_pool_*` series on `/metrics`.
  `activation_base_connections`/`activation_peak_connections` and the three
  `connections_after_*` values are `pg_stat_activity` samples.
- `app_role.comparison` is the app-pool delta against the mean of the two control passes.

No latency threshold is asserted: results depend on the machine. The script exits non-zero only when
a scenario returns an unexpected status (a correctness failure), not when a percentile moves.

## Limits

- One server instance at a time. The counters on `/metrics` are per process; the shared rate-limit
  test with two processes is e2e step 63, not this benchmark.
- The token endpoint's `client_credentials` grant includes Argon2 secret verification, and the
  interactive flow includes Argon2 password verification; those costs are intentional and part of
  the measurement.
- The benchmark does not measure TLS, a gateway, or a reverse proxy. It addresses the server
  directly.
