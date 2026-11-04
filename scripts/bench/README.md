# `bun run bench`

Repeatable latency/throughput baseline for the M0 request paths, and the source of the numbers in
`docs/roadmap.md` §Batch C.

## One command

```bash
bun run bench --profile smoke     # 10 tenants, 50 accounts, 10 clients, 100 iterations
bun run bench --profile full      # 200 tenants, 200 accounts, 20 clients, 1000 iterations
```

Both profiles create their fixtures from an empty database; nothing is reused from `bun run dev` or
the acceptance walk-through. The report is `.monaca/reports/bench-<profile>.json`; pass
`--archive docs/bench/results/<name>.json` to keep a copy in the repository.

`--no-app-role` and `--no-pool` skip the app-pool comparison and tenant-pool phases. They exist for
debugging one section, not for producing comparable numbers.

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
`synchronous_commit=off`, `full_page_writes=off`, `max_connections=200`, `shared_buffers=256MB`,
`work_mem=8MB`. Durability is off because the cluster is thrown away; the numbers are comparative,
not a production SLO.

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
| `tenant_pool` | one public `sign-in-experience` request per tenant, cold then warm, at 50 and 198 tenants |
| `app_role` | control pass, `monaca_app` pass, control pass again; the same four scenarios |

Every scenario reports P50/P95/P99, throughput, error rate, and (when `pg_stat_statements` is
available) queries per request with the statements grouped by pattern. The mailer's `active_tenants`
and `email_connector` statements are excluded from the per-request count; they are background work,
not request work.

The tenant-pool phase keeps the extra tenants `provisioning` until the phase starts, waits for the
mailer's first tick, activates only the subset being probed, and deactivates it immediately after.
The phase duration is recorded; if it reaches 4 s a mailer tick could have overlapped.

## Reading the report

- `meta.fixtures` is the fixed data volume and `meta.pg.settings` the fixed PostgreSQL parameters.
- `scenarios[].db.named` is what to follow for an optimization: `revocation_lookup`,
  `rate_limit_counter`, `interaction_state`, `tenant_lookup`, `signing_keys`, `account_lookup`.
- `rate_limit_ramp` is the shared-counter knee: compare P99 and throughput as concurrency rises.
- `tenant_pool[].warm_pool.hit_rate` and `connect_avg_ms` come from the
  `monaca_tenant_pool_*` series on `/metrics`; `connections` is `pg_stat_activity` after the cold
  pass.
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
