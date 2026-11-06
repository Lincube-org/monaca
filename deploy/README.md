# Notes for the VPS that runs mode B (docs/contracts/m0.md §3, §10.4).
#
# Nothing in this directory is a secret. The real `deploy/.env` is written on the host by
# .github/workflows/deploy-dev.yml from the DEPLOY_ENV_FILE secret, mode 0600, and is never
# committed (`.gitignore` covers `.env` and `.env.*`).
#
# The host needs: docker with the compose plugin, and a login that can run it. No Rust, no
# Node, no PostgreSQL — all three live inside the containers.

## First-time setup

    ssh <user>@<host>
    mkdir -p /opt/monaca && cd /opt/monaca
    # compose.dev.yml, remote-deploy.sh and .env are copied by deploy-dev.yml; to bootstrap by
    # hand, copy the two files and write .env yourself:
    scp deploy/compose.dev.yml deploy/remote-deploy.sh <user>@<host>:/opt/monaca/

Then set these repository secrets (Settings → Secrets and variables → Actions):

| secret | required | meaning |
|---|---|---|
| `DEPLOY_HOST` | yes | hostname or IP of the VPS |
| `DEPLOY_USER` | yes | ssh user |
| `DEPLOY_SSH_KEY` | yes | private key for that user (its public half in `~/.ssh/authorized_keys`) |
| `DEPLOY_PORT` | no | ssh port, default 22 |
| `DEPLOY_PATH` | no | directory holding the compose file, default `/opt/monaca` |
| `DEPLOY_ENV_FILE` | no | contents of the deployed `.env` (see below) |

With the three required secrets unset, `deploy-dev.yml` exits 0 having done nothing. That is
the intended behaviour: a contributor who only runs the Vue apps (mode B without a deploy
target) should never see a red workflow.

## The deployed `.env`

`compose.dev.yml` reads it via `--env-file`. It must define at least:

    MONACA_PUBLIC_BASE_URL=https://dev.monaca.example
    POSTGRES_PASSWORD=<generated>
    MONACA_INTERNAL_SECRET=<generated>
    MONACA_DEV_KEK=<64 hex chars>
    MONACA_APP_DB_PASSWORD=<generated>
    MONACA_BOOTSTRAP_ADMIN_PASSWORD=<generated>
    MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET=<generated>
    MONACA_CONSOLE_CLIENT_SECRET=<generated>

Compose fails with an explicit "set POSTGRES_PASSWORD in deploy/.env" message when a required
value is missing, rather than starting a stack with a default credential.

`MONACA_DEV_KEK` is dev-only and the server refuses it unless `MONACA_ENV=dev` (§2.2) — which
is exactly what the compose file sets.

`MONACA_ENV` defaults to `dev` in `compose.dev.yml`. To run the same stack as `prod`, put
`MONACA_ENV=prod` in the deployed `.env` and replace the dev values as well:

    MONACA_KEK=<64 hex chars>
    MONACA_INTERNAL_SECRET=<explicit, not the dev default>
    MONACA_BOOTSTRAP_ADMIN_PASSWORD=<explicit, not the dev default>
    MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET=<explicit, not the dev default>
    MONACA_CONSOLE_CLIENT_SECRET=<explicit, not the dev default>
    # remove MONACA_DEV_KEK entirely

`remote-deploy.sh` checks all of these before it starts anything, and the server repeats the
startup checks (§2.2). The bootstrap secrets are read only when the seeded rows do not exist:
an existing admin password or client secret is never overwritten by a later deploy.

## Owner override: `is_tenant_admin` is CLI-demoted only

The tenant owner override is a boolean on `tenant.accounts`, set only by `bootstrap` or
`tenant create`. There is **no** `/v1` endpoint that clears it: an API token cannot demote the
account it belongs to. This is deliberate — the management API is shared by tenant administrators,
and a self-demotion endpoint would be a privilege-escalation target with no second pair of eyes.

The only off-switch is the offline CLI:

    monaca-server tenant demote-admin --slug <slug> --email <account-email> --dry-run
    monaca-server tenant demote-admin --slug <slug> --email <account-email>

Run it on the same host and with the same `MONACA_ENV`, `MONACA_CONTROL_DATABASE_URL` and
`MONACA_ADMIN_DATABASE_URL` as the server. It requires no management token and does not need the
server to be running. After it succeeds:

1. The account's `/v1` management tier drops to whatever its tenant roles grant; if it holds no
   `monaca:admin` role, its next `/v1` request is `403`.
2. A user token minted before the demotion still carries `monaca:admin` until it expires, but
   `/v1` re-reads the account row on every request, so the scope alone no longer opens the API.
3. Verify with the console Settings page or `GET /v1/me`: `is_tenant_admin` is `false` and
   `management` is the role-derived tier.

**Deployment checklist.** Before closing a decommissioned operator's access, or after a
privileged account changes hands:

- [ ] `tenant demote-admin --dry-run` names the right account.
- [ ] `tenant demote-admin` succeeded.
- [ ] The account's `/v1/me` reports `is_tenant_admin: false` and no `monaca:admin` role.
- [ ] Any remaining access is an explicit tenant role, listed on `GET /v1/me`.
- [ ] Tenant lifecycle changes still go through `tenant suspend|resume|archive`; the API only
      offers the reversible archive/reactivate pair.

The demotion writes `account.tenant_admin_demoted` on the tenant audit chain: actor `tenant`
(the command runs on the owner connection, not as an account), subject the demoted account, and
payload `{"email","via":"cli","before":true,"after":false}`. `--dry-run` writes nothing. Record
the command and its output alongside the operator ticket as well, because the chain proves what
happened but not who ran the shell.

**SAML federation.** A tenant registers a SAML IdP through `POST /v1/saml-connectors` with the
provider's metadata XML. Before accepting it, the server refuses metadata that sets
`WantAuthnRequestsSigned=true` (this SP sends unsigned AuthnRequests and will not silently
downgrade the IdP's requirement), metadata with no HTTP-Redirect SSO endpoint, and metadata with
no signing certificate. Give the IdP the SP metadata at
`https://<host>/t/<tenant>/sso/<connector>/metadata`; its ACS is
`https://<host>/t/<tenant>/sso/<connector>/acs`. `WantAssertionsSigned=true` is advertised and
enforced, so the IdP must sign the Assertion itself, not only the Response.

Operational boundaries: IdP-initiated SSO and SAML Single Logout are not implemented (an
unsolicited POST is refused at the ACS); encrypted assertions are refused; role mapping from the
configured attribute is additive and never grants a role that names `monaca:admin`.

**KEK rotation is an offline, three-step procedure** (§10.7). `MONACA_KEK` derives every tenant
DEK, and sealed signing keys, TOTP seeds, passkey blobs and connector secrets are encrypted under
those DEKs. There is no stored key id: decryption tries the current key first and the retiring key
second.

1. Put the **new** key in `MONACA_KEK` and the old one in `MONACA_KEK_PREVIOUS`, then restart (or
   roll) every server instance. Reads try both; writes use the new key.
2. Run `monaca-server rewrap` (optionally `--tenant <slug>` or `--dry-run`). It walks every sealed
   column and the control-plane `clusters` DSNs, re-seals values that only the old key opens,
   skips values already under the new key, and exits non-zero if any value opens with neither. It
   is idempotent, so an interrupted run is resumed by running it again.
3. Restart with only the new `MONACA_KEK` after `rewrap` reports zero failures.

Not supported: a KMS-hosted KEK, automatic or online rotation, per-ciphertext key ids, and
rotating while an instance still runs with only the old key (that instance would write under the
retiring key). The CI e2e job runs the rotation drill against a disposable database on every
build.

Switching an existing deployment from dev to prod changes the key from `MONACA_DEV_KEK` to
`MONACA_KEK`: use the procedure above with the dev key as `MONACA_KEK_PREVIOUS`, or start from an
empty database.

## Backups and recovery

`remote-deploy.sh` dumps every Monaca database between `pull` and `migrate`. A failed dump aborts
the deploy before the schema changes. Dumps are written to `backups/<UTC stamp>/` (override with
`MONACA_BACKUP_DIR`) and are owner-only. The pg_dump client runs inside the `postgres` container,
so the host does not need PostgreSQL installed. A dump keeps ownership and ACLs by default: an
in-place restore must leave the org roles owning their schemas, or `SET LOCAL ROLE` in the request
path loses access. `--portable` strips both for a restore into a different cluster whose roles do
not exist; restore it with `restore-drill.sh --portable` and expect to provision the roles there
first.

    # what the deploy does, by hand (files are in /opt/monaca on the host)
    bash backup.sh --compose-file compose.dev.yml \
      --db monaca_control --out "backups/$(date -u +%Y%m%dT%H%M%SZ)/monaca_control.dump"

`MONACA_SKIP_BACKUP=1` skips the step and prints a warning; it is for throw-away environments
only, and it is not the default.

A dump is one database. A complete backup is `monaca_control` plus every `mt_*` tenant database;
`remote-deploy.sh` enumerates them from `pg_database`, and a manual backup should do the same.

**Restore drill.** Restore into a fresh database object, then prove the schema replays and the
audit chain still verifies. The default restore keeps the dump's owners and ACLs; pass
`--portable` only for a dump taken with `backup.sh --portable` on another cluster:

    bash restore-drill.sh --compose-file compose.dev.yml \
      --dump backups/<stamp>/monaca_control.dump --target-db monaca_control_drill --recreate

    # Replay the schema and verify an audit chain against the restored copy. `docker compose
    # run` replaces the service command, so the entrypoint sees `audit verify`.
    docker compose -f compose.dev.yml --env-file .env run --rm \
      -e MONACA_CONTROL_DATABASE_URL=postgres://monaca:<password>@postgres:5432/monaca_control_drill \
      migrate
    docker compose -f compose.dev.yml --env-file .env run --rm \
      -e MONACA_CONTROL_DATABASE_URL=postgres://monaca:<password>@postgres:5432/monaca_control_drill \
      -e MONACA_AUDIT_TENANT=demo -e MONACA_AUDIT_ORG=acme \
      migrate audit verify

`audit verify` exits non-zero on the first broken row. For a full drill, restore the tenant
databases too and point `MONACA_AUDIT_*` at one of them.

**Scheduled backups.** `deploy/backup-all.sh` is the recurring backup: it dumps `monaca_control`
plus every `mt_*` database into one timestamped directory, writes a manifest, prunes directories
older than `--retention-days` (or `MONACA_BACKUP_RETENTION_DAYS`, default 14), and exits non-zero
with a `BACKUP FAILED: …` line on any failure. `MONACA_BACKUP_ALERT_COMMAND` is an optional
executable that receives the failure line as its only argument, so a cron job can page. Example
hourly schedule on the deploy host:

    # /etc/cron.d/monaca-backup (run as the compose user)
    17 * * * * root cd /opt/monaca && \
      MONACA_BACKUP_RETENTION_DAYS=14 \
      MONACA_BACKUP_ALERT_COMMAND=/usr/local/bin/monaca-alert \
      bash deploy/backup-all.sh --compose-file deploy/compose.dev.yml \
        --out-dir /opt/monaca/backups >> /var/log/monaca-backup.log 2>&1

A systemd timer works the same way; the command is one shot and exits non-zero, so a failed unit
is visible to the usual `systemctl --failed`/journal alerting. Copy the directory off the deploy
host: a backup in the same failure domain as PostgreSQL is not a backup.

**RPO: the schedule interval, not zero.** There is no WAL archiving and no point-in-time
recovery. With the hourly schedule above, a disaster loses up to one hour plus the dump duration;
without a scheduler, the recovery point is the last deploy's pre-migrate dump, so the gap between
backups is unbounded. `MONACA_SKIP_BACKUP=1` removes even that point for the deploy it covers.

**RTO: one `pg_restore` per database plus `migrate` plus a server start.** The one-command
acceptance restored a near-empty control and tenant database in 1.9 s on the CI fixture; that is
not a production number and no SLO is promised. It is dominated by database size, and the
per-database dumps are sequential, so control and tenants can be a few seconds apart. Run the
drill against a production-sized copy before relying on a figure.

## Least-privilege tenant role (the default)

The request path uses `monaca_app`, not the control owner. `bootstrap` creates or updates the
login as `LOGIN NOINHERIT` with `MONACA_APP_DB_PASSWORD`, revokes `CONNECT … FROM PUBLIC` on every
tenant database, grants it `CONNECT`, `USAGE` and CRUD on the `tenant` schema, and grants it every
org role so `SET LOCAL ROLE` works. `compose.dev.yml` points the server at
`MONACA_APP_DATABASE_URL` and leaves the one-shot `migrate`/`bootstrap` services on the owner DSN.
Tenant and org provisioning (`tenant create`, `POST /v1/orgs`) is the exception: the DDL
(`CREATE DATABASE`, `CREATE SCHEMA`, `CREATE ROLE`, migration sets) runs on
`MONACA_ADMIN_DATABASE_URL`, and the new org's rows are then read through the app pool.

`serve` checks the login before it binds the listener. It fails when:

* `MONACA_APP_DATABASE_URL` is unset and `MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1` was not written
  explicitly (there is no silent fallback to `MONACA_CONTROL_DATABASE_URL`);
* the login does not exist (bootstrap never provisioned it);
* the login is a superuser, or inherits privileges instead of `NOINHERIT`;
* the login cannot open an active tenant database and read `tenant.accounts`.

The CI e2e job runs both refusals (superuser DSN, unprovisioned login) and requires the error to
name the variable and the role. `scripts/verify-app-role.ts` remains the per-tenant proof: it
provisions the role, shows DDL and direct org-schema reads are denied, shows an ungranted
database is unreachable, and starts a real server through the app pool to create and read an
account. The login is deployment-wide: bootstrap grants it every tenant, and the org role
(`SET LOCAL ROLE`) is what separates tenants once a connection is open.
`MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1` is the explicit escape hatch for capacity benchmarks and
throw-away environments; it is not a production default.

Existing deployments that predate this default need a `bootstrap` run (it is idempotent) to
create the role and grants, then a restart. The first provisionment also revokes `CONNECT` from
`PUBLIC` on those tenant databases; other roles that relied on PUBLIC and are not superusers need
an explicit grant.

## Metrics

The server exposes Prometheus text at `/metrics` (§6.4). `compose.dev.yml` also starts a second
listener inside the server container (`MONACA_METRICS_ADDR=0.0.0.0:9090`) and publishes it on the
host **loopback only**:

    http://127.0.0.1:9090/metrics

Scrape it from a Prometheus on the host, or through your own network policy. Do not put it behind
the public origin. `MONACA_METRICS_PORT` changes the host port; the container port stays 9090.
The series are `monaca_http_requests_total`, `monaca_http_request_duration_seconds` (histogram),
`monaca_rate_limit_rejections_total`, `monaca_revoked_token_rejections_total` and the tenant-pool
cache counters. Metrics are per process: scrape every server instance and aggregate in Prometheus
(`sum` for counters, `sum by (le)` for histogram buckets). A single instance's `/metrics` is not a
deployment total.

## Tenant pool connection budget

Tenant pools are cached per database (`MONACA_TENANT_POOL_CACHE`, default 64) and each can open up
to `MONACA_TENANT_POOL_SIZE` connections (default 5). The mailer has its **own** cache over the same
control and provisioning connections (`MONACA_MAILER_POOL_CACHE`, default 128;
`MONACA_MAILER_POOL_SIZE`, default 1), so a sweep cannot evict the request-path working set. The
safe ceiling is:

    max_connections >= MONACA_TENANT_POOL_CACHE × MONACA_TENANT_POOL_SIZE
                    + MONACA_MAILER_POOL_CACHE × MONACA_MAILER_POOL_SIZE
                    + control/admin headroom

At the defaults that is `64 × 5 + 128 × 1 + 7 = 455`, so `compose.dev.yml` starts PostgreSQL with
`max_connections=500`. The measured peak at 400 connector tenants is 129 tenant connections; the
formula is the worst case if every cached pool opens its full quota, not the expected peak.
An external PostgreSQL must set the same headroom. A PostgreSQL `max_connections=100` (the image
default) is below the observed ~128 tenant connections at 100 active tenants; the old all-tenant
mailer stalled a 198-tenant fixture at `max_connections=200`. The request-path cache should cover
the hot tenant working set, not every registered tenant: 400 tenants at pool size 5 would need
2,000 connections if the cache covered them all. The mailer's cache is the one that may be sized
near the connector count, and its one-connection pools are why 128 costs 128, not 640.

## Operating

`remote-deploy.sh` is the deploy itself (postgres ready → pull → backup → migrate → bootstrap → up);
run it by hand on the host when a workflow deploy fails:

    cd /opt/monaca
    MONACA_SERVER_IMAGE=ghcr.io/<owner>/monaca-server:<sha> \
    MONACA_GATEWAY_IMAGE=ghcr.io/<owner>/monaca-gateway:<sha> \
      bash remote-deploy.sh

    docker compose -f compose.dev.yml --env-file .env ps
    docker compose -f compose.dev.yml --env-file .env logs -f gateway

`migrate` and `bootstrap` are one-shot services: `remote-deploy.sh` runs them explicitly
before `up`, and `bootstrap` runs once per deploy (it is idempotent by contract, §5.6). A
server restart therefore never re-provisions.

The gateway publishes `${MONACA_GATEWAY_PORT:-8080}` and is the single public origin. The
server is not published at all: reach it only through the gateway, which is what makes
`MONACA_PUBLIC_BASE_URL` the sole source of every `iss` (§2.1).

TLS is terminated by whatever fronts the host (Caddy, nginx, a cloud load balancer) — that
front end is what turns `MONACA_PUBLIC_BASE_URL` into an `https://` origin, and the gateway
itself speaks plain HTTP inside the network.
