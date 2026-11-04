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

**KEK rotation is not supported.** `MONACA_KEK` derives every tenant DEK, and sealed signing keys
and account secrets are encrypted under those DEKs. Changing the value silently makes existing
rows unreadable; there is no re-encryption tool in M0. Treat it as a permanent secret (§10.7).

This also applies to switching an existing deployment from dev to prod: the KEK changes from
`MONACA_DEV_KEK` to `MONACA_KEK`, so rows sealed by the old key stop decrypting. Either start
from an empty database, or set `MONACA_KEK` to the exact hex value the existing data was sealed
with (copy the old `MONACA_DEV_KEK`, or `1111…` if that deployment used the built-in fallback)
and only then remove `MONACA_DEV_KEK`.

## Backups and recovery

`remote-deploy.sh` dumps every Monaca database between `pull` and `migrate`. A failed dump aborts
the deploy before the schema changes. Dumps are written to `backups/<UTC stamp>/` (override with
`MONACA_BACKUP_DIR`) and are owner-only. The pg_dump client runs inside the `postgres` container,
so the host does not need PostgreSQL installed.

    # what the deploy does, by hand (files are in /opt/monaca on the host)
    bash backup.sh --compose-file compose.dev.yml \
      --db monaca_control --out "backups/$(date -u +%Y%m%dT%H%M%SZ)/monaca_control.dump"

`MONACA_SKIP_BACKUP=1` skips the step and prints a warning; it is for throw-away environments
only, and it is not the default.

A dump is one database. A complete backup is `monaca_control` plus every `mt_*` tenant database;
`remote-deploy.sh` enumerates them from `pg_database`, and a manual backup should do the same.

**Restore drill.** Restore into a new database, then prove the schema replays and the audit chain
still verifies:

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

**RPO: the last successful pre-deploy dump.** There is no WAL archiving and no point-in-time
recovery. Anything written after that dump is lost in a disaster, and deploys are the only
scheduled dump in M0 — schedule `backup.sh` yourself if that window is too large. Copy the dumps
off the deploy host: a backup in the same failure domain as PostgreSQL is not a backup.

**RTO: one `pg_restore` per database plus `migrate` plus a server start.** It is dominated by
database size and has not been measured for this stack; run the drill against a production-sized
copy before relying on a number. Dumps are sequential per database, so control and tenants can be
seconds apart.

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
