#!/usr/bin/env bash
#
# Runs ON the deploy host (docs/contracts/m0.md §10.4). deploy-dev.yml copies this file,
# backup.sh, compose.dev.yml and (when configured) the environment file to $DEPLOY_PATH and then
# runs:
#
#   MONACA_SERVER_IMAGE=ghcr.io/<owner>/monaca-server:<sha> \
#   MONACA_GATEWAY_IMAGE=ghcr.io/<owner>/monaca-gateway:<sha> \
#   bash remote-deploy.sh
#
# It is a file rather than an inline `ssh "…"` string so it can be read, shellchecked and
# re-run by hand on the host when a deploy fails. No arguments, no secrets: everything it
# needs is in the environment or in the sibling `.env`.
#
# Ordering matters and is explicit here rather than left to compose:
#   1. postgres up, and *verified* ready (a running container is still initdb'ing)
#   2. pull the images, so a failed pull cannot leave a migration half-applied
#   3. backup — pg_dump each Monaca database before any schema change (§10.7); a failed backup
#      aborts the deploy
#   4. migrate + bootstrap — one-shot; §5.4 makes `migrate` resumable and §5.6 makes
#      `bootstrap` idempotent, so a retry is safe
#   5. everything else up
#   6. report the resulting state
# `docker compose run` does not reliably wait on a `service_healthy` condition, so step 1 is
# polled with pg_isready instead of assumed.

set -euo pipefail

compose() {
  docker compose -f compose.dev.yml --env-file .env "$@"
}

# Read a deploy setting from the process environment first, then from `.env`, the same order
# compose uses. The last definition wins, matching `--env-file`.
env_value() {
  local name="$1" value
  value="${!name:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi
  if [ -f .env ]; then
    value="$(sed -n "s/^${name}=//p" .env | tail -n 1)"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    printf '%s' "$value"
  fi
}

: "${MONACA_SERVER_IMAGE:?MONACA_SERVER_IMAGE must be set (ghcr.io/<owner>/monaca-server:<sha>)}"
: "${MONACA_GATEWAY_IMAGE:?MONACA_GATEWAY_IMAGE must be set (ghcr.io/<owner>/monaca-gateway:<sha>)}"

if [ ! -f .env ]; then
  echo "remote-deploy: no .env in $(pwd)." >&2
  echo "  deploy-dev.yml writes it from the DEPLOY_ENV_FILE secret; see deploy/README.md." >&2
  exit 1
fi

target_env="$(env_value MONACA_ENV)"
target_env="${target_env:-dev}"

# Fail here, not inside a container that has already rolled the version forward. The server
# repeats these checks at startup (§2.2); doing them first keeps a bad deploy from touching the
# database at all.
case "$target_env" in
  dev|ci) ;;
  prod)
    missing=""
    for name in \
      MONACA_KEK \
      MONACA_INTERNAL_SECRET \
      MONACA_BOOTSTRAP_ADMIN_PASSWORD \
      MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET \
      MONACA_CONSOLE_CLIENT_SECRET
    do
      if [ -z "$(env_value "$name")" ]; then
        missing="$missing $name"
      fi
    done
    if [ -n "$missing" ]; then
      echo "remote-deploy: MONACA_ENV=prod but these variables are missing:$missing" >&2
      echo "  Set them in .env (or the shell environment); see deploy/README.md." >&2
      exit 1
    fi

    kek="$(env_value MONACA_KEK)"
    case "$kek" in
      *[!0-9a-fA-F]*)
        echo "remote-deploy: MONACA_KEK must be 64 hex characters (32 bytes)." >&2
        exit 1
        ;;
    esac
    if [ "${#kek}" -ne 64 ]; then
      echo "remote-deploy: MONACA_KEK must be 64 hex characters (32 bytes), got ${#kek}." >&2
      exit 1
    fi
    if [ -n "$(env_value MONACA_DEV_KEK)" ]; then
      echo "remote-deploy: MONACA_DEV_KEK is set; remove it when MONACA_ENV=prod." >&2
      exit 1
    fi

    for pair in \
      "MONACA_INTERNAL_SECRET=dev-internal-secret-change-me" \
      "MONACA_BOOTSTRAP_ADMIN_PASSWORD=monaca-dev-password" \
      "MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET=dev-admin-client-secret" \
      "MONACA_CONSOLE_CLIENT_SECRET=dev-console-client-secret"
    do
      name="${pair%%=*}"
      dev_default="${pair#*=}"
      if [ "$(env_value "$name")" = "$dev_default" ]; then
        echo "remote-deploy: $name is the documented dev default; set a real value." >&2
        exit 1
      fi
    done
    ;;
  *)
    echo "remote-deploy: MONACA_ENV must be dev, ci or prod (got '$target_env')." >&2
    exit 1
    ;;
esac

echo "remote-deploy: env=$target_env"
echo "remote-deploy: server=$MONACA_SERVER_IMAGE"
echo "remote-deploy: gateway=$MONACA_GATEWAY_IMAGE"

echo "--- 1/6 postgres"
compose up -d postgres

ready=0
for _ in $(seq 1 60); do
  if compose exec -T postgres pg_isready -U monaca -d monaca_control >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "remote-deploy: postgres never became ready" >&2
  compose logs --tail 100 postgres >&2 || true
  exit 1
fi

echo "--- 2/6 pull"
compose pull

echo "--- 3/6 backup"
if [ "${MONACA_SKIP_BACKUP:-0}" = "1" ]; then
  cat >&2 <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! MONACA_SKIP_BACKUP=1: the pre-migrate backup is SKIPPED.
!! A migration that fails from here on has NO restore point from this deploy.
!! This switch exists for a throw-away environment only. Never use it in production.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
else
  if [ ! -f backup.sh ]; then
    echo "remote-deploy: backup.sh is missing next to this script." >&2
    echo "  deploy-dev.yml copies it; refusing to migrate without a backup (§10.7)." >&2
    exit 1
  fi

  backup_dir="${MONACA_BACKUP_DIR:-backups}/$(date -u +%Y%m%dT%H%M%SZ)"
  umask 077
  mkdir -p "$backup_dir"
  echo "remote-deploy: dumping to $backup_dir"

  bash backup.sh \
    --compose-file compose.dev.yml \
    --service postgres \
    --db monaca_control \
    --db-user monaca \
    --out "$backup_dir/monaca_control.dump"

  # Every tenant lives in its own `mt_` database (§5.1). The catalog is the source, not the
  # `tenants` table: a first deploy has not run `migrate` yet, so that table may not exist.
  tenant_dbs="$(compose exec -T postgres psql -U monaca -d monaca_control -tAc \
    "SELECT datname FROM pg_database WHERE datname ~ '^mt_' ORDER BY datname")"
  # Word splitting is intended: one database name per line.
  for db in $tenant_dbs; do
    bash backup.sh \
      --compose-file compose.dev.yml \
      --service postgres \
      --db "$db" \
      --db-user monaca \
      --out "$backup_dir/$db.dump"
  done

  dumps="$(find "$backup_dir" -maxdepth 1 -name '*.dump' -size +0c | grep -c . || true)"
  if [ "$dumps" -lt 1 ]; then
    echo "remote-deploy: no non-empty dump was written; refusing to migrate." >&2
    exit 1
  fi
  echo "remote-deploy: $dumps database dump(s) written"
fi

echo "--- 4/6 migrate + bootstrap"
compose run --rm migrate
compose run --rm bootstrap

echo "--- 5/6 up"
compose up -d --remove-orphans

echo "--- 6/6 state"
compose ps
