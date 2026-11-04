#!/usr/bin/env bash
#
# Restore one dump into a NEW database and report what landed (docs/contracts/m0.md §10.7).
#
# This is the first half of the restore drill: restore, then run `migrate` and `audit verify`
# against the result. deploy/README.md has the copy-paste second half.
#
# Passing the same connection options as backup.sh:
#
#   --dump <file> --target-db <name> --container <id|name>
#   --dump <file> --target-db <name> --compose-file <file> [--service postgres]
#   --dump <file> --target-db <name> --dsn <target-dsn> --admin-dsn <maintenance-dsn>
#
# The target database must not exist unless --recreate is passed; --recreate drops it first, so a
# drill can be re-run. Both database names are validated before they are interpolated into SQL.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: restore-drill.sh --dump <file> --target-db <name>
                        (--container <id|name> | --compose-file <file> [--service <name>]
                         | --dsn <target-dsn> --admin-dsn <maintenance-dsn>)
                        [--db-user <user>] [--admin-db <name>] [--recreate]
EOF
}

dump=""
target_db=""
container=""
compose_file=""
service="postgres"
db_user="monaca"
admin_db="postgres"
dsn=""
admin_dsn=""
recreate=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dump) dump="${2:-}"; shift 2 ;;
    --target-db) target_db="${2:-}"; shift 2 ;;
    --container) container="${2:-}"; shift 2 ;;
    --compose-file) compose_file="${2:-}"; shift 2 ;;
    --service) service="${2:-}"; shift 2 ;;
    --db-user) db_user="${2:-}"; shift 2 ;;
    --admin-db) admin_db="${2:-}"; shift 2 ;;
    --dsn) dsn="${2:-}"; shift 2 ;;
    --admin-dsn) admin_dsn="${2:-}"; shift 2 ;;
    --recreate) recreate=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "restore-drill.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$dump" ] || [ ! -s "$dump" ]; then
  echo "restore-drill.sh: --dump must name a non-empty dump file." >&2
  exit 2
fi
if [ -z "$target_db" ]; then
  echo "restore-drill.sh: --target-db is required." >&2
  exit 2
fi
case "$target_db" in
  *[!A-Za-z0-9_]*)
    echo "restore-drill.sh: --target-db must be an unquoted SQL identifier." >&2
    exit 2
    ;;
esac
case "$admin_db" in
  *[!A-Za-z0-9_]*)
    echo "restore-drill.sh: --admin-db must be an unquoted SQL identifier." >&2
    exit 2
    ;;
esac

modes=0
[ -n "$container" ] && modes=$((modes + 1))
[ -n "$compose_file" ] && modes=$((modes + 1))
[ -n "$dsn" ] && modes=$((modes + 1))
if [ "$modes" -ne 1 ]; then
  echo "restore-drill.sh: pass exactly one of --container, --compose-file or --dsn." >&2
  exit 2
fi

if [ -n "$dsn" ]; then
  if [ -z "$admin_dsn" ]; then
    echo "restore-drill.sh: --dsn needs --admin-dsn to create the target database." >&2
    exit 2
  fi
  for tool in psql pg_restore; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "restore-drill.sh: $tool is not installed or not on PATH." >&2
      exit 1
    fi
  done
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "restore-drill.sh: docker is not installed or not on PATH." >&2
    exit 1
  fi
  if [ -z "$container" ]; then
    compose_args=(docker compose -f "$compose_file")
    compose_env="$(dirname "$compose_file")/.env"
    if [ -f "$compose_env" ]; then
      compose_args+=(--env-file "$compose_env")
    fi
    container="$("${compose_args[@]}" ps -q "$service")"
  fi
  if [ -z "$container" ]; then
    echo "restore-drill.sh: no running container for service '$service'." >&2
    exit 1
  fi
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)"
  if [ "$running" != "true" ]; then
    echo "restore-drill.sh: container '$container' is not running." >&2
    exit 1
  fi
fi

# One psql and one pg_restore invocation, whichever route was chosen.
admin_psql() {
  if [ -n "$dsn" ]; then
    psql "$admin_dsn" -v ON_ERROR_STOP=1 "$@"
  else
    docker exec -i "$container" psql -U "$db_user" -d "$admin_db" -v ON_ERROR_STOP=1 "$@"
  fi
}

target_psql() {
  if [ -n "$dsn" ]; then
    psql "$dsn" -v ON_ERROR_STOP=1 "$@"
  else
    docker exec -i "$container" psql -U "$db_user" -d "$target_db" -v ON_ERROR_STOP=1 "$@"
  fi
}

exists="$(admin_psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$target_db'")"
if [ -n "$exists" ]; then
  if [ "$recreate" -ne 1 ]; then
    echo "restore-drill.sh: database '$target_db' already exists; pass --recreate to replace it." >&2
    exit 1
  fi
  admin_psql -c "DROP DATABASE IF EXISTS \"$target_db\"" >/dev/null
fi
admin_psql -c "CREATE DATABASE \"$target_db\"" >/dev/null

echo "restore-drill.sh: pg_restore $dump -> $target_db"
if [ -n "$dsn" ]; then
  pg_restore --no-owner --no-privileges --dbname "$dsn" "$dump"
else
  docker exec -i "$container" \
    pg_restore -U "$db_user" -d "$target_db" --no-owner --no-privileges < "$dump"
fi

tables="$(target_psql -tAc \
  "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')")"
tables="$(printf '%s' "$tables" | tr -d '[:space:]')"
echo "restore-drill.sh: restored $tables table(s) into $target_db"

cat <<EOF

Next, against the restored database:
  1. monaca-server migrate   (MONACA_CONTROL_DATABASE_URL pointing at $target_db)
  2. monaca-server audit verify   (MONACA_AUDIT_TENANT / MONACA_AUDIT_ORG on the restored data)
deploy/README.md "Restore drill" has the exact commands.
EOF
