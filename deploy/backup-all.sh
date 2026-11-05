#!/usr/bin/env bash
#
# Scheduled backup for every Monaca database (docs/contracts/m0.md §10.7).
#
# `remote-deploy.sh` takes a pre-deploy snapshot. This script is the recurring one: it dumps
# `monaca_control` plus every `mt_*` tenant database into one timestamped directory, prunes
# timestamped directories older than the retention window, and prints a loud failure line (plus
# runs an optional alert command) when any dump fails.
#
#   deploy/backup-all.sh --compose-file deploy/compose.dev.yml \
#     --out-dir backups --retention-days 14
#   deploy/backup-all.sh --container <postgres-container> --out-dir backups
#   deploy/backup-all.sh --dsn <control-dsn> --admin-dsn <postgres-dsn> --out-dir backups
#
# There is no WAL archiving and no PITR: the recovery point is the last successful run, so the
# schedule is the RPO. Run it hourly (see deploy/README.md) and copy the directory off-host.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: backup-all.sh --out-dir <dir>
                     (--container <id|name> | --compose-file <file> [--service <name>]
                      | --dsn <control-dsn> --admin-dsn <maintenance-dsn>)
                     [--db-user <role>] [--retention-days <days>]

  --out-dir          parent of the timestamped backup directories (required)
  --container        running postgres container to docker exec into
  --compose-file     compose file whose postgres service container is used
  --service          compose service name (default: postgres)
  --dsn              control database DSN (host psql/pg_dump mode)
  --admin-dsn        maintenance database DSN used to list databases
  --db-user          role inside the container (default: monaca)
  --retention-days   delete timestamp directories older than this (default: 14; 0 disables)
EOF
}

out_dir=""
container=""
compose_file=""
service="postgres"
db_user="monaca"
dsn=""
admin_dsn=""
retention_days="${MONACA_BACKUP_RETENTION_DAYS:-14}"
alert_command="${MONACA_BACKUP_ALERT_COMMAND:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) out_dir="${2:-}"; shift 2 ;;
    --container) container="${2:-}"; shift 2 ;;
    --compose-file) compose_file="${2:-}"; shift 2 ;;
    --service) service="${2:-}"; shift 2 ;;
    --db-user) db_user="${2:-}"; shift 2 ;;
    --dsn) dsn="${2:-}"; shift 2 ;;
    --admin-dsn) admin_dsn="${2:-}"; shift 2 ;;
    --retention-days) retention_days="${2:-}"; shift 2 ;;
    --alert-command) alert_command="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "backup-all.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$out_dir" ]; then
  echo "backup-all.sh: --out-dir is required." >&2
  usage >&2
  exit 2
fi
case "$retention_days" in
  ''|*[!0-9]*)
    echo "backup-all.sh: --retention-days must be a non-negative integer." >&2
    exit 2
    ;;
esac

modes=0
if [ -n "$container" ]; then modes=$((modes + 1)); fi
if [ -n "$compose_file" ]; then modes=$((modes + 1)); fi
if [ -n "$dsn" ]; then modes=$((modes + 1)); fi
if [ "$modes" -ne 1 ]; then
  echo "backup-all.sh: pass exactly one of --container, --compose-file or --dsn." >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
backup="$script_dir/backup.sh"
if [ ! -f "$backup" ]; then
  echo "backup-all.sh: backup.sh is missing next to this script." >&2
  exit 1
fi

if [ -n "$compose_file" ] && [ -z "$container" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "backup-all.sh: docker is not installed or not on PATH." >&2
    exit 1
  fi
  compose_args=(docker compose -f "$compose_file")
  compose_env="$(dirname "$compose_file")/.env"
  if [ -f "$compose_env" ]; then
    compose_args+=(--env-file "$compose_env")
  fi
  container="$("${compose_args[@]}" ps -q "$service")"
  if [ -z "$container" ]; then
    echo "backup-all.sh: no running container for service '$service'." >&2
    exit 1
  fi
fi

fail() {
  local message="$1"
  echo "BACKUP FAILED: $message" >&2
  if [ -n "$alert_command" ]; then
    if ! "$alert_command" "BACKUP FAILED: $message" >&2; then
      echo "BACKUP FAILED: the alert command itself failed" >&2
    fi
  fi
  exit 1
}

if [ -n "$dsn" ]; then
  if [ -z "$admin_dsn" ]; then
    echo "backup-all.sh: --dsn needs --admin-dsn to list databases." >&2
    exit 2
  fi
  if ! command -v psql >/dev/null 2>&1; then
    echo "backup-all.sh: psql is not installed or not on PATH." >&2
    exit 1
  fi
  databases="$(psql "$admin_dsn" -v ON_ERROR_STOP=1 -tAc \
    "SELECT datname FROM pg_database WHERE datname = 'monaca_control' OR datname LIKE 'mt\\_%' ORDER BY 1")" ||
    fail "could not list databases through --admin-dsn"
  # backup.sh's --dsn mode dumps the DSN's own database, so each database needs its own DSN.
  dsn_base="${dsn%%\?*}"
  source_args=()
else
  databases="$(docker exec -i "$container" psql -U "$db_user" -d postgres -v ON_ERROR_STOP=1 -tAc \
    "SELECT datname FROM pg_database WHERE datname = 'monaca_control' OR datname LIKE 'mt\\_%' ORDER BY 1")" ||
    fail "could not list databases in container '$container'"
  source_args=(--container "$container" --db-user "$db_user")
fi

databases="$(printf '%s\n' "$databases" | sed '/^[[:space:]]*$/d')"
if [ -z "$databases" ]; then
  fail "no monaca_control or mt_* database was found"
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$out_dir/$stamp"
mkdir -p "$target"
umask 077

count=0
for database in $databases; do
  if [ -n "$dsn" ]; then
    dump_args=(--dsn "${dsn_base%/*}/$database")
  else
    dump_args=("${source_args[@]}")
  fi
  if ! bash "$backup" "${dump_args[@]}" --db "$database" --out "$target/$database.dump"; then
    fail "dump of $database into $target failed"
  fi
  count=$((count + 1))
done

printf '%s\n' "$databases" > "$target/manifest.txt"

if [ "$retention_days" -gt 0 ]; then
  removed=0
  while IFS= read -r old; do
    rm -rf "$old"
    removed=$((removed + 1))
  done < <(find "$out_dir" -mindepth 1 -maxdepth 1 -type d \
    -name '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z' \
    -mtime "+$retention_days" 2>/dev/null || true)
  echo "backup-all.sh: removed $removed director(ies) older than $retention_days day(s)"
fi

echo "backup-all.sh: $count database(s) -> $target"
echo "backup-all.sh: RPO is the schedule interval; there is no WAL/PITR."
