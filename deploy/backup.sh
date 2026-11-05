#!/usr/bin/env bash
#
# Dump one Monaca database (docs/contracts/m0.md §10.7).
#
# Three ways to reach PostgreSQL, exactly one required:
#
#   --dsn postgres://user:pass@host:port/db    pg_dump from this machine
#   --container <id|name>                      docker exec into a running container
#   --compose-file <file> [--service postgres] docker exec into the compose service's container
#
# --out is always required. The dump is `pg_dump --format=custom`, including ownership and ACLs:
# an in-place disaster restore needs the org roles to own their schemas, or `SET LOCAL ROLE` in the
# request path loses access. `--portable` strips owners and privileges for a restore into a
# different cluster whose roles do not exist. The script exits non-zero when pg_dump fails, when
# the dump is empty, or when the requested client tools are absent.
#
# Example, a host with the PostgreSQL client:
#
#   deploy/backup.sh --dsn "postgres://monaca:…@db:5432/monaca_control" \
#     --out backups/$(date -u +%Y%m%dT%H%M%SZ)/monaca_control.dump
#
# remote-deploy.sh calls this with --compose-file before every migrate.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: backup.sh --out <file> (--dsn <url> | --container <id|name> | --compose-file <file>)
                 [--service <name>] [--db <name>] [--db-user <user>] [--portable]

  --out           destination dump file (required)
  --dsn           host pg_dump connection string
  --container     running container to docker exec into
  --compose-file  compose file whose service container is used
  --service       compose service name (default: postgres)
  --db            database to dump (default: monaca_control)
  --db-user       role for the container dump (default: monaca)
  --portable      strip owners and ACLs for a restore into a different cluster
EOF
}

dsn=""
out=""
container=""
compose_file=""
service="postgres"
db="monaca_control"
db_user="monaca"
portable=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dsn) dsn="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --container) container="${2:-}"; shift 2 ;;
    --compose-file) compose_file="${2:-}"; shift 2 ;;
    --service) service="${2:-}"; shift 2 ;;
    --db) db="${2:-}"; shift 2 ;;
    --db-user) db_user="${2:-}"; shift 2 ;;
    --portable) portable=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "backup.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

dump_flags=(--format=custom)
if [ "$portable" -eq 1 ]; then
  dump_flags+=(--no-owner --no-privileges)
fi

if [ -z "$out" ]; then
  echo "backup.sh: --out is required." >&2
  usage >&2
  exit 2
fi

sources=0
if [ -n "$dsn" ]; then sources=$((sources + 1)); fi
if [ -n "$container" ]; then sources=$((sources + 1)); fi
if [ -n "$compose_file" ]; then sources=$((sources + 1)); fi
if [ "$sources" -ne 1 ]; then
  echo "backup.sh: pass exactly one of --dsn, --container or --compose-file." >&2
  exit 2
fi

if [ -d "$out" ]; then
  echo "backup.sh: --out is a directory: $out" >&2
  exit 2
fi
mkdir -p "$(dirname "$out")"
# A dump contains password hashes and plaintext outbox rows; keep it owner-only.
umask 077

if [ -n "$dsn" ]; then
  if ! command -v pg_dump >/dev/null 2>&1; then
    echo "backup.sh: pg_dump is not installed or not on PATH." >&2
    echo "  Install the PostgreSQL client tools (postgresql-client-18 for a v18 server)," >&2
    echo "  or use --container/--compose-file to dump from inside the postgres container." >&2
    exit 1
  fi
  echo "backup.sh: pg_dump $db -> $out"
  if ! pg_dump "${dump_flags[@]}" --file "$out" "$dsn"; then
    echo "backup.sh: pg_dump failed; removing the incomplete dump." >&2
    rm -f "$out"
    exit 1
  fi
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "backup.sh: docker is not installed or not on PATH." >&2
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
    echo "backup.sh: no running container for service '$service' in '$compose_file'." >&2
    exit 1
  fi
  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)"
  if [ "$running" != "true" ]; then
    echo "backup.sh: container '$container' is not running." >&2
    exit 1
  fi

  echo "backup.sh: docker exec $container: pg_dump $db -> $out"
  if ! docker exec -i "$container" \
    pg_dump -U "$db_user" -d "$db" "${dump_flags[@]}" > "$out"
  then
    echo "backup.sh: pg_dump failed inside '$container'; removing the incomplete dump." >&2
    rm -f "$out"
    exit 1
  fi
fi

if [ ! -s "$out" ]; then
  echo "backup.sh: the dump is empty; treating it as a failure." >&2
  rm -f "$out"
  exit 1
fi

echo "backup.sh: wrote $out ($(wc -c < "$out" | tr -d ' ') bytes)"
