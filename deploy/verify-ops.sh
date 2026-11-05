#!/usr/bin/env bash
#
# One-command operations acceptance (docs/contracts/m0.md §10.7, docs/roadmap.md §Batch H).
#
# Runs the deployment sequence a release actually needs, against a disposable database:
#
#   empty databases -> migrate -> bootstrap -> seed data -> backup -> restore into fresh
#   databases -> migrate/audit-verify -> start and verify -> rotate the KEK -> rewrap ->
#   restart with only the new key -> verify
#
# It calls the real deploy/backup.sh and deploy/restore-drill.sh, so a change to either script
# that breaks a step turns this command red. Any failing step exits non-zero.
#
#   bash deploy/verify-ops.sh --container <postgres-container> [--server-bin <path>]
#
# The container must be a running postgres:18 image (it supplies psql, pg_dump and pg_restore).
# The host needs bash, bun and the monaca-server binary. The script drops and recreates
# `monaca_control` and `mt_demo`: point it at a disposable database only.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v bun >/dev/null 2>&1; then
  echo "verify-ops.sh: bun is not installed or not on PATH." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "verify-ops.sh: docker is not installed or not on PATH." >&2
  exit 1
fi

exec bun "$root/scripts/verify-ops.ts" "$@"
