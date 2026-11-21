#!/usr/bin/env bash
#
# webapp.sh — launch the Arsenal Console (micro web GUI)
# =============================================================================
#   Thin launcher for arsenal-webapp.py: a small local-only console that runs
#   the arsenal analysers from a browser and exports an engagement bundle to
#   Mimir and Crucible. Binds 127.0.0.1 only. Authorized use only.
# =============================================================================
#   Requires: python3.
#   Usage:
#     ./webapp.sh                       # http://127.0.0.1:8733
#     ARSENAL_WEBAPP_PORT=9000 ./webapp.sh
#     ARSENAL_MIMIR_URL=http://host/ingest ARSENAL_CRUCIBLE_URL=http://host/recon ./webapp.sh
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "[x] python3 is required" >&2; exit 2; }
exec python3 "${HERE}/arsenal-webapp.py" "$@"
