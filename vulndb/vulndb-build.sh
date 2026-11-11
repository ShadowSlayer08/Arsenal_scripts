#!/usr/bin/env bash
#
# vulndb-build.sh — build/update the offline CVE+exploit knowledge base
# =============================================================================
#   Thin wrapper over vulndb_build.py (stdlib python3). Fetches public feeds
#   (NVD, CISA KEV, FIRST EPSS, nuclei-templates, Exploit-DB, Metasploit) into a
#   single SQLite file that Arsenal's vulndb-lookup, Mimir, and Crucible share.
#
#   Only queries public data sources; makes no connection to any target.
# =============================================================================
#
#   Requires: python3, curl/network for the initial build (then fully offline).
#
#   Examples:
#     ./vulndb-build.sh                         # exploit/KEV/EPSS/nuclei layer -> ./vulndb.sqlite
#     ./vulndb-build.sh --nvd-keyword openssh   # + version->CVE map for OpenSSH
#     ./vulndb-build.sh --nvd-full              # + full NVD (large; set NVD_API_KEY)
#     ARSENAL_VULNDB=/data/vulndb.sqlite ./vulndb-build.sh --refresh
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PY="${HERE}/vulndb_build.py"

command -v python3 >/dev/null 2>&1 || { echo "[x] python3 is required" >&2; exit 2; }
[[ -f "$PY" ]] || { echo "[x] missing $PY" >&2; exit 2; }

case "${1:-}" in -h|--help) exec python3 "$PY" --help ;; esac

# default DB location unless the caller passes --db
DB_DEFAULT="${ARSENAL_VULNDB:-${HERE}/vulndb.sqlite}"
has_db=0; for a in "$@"; do [[ "$a" == "--db" ]] && has_db=1; done
if [[ $has_db -eq 0 ]]; then
    exec python3 "$PY" --db "$DB_DEFAULT" "$@"
else
    exec python3 "$PY" "$@"
fi
