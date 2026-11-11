#!/usr/bin/env bash
#
# vulndb-lookup.sh — offline CVE+exploit lookup by software product+version
# =============================================================================
#   Thin wrapper over vulndb_lookup.py. Resolves a product+version (or nmap -sV
#   output) to CVEs with their public exploits, enriched with CVSS/EPSS/KEV,
#   reading the shared SQLite DB read-only. Fully offline once the DB is built.
#
#   This is the OFFLINE sibling of ../vuln/cve-lookup.sh (which queries the live
#   NVD API). Build the DB first with vulndb-build.sh.
# =============================================================================
#
#   DB resolution:  --db FILE  >  $ARSENAL_VULNDB  >  ./vulndb.sqlite  >  <script dir>/vulndb.sqlite
#
#   Examples:
#     ./vulndb-lookup.sh openssh 9.2
#     ./vulndb-lookup.sh --json --min-score 7 "apache http_server" 2.4.49
#     ./vulndb-lookup.sh --cve CVE-2024-6387
#     nmap -sV -oG - host | ./vulndb-lookup.sh --from-nmap --exploitable-only
#
#   Exit: 0 nothing found / 1 vulnerabilities found / 2 error.
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PY="${HERE}/vulndb_lookup.py"

command -v python3 >/dev/null 2>&1 || { echo "[x] python3 is required" >&2; exit 2; }
[[ -f "$PY" ]] || { echo "[x] missing $PY" >&2; exit 2; }

case "${1:-}" in -h|--help) exec python3 "$PY" --help ;; esac

# resolve DB unless caller passes --db
has_db=0; for a in "$@"; do [[ "$a" == "--db" ]] && has_db=1; done
if [[ $has_db -eq 0 ]]; then
    DB="${ARSENAL_VULNDB:-}"
    [[ -z "$DB" && -f "./vulndb.sqlite" ]] && DB="./vulndb.sqlite"
    [[ -z "$DB" ]] && DB="${HERE}/vulndb.sqlite"
    exec python3 "$PY" --db "$DB" "$@"
else
    exec python3 "$PY" "$@"
fi
