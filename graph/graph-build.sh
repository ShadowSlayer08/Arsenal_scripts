#!/usr/bin/env bash
#
# graph-build.sh — weave analyser --json into the "red ribbon" knowledge graph
# =============================================================================
#   Thin wrapper over graph_build.py. Consumes the --json output of any Arsenal
#   analyser (and vulndb/cve-lookup) and emits a connected knowledge graph
#   (nodes.jsonl + edges.jsonl + graph.json + manifest.json) that graphify,
#   Mimir, and Crucible can ingest. If a vuln DB is present it auto-enriches CVE
#   nodes with CVSS/EPSS/KEV + public exploits + CWE.
# =============================================================================
#
#   Requires: python3.
#
#   Examples:
#     { arsenal ssl --json host; arsenal http --json host; } | arsenal graph --out ./g
#     arsenal vulndb --json openssh 9.2 | arsenal graph --out ./g
#     arsenal graph --out ./g --vulndb vulndb/vulndb.sqlite results.jsonl
#     arsenal graph --out ./g --format bloodhound results.jsonl
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PY="${HERE}/graph_build.py"

command -v python3 >/dev/null 2>&1 || { echo "[x] python3 is required" >&2; exit 2; }
[[ -f "$PY" ]] || { echo "[x] missing $PY" >&2; exit 2; }
case "${1:-}" in -h|--help) exec python3 "$PY" --help ;; esac

# auto-wire the vuln DB (the red ribbon) if one exists and the caller didn't pass --vulndb
has_db=0; for a in "$@"; do [[ "$a" == "--vulndb" ]] && has_db=1; done
EXTRA=()
if [[ $has_db -eq 0 ]]; then
    for cand in "${ARSENAL_VULNDB:-}" "${ROOT}/vulndb/vulndb.sqlite" "./vulndb.sqlite"; do
        [[ -n "$cand" && -f "$cand" ]] && { EXTRA=(--vulndb "$cand"); break; }
    done
fi
exec python3 "$PY" "${EXTRA[@]}" "$@"
