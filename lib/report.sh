#!/usr/bin/env bash
#
# report.sh — unified engagement report builder
# =============================================================================
#   Ingests the --json output of any arsenal analyser (one JSON object per line)
#   and renders a single consolidated report as Markdown, CSV, plain text, or
#   merged JSON. Lets a pipeline of independent tools produce one deliverable.
#
#   Each input object is expected to carry (all optional, tolerated if absent):
#     tool      name of the producing tool      ("ssl-audit", "dns-audit", ...)
#     host      target host/ip
#     port      target port
#     problems  array of finding strings        (ssl/ssh/http/dns/... use this)
#     findings  array of finding strings         (alias for problems)
#   Any object lacking findings is reported as "ok".
# =============================================================================
#
#   Requires: python3 (for tolerant JSON parsing).
#
#   Usage:
#     <tool> --json ... | report.sh                       # Markdown to stdout
#     report.sh --format csv results.jsonl > report.csv
#     report.sh --format md  --title "Acme VAPT" a.json b.json > report.md
#     { sslA; sshA; } | report.sh --format txt
#
#   --format  md | csv | txt | json      (default: md)
#   --title   STRING                     report heading (default: Arsenal report)
#   --only-findings                      omit targets with no findings
#
set -uo pipefail

FORMAT="md"
TITLE="Arsenal report"
ONLY_FINDINGS=0
FILES=()

have() { command -v "$1" >/dev/null 2>&1; }
err() { printf '[x] %s\n' "$*" >&2; }

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --format) FORMAT="${2:?}"; shift 2 ;;
        --title)  TITLE="${2:?}"; shift 2 ;;
        --only-findings) ONLY_FINDINGS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) err "unknown option: $1"; usage; exit 2 ;;
        *) FILES+=("$1"); shift ;;
    esac
done

case "$FORMAT" in md|csv|txt|json) ;; *) err "bad --format: $FORMAT"; exit 2 ;; esac
have python3 || { err "python3 required"; exit 2; }

# Gather input: files if given, else stdin.
input() { if [[ ${#FILES[@]} -gt 0 ]]; then cat "${FILES[@]}"; else cat; fi; }

input | TITLE="$TITLE" FORMAT="$FORMAT" ONLY="$ONLY_FINDINGS" python3 -c '
import sys, os, json, csv, io

title = os.environ.get("TITLE", "Arsenal report")
fmt   = os.environ.get("FORMAT", "md")
only  = os.environ.get("ONLY", "0") == "1"

rows = []      # (tool, target, finding)   finding="" means clean
objs = []      # raw parsed objects (for json format)
bad  = 0
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] not in "{[":
        continue
    try:
        obj = json.loads(line)
    except Exception:
        bad += 1
        continue
    items = obj if isinstance(obj, list) else [obj]
    for o in items:
        if not isinstance(o, dict):
            continue
        objs.append(o)
        tool = str(o.get("tool", o.get("source", "?")))
        host = str(o.get("host", o.get("target", o.get("url", "?"))))
        port = o.get("port", "")
        target = f"{host}:{port}" if port not in ("", None) else host
        finds = o.get("problems") or o.get("findings") or []
        if isinstance(finds, str):
            finds = [finds]
        if finds:
            for f in finds:
                rows.append((tool, target, str(f)))
        else:
            if not only:
                rows.append((tool, target, ""))

def severity(f):
    fl = f.lower()
    if any(k in fl for k in ("expired", "mismatch", "no tls", "no supported", "open relay", "anonymous", "no matching", "critical", "sshv1", "empty password")):
        return "high"
    if any(k in fl for k in ("weak", "deprecated", "self-signed", "missing", "not set", "disclos", "expires in")):
        return "medium"
    if not f:
        return "ok"
    return "low"

n_find = sum(1 for r in rows if r[2])
n_tgt  = len({r[1] for r in rows})

if fmt == "json":
    print(json.dumps({"title": title, "targets": n_tgt, "findings": n_find, "results": objs}, indent=2))

elif fmt == "csv":
    w = csv.writer(sys.stdout)
    w.writerow(["tool", "target", "severity", "finding"])
    for tool, target, f in rows:
        w.writerow([tool, target, severity(f), f or "(no findings)"])

elif fmt == "txt":
    print(f"{title}")
    print("=" * len(title))
    print(f"targets: {n_tgt}   findings: {n_find}")
    print()
    cur = None
    for tool, target, f in sorted(rows, key=lambda r: (r[1], r[0])):
        if target != cur:
            print(f"\n[{target}]")
            cur = target
        if f:
            print(f"  ({severity(f):>6}) {tool}: {f}")
        else:
            print(f"  (    ok) {tool}: no findings")

else:  # md
    order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    print(f"# {title}\n")
    print(f"**Targets:** {n_tgt}  |  **Findings:** {n_find}\n")
    if bad:
        print(f"> {bad} input line(s) were not valid JSON and were skipped.\n")
    sev_counts = {}
    for _, _, f in rows:
        if f:
            sev_counts[severity(f)] = sev_counts.get(severity(f), 0) + 1
    if sev_counts:
        print("| Severity | Count |")
        print("| --- | --- |")
        for s in ("high", "medium", "low"):
            if s in sev_counts:
                print(f"| {s} | {sev_counts[s]} |")
        print()
    print("| Target | Tool | Severity | Finding |")
    print("| --- | --- | --- | --- |")
    def esc(x): return str(x).replace("|", "\\|")
    for tool, target, f in sorted(rows, key=lambda r: (order.get(severity(r[2]), 9), r[1])):
        cell = esc(f) if f else "_no findings_"
        print(f"| {esc(target)} | {esc(tool)} | {severity(f)} | {cell} |")

sys.exit(0)
'
