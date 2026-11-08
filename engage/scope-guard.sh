#!/usr/bin/env bash
#
# scope-guard.sh — engagement scope allowlist & target gatekeeper
# =============================================================================
#   Keeps automated tooling inside the agreed engagement scope. Every active
#   script should run a target past `scope-guard.sh check <target>` (or pipe a
#   host list through `filter`) before touching it. Exit 0 = in scope.
#
#   This is an opsec/safety control, not a security boundary — it prevents
#   honest mistakes (fat-fingered CIDR, a stray host in a list), not a
#   determined operator. Written authorization still governs what is legal.
# =============================================================================
#
#   Scope file format (one entry per line, # comments):
#     203.0.113.0/24          CIDR range (IPv4)
#     198.51.100.10           single IPv4
#     example.com             domain (also matches *.example.com)
#     app.example.com         exact host
#     !admin.example.com      exclusion (takes precedence over any include)
#     !203.0.113.5            excluded host inside an included range
#
#   Scope file resolution order:
#     1. --scope FILE
#     2. $ARSENAL_SCOPE
#     3. ./.arsenal-scope
#     4. ~/.config/arsenal/scope
#
#   Usage:
#     scope-guard.sh init [FILE]          create a template scope file
#     scope-guard.sh add  <entry>         append an entry
#     scope-guard.sh list                 print active scope
#     scope-guard.sh check <target>       exit 0 if in scope, 1 if not
#     scope-guard.sh filter < hosts.txt   print only in-scope targets (stdin)
#
#   <target> may be an IP, host, host:port, or URL — the host/IP is extracted.
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
SCOPE_FILE=""
QUIET=0

if [[ -t 2 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_DIM=""
fi
# diagnostics go to stderr so `filter`/`check` stdout stays clean for piping
msg()  { [[ $QUIET -eq 1 ]] || printf '%s\n' "$*" >&2; }
ok()   { [[ $QUIET -eq 1 ]] || printf '%s[+]%s %s\n' "$C_G" "$C_RST" "$*" >&2; }
no()   { [[ $QUIET -eq 1 ]] || printf '%s[-]%s %s\n' "$C_R" "$C_RST" "$*" >&2; }
warn() { [[ $QUIET -eq 1 ]] || printf '%s[!]%s %s\n' "$C_Y" "$C_RST" "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

resolve_scope_file() {
    local f
    for f in "$SCOPE_FILE" "${ARSENAL_SCOPE:-}" "./.arsenal-scope" "${HOME}/.config/arsenal/scope"; do
        [[ -n "$f" && -f "$f" ]] && { echo "$f"; return 0; }
    done
    return 1
}

# ---- IPv4 helpers (pure bash) -----------------------------------------------
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

ip_to_int() {  # dotted quad -> 32-bit int (echo), or empty on bad input
    local ip="$1" a b c d
    IFS=. read -r a b c d <<<"$ip"
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || { echo ""; return 1; }
    done
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_in_cidr() {  # <ip> <cidr>  -> return 0 if ip within cidr
    local ip="$1" cidr="$2" net mask bits ipint netint
    net="${cidr%/*}"; bits="${cidr#*/}"
    [[ "$bits" =~ ^[0-9]+$ ]] && (( bits >= 0 && bits <= 32 )) || return 1
    ipint="$(ip_to_int "$ip")"  || return 1
    netint="$(ip_to_int "$net")" || return 1
    if (( bits == 0 )); then return 0; fi
    mask=$(( 0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF ))
    (( (ipint & mask) == (netint & mask) ))
}

# extract the host/IP from an IP | host | host:port | URL
target_host() {
    local t="$1"
    t="${t#*://}"          # strip scheme
    t="${t%%/*}"           # strip path
    t="${t%%\?*}"          # strip query
    t="${t##*@}"           # strip userinfo
    if [[ "$t" == \[*\]* ]]; then t="${t#\[}"; t="${t%%\]*}"      # [ipv6]
    else t="${t%%:*}"; fi  # strip :port
    echo "$t"
}

# resolve a hostname to IPv4s (best effort; empty if unresolved)
resolve_ips() {
    local host="$1"
    if is_ipv4 "$host"; then echo "$host"; return; fi
    if have getent; then getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u; return; fi
    if have python3; then
        python3 -c 'import socket,sys
try:
    print("\n".join(sorted({ai[4][0] for ai in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)})))
except Exception: pass' "$host" 2>/dev/null
        return
    fi
    if have nslookup; then
        nslookup "$host" 2>/dev/null | awk '/^Address: /{print $2}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    fi
}

# does <host> (a domain) match scope entry <e> (domain rule)?
domain_matches() { local host="$1" e="$2"; [[ "$host" == "$e" || "$host" == *".$e" ]]; }

# core decision: is target in scope? echoes matched rule on stdout for `check`
# returns 0 in-scope, 1 out-of-scope
in_scope() {
    local target="$1" sf host ips line entry matched_include="" excluded=""
    sf="$(resolve_scope_file)" || { warn "no scope file found — refusing all (fail-closed)"; return 1; }
    host="$(target_host "$target")"
    ips="$(resolve_ips "$host")"

    while IFS= read -r line; do
        line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
        [[ -z "$line" ]] && continue
        local neg=0; entry="$line"
        [[ "$entry" == !* ]] && { neg=1; entry="${entry#!}"; }

        local hit=0
        if [[ "$entry" == */* ]]; then           # CIDR
            if [[ -n "$ips" ]]; then
                while IFS= read -r ip; do [[ -n "$ip" ]] && ip_in_cidr "$ip" "$entry" && hit=1; done <<<"$ips"
            fi
        elif is_ipv4 "$entry"; then               # single IP
            if [[ -n "$ips" ]]; then
                while IFS= read -r ip; do [[ "$ip" == "$entry" ]] && hit=1; done <<<"$ips"
            fi
            [[ "$host" == "$entry" ]] && hit=1
        else                                      # domain / host
            domain_matches "$host" "$entry" && hit=1
        fi

        if (( hit == 1 )); then
            if (( neg == 1 )); then excluded="$entry"; else matched_include="$entry"; fi
        fi
    done < "$sf"

    if [[ -n "$excluded" ]]; then echo "excluded by: $excluded"; return 1; fi
    if [[ -n "$matched_include" ]]; then echo "in scope: $matched_include"; return 0; fi
    echo "no matching scope rule"; return 1
}

# ---------------------------------------------------------------- subcommands --
cmd_init() {
    local f="${1:-${SCOPE_FILE:-./.arsenal-scope}}"
    [[ -e "$f" ]] && { no "refusing to overwrite existing $f"; return 1; }
    mkdir -p "$(dirname "$f")" 2>/dev/null
    cat > "$f" <<'TEMPLATE'
# Arsenal engagement scope — one entry per line.
#   CIDR:        203.0.113.0/24
#   single IP:   198.51.100.10
#   domain:      example.com        (also matches *.example.com)
#   exact host:  app.example.com
#   exclusion:   !admin.example.com (wins over any include)
#
# Edit before running any active tooling. Entries below are placeholders.
# example.com
# 203.0.113.0/24
# !203.0.113.5
TEMPLATE
    ok "created scope template: $f"
    msg "edit it, then: $SCRIPT_NAME list"
}

cmd_add() {
    local entry="$1" f
    f="$(resolve_scope_file)" || f="${SCOPE_FILE:-./.arsenal-scope}"
    [[ -f "$f" ]] || : > "$f"
    printf '%s\n' "$entry" >> "$f"
    ok "added '$entry' to $f"
}

cmd_list() {
    local f; f="$(resolve_scope_file)" || { no "no scope file found"; return 1; }
    msg "${C_DIM}scope file: $f${C_RST}"
    grep -vE '^\s*(#|$)' "$f" 2>/dev/null || true
}

cmd_check() {
    local target="$1" reason
    reason="$(in_scope "$target")"
    if (( $? == 0 )); then ok "$target — $reason"; return 0
    else no "$target — $reason"; return 1; fi
}

cmd_filter() {  # read targets on stdin, print in-scope ones to stdout
    local t reason
    while IFS= read -r t; do
        t="${t%%#*}"; t="$(echo "$t" | tr -d '[:space:]')"
        [[ -z "$t" ]] && continue
        if reason="$(QUIET=1 in_scope "$t")"; then printf '%s\n' "$t"; else warn "drop $t ($reason)"; fi
    done
}

# --------------------------------------------------------------------- main --
[[ $# -eq 0 ]] && { usage; exit 2; }
# pull out --scope FILE / --quiet from anywhere in the args
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scope) SCOPE_FILE="${2:?}"; shift 2 ;;
        --quiet|-q) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) args+=("$1"); shift ;;
    esac
done
set -- "${args[@]}"
cmd="${1:-}"; shift || true

case "$cmd" in
    init)   cmd_init "${1:-}" ;;
    add)    [[ -z "${1:-}" ]] && { no "add needs an entry"; exit 2; }; cmd_add "$1" ;;
    list)   cmd_list ;;
    check)  [[ -z "${1:-}" ]] && { no "check needs a target"; exit 2; }; cmd_check "$1" ;;
    filter) cmd_filter ;;
    *)      no "unknown command: $cmd"; usage; exit 2 ;;
esac
