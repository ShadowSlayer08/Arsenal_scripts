#!/usr/bin/env bash
#
# http-audit.sh — HTTP security-header, cookie & exposure analyser
# =============================================================================
#   Fetches a URL (read-only, like a browser) and reports on:
#     * security headers  — HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
#                            Referrer-Policy, Permissions-Policy, COOP/COEP
#     * cookies           — Secure / HttpOnly / SameSite flags
#     * transport         — HTTP->HTTPS redirect enforcement, redirect chain
#     * disclosure        — Server / X-Powered-By version banners
#     * exposure          — well-known sensitive paths (.git, .env, backups, ...)
#   Only GET/HEAD requests are made. Assess sites you are authorized to.
# =============================================================================
#
#   Requires: curl.
#
#   Quick start:
#     ./http-audit.sh example.com
#     ./http-audit.sh https://example.com/app
#     ./http-audit.sh -f urls.txt
#     ./http-audit.sh --json example.com
#     ./http-audit.sh --no-probe example.com        # skip sensitive-path probes
#
set -uo pipefail

TIMEOUT=10
JSON=0
DO_PROBE=1
UA="arsenal-http-audit/1.0"
URLS=()
EXIT_CODE=0

# sensitive paths probed with a ranged GET (only headers/first bytes fetched)
PROBE_PATHS=("/.git/HEAD" "/.env" "/.svn/entries" "/.DS_Store" "/server-status"
             "/.well-known/security.txt" "/phpinfo.php" "/config.php.bak"
             "/backup.zip" "/.git/config" "/actuator/health" "/wp-config.php.bak")

if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'
    C_B=$'\e[34m'; C_C=$'\e[36m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_BOLD=""; C_DIM=""
fi
info()    { printf '%s[*]%s %s\n'  "${C_B}"   "${C_RST}" "$*"; }
ok()      { printf '%s[+]%s %s\n'  "${C_G}"   "${C_RST}" "$*"; }
warn()    { printf '%s[!]%s %s\n'  "${C_Y}"   "${C_RST}" "$*"; }
err()     { printf '%s[x]%s %s\n'  "${C_R}"   "${C_RST}" "$*"; }
field()   { printf '    %s%-26s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }
jesc()    { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\r'/}"; printf '%s' "$s"; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            [[ -z "${2:-}" ]] && { err "missing FILE"; exit 2; }
            while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && URLS+=("$l"); done < "$2"
            shift 2 ;;
        -t|--timeout)  TIMEOUT="${2:?}"; shift 2 ;;
        --no-probe)    DO_PROBE=0; shift ;;
        --json)        JSON=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        -*)            err "unknown option: $1"; usage; exit 2 ;;
        *)             URLS+=("$1"); shift ;;
    esac
done
[[ ${#URLS[@]} -eq 0 ]] && { err "no URLs given"; usage; exit 2; }
have curl || { err "curl is required"; exit 2; }

# normalize: bare host -> https://host
normalize() { local u="$1"; [[ "$u" == http://* || "$u" == https://* ]] && echo "$u" || echo "https://$u"; }

# fetch response headers (follow redirects); prints headers of FINAL response
fetch_headers() {
    curl -sS -L --max-time "$TIMEOUT" -A "$UA" -D - -o /dev/null "$1" 2>/dev/null
}

# header value (last occurrence wins), case-insensitive name; strips CR
hget() { awk -v h="$1" 'BEGIN{IFS=":"} tolower($0) ~ "^" tolower(h) ":" {sub(/^[^:]*:[ \t]*/,""); v=$0} END{gsub(/\r/,"",v); print v}'; }

audit_url() {
    local raw="$1" url; url="$(normalize "$raw")"
    local host scheme
    scheme="${url%%://*}"; host="${url#*://}"; host="${host%%/*}"

    local hdrs
    hdrs="$(fetch_headers "$url")"
    if [[ -z "$hdrs" ]]; then
        if [[ ${JSON} -eq 1 ]]; then
            printf '{"tool":"http-audit","host":"%s","url":"%s","reachable":false,"problems":["no HTTP response"]}\n' "$(jesc "$host")" "$(jesc "$url")"
        else section "$url"; err "no HTTP response"; fi
        EXIT_CODE=1; return
    fi

    local status server powered
    status="$(printf '%s' "$hdrs" | grep -aE '^HTTP/' | tail -1 | tr -d '\r')"
    server="$(printf '%s' "$hdrs" | hget 'Server')"
    powered="$(printf '%s' "$hdrs" | hget 'X-Powered-By')"

    # --- security headers -----------------------------------------------------
    local problems=()
    declare -A H
    H[hsts]="$(printf '%s' "$hdrs" | hget 'Strict-Transport-Security')"
    H[csp]="$(printf '%s' "$hdrs" | hget 'Content-Security-Policy')"
    H[xfo]="$(printf '%s' "$hdrs" | hget 'X-Frame-Options')"
    H[xcto]="$(printf '%s' "$hdrs" | hget 'X-Content-Type-Options')"
    H[ref]="$(printf '%s' "$hdrs" | hget 'Referrer-Policy')"
    H[perm]="$(printf '%s' "$hdrs" | hget 'Permissions-Policy')"
    H[coop]="$(printf '%s' "$hdrs" | hget 'Cross-Origin-Opener-Policy')"

    [[ "$scheme" == "https" && -z "${H[hsts]}" ]] && problems+=("missing HSTS (Strict-Transport-Security)")
    [[ -z "${H[csp]}"  ]] && problems+=("missing Content-Security-Policy")
    [[ -z "${H[xfo]}" && "${H[csp]}" != *frame-ancestors* ]] && problems+=("missing X-Frame-Options / CSP frame-ancestors (clickjacking)")
    [[ -z "${H[xcto]}" ]] && problems+=("missing X-Content-Type-Options: nosniff")
    [[ -z "${H[ref]}"  ]] && problems+=("missing Referrer-Policy")
    [[ -z "${H[perm]}" ]] && problems+=("missing Permissions-Policy")

    # --- cookies --------------------------------------------------------------
    local cookie_issues=() setcookies
    setcookies="$(printf '%s' "$hdrs" | grep -aiE '^Set-Cookie:')"
    if [[ -n "$setcookies" ]]; then
        while IFS= read -r ck; do
            [[ -z "$ck" ]] && continue
            local cname; cname="$(echo "$ck" | sed -E 's/^[Ss]et-[Cc]ookie:[ ]*([^=]+)=.*/\1/' | tr -d '\r')"
            echo "$ck" | grep -qi 'Secure'   || cookie_issues+=("${cname}: no Secure")
            echo "$ck" | grep -qi 'HttpOnly' || cookie_issues+=("${cname}: no HttpOnly")
            echo "$ck" | grep -qi 'SameSite' || cookie_issues+=("${cname}: no SameSite")
        done <<<"$setcookies"
    fi
    [[ ${#cookie_issues[@]} -gt 0 ]] && problems+=("cookie flags: ${cookie_issues[*]}")

    # --- transport: does http:// redirect to https:// ? ----------------------
    local http_redirect="n/a"
    if [[ "$scheme" == "https" ]]; then
        local loc
        loc="$(curl -sS -I --max-time "$TIMEOUT" -A "$UA" "http://${host}/" 2>/dev/null | hget 'Location')"
        if [[ "$loc" == https://* ]]; then http_redirect="yes"
        else http_redirect="no"; problems+=("http:// does not redirect to https://"); fi
    fi

    # --- disclosure -----------------------------------------------------------
    echo "$server"  | grep -qE '[0-9]+\.[0-9]+' && problems+=("version disclosure in Server: ${server}")
    [[ -n "$powered" ]] && problems+=("X-Powered-By disclosure: ${powered}")

    # --- exposure probes ------------------------------------------------------
    local exposed=()
    if [[ ${DO_PROBE} -eq 1 ]]; then
        local base="${scheme}://${host}" p code
        # Baseline: if a known-bogus path returns 200/206 the site soft-404s,
        # so probe results would be meaningless — skip and note it.
        local baseline
        baseline="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" -A "$UA" \
                    "${base}/arsenal_nonexistent_baseline_9f3a2b" 2>/dev/null)"
        if [[ "$baseline" == "200" || "$baseline" == "206" ]]; then
            problems+=("exposure probing skipped: site returns 200 for missing paths (soft 404)")
        else
            for p in "${PROBE_PATHS[@]}"; do
                code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" -A "$UA" -r 0-0 "${base}${p}" 2>/dev/null)"
                [[ "$code" == "200" || "$code" == "206" ]] && exposed+=("${p} (${code})")
            done
            [[ ${#exposed[@]} -gt 0 ]] && problems+=("exposed paths: ${exposed[*]}")
        fi
    fi

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    # --- output ---------------------------------------------------------------
    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"http-audit","host":"%s","url":"%s","reachable":true,' "$(jesc "$host")" "$(jesc "$url")"
        printf '"status":"%s","server":"%s","http_redirect":"%s",' "$(jesc "$status")" "$(jesc "$server")" "$http_redirect"
        printf '"hsts":"%s","csp":%s,"problems":[%s]}\n' \
            "$(jesc "${H[hsts]}")" "$([[ -n "${H[csp]}" ]] && echo true || echo false)" "$pj"
        return
    fi

    section "$url"
    field "Status"                "${status:-?}"
    [[ -n "$server" ]]  && field "Server" "$server"
    [[ -n "$powered" ]] && field "X-Powered-By" "$powered"
    field "HSTS"                  "${H[hsts]:-MISSING}"
    field "Content-Security-Policy" "$([[ -n "${H[csp]}" ]] && echo present || echo MISSING)"
    field "X-Frame-Options"       "${H[xfo]:-MISSING}"
    field "X-Content-Type-Options" "${H[xcto]:-MISSING}"
    field "Referrer-Policy"       "${H[ref]:-MISSING}"
    field "Permissions-Policy"    "$([[ -n "${H[perm]}" ]] && echo present || echo MISSING)"
    field "http->https redirect"  "$http_redirect"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "http-audit — ${#URLS[@]} URL(s), timeout ${TIMEOUT}s"
for u in "${URLS[@]}"; do audit_url "$u"; done
exit "${EXIT_CODE}"
