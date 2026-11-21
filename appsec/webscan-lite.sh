#!/usr/bin/env bash
#
# webscan-lite.sh — fast, passive web-app posture scan (appsec)
# =============================================================================
#   A quick, read-only look at one or more web apps: a handful of requests, no
#   crawling or brute-forcing. Rolls up transport + security headers + cookies
#   + CORS + tech fingerprint + a light page inspection (title, login/forms,
#   mixed content) + a few well-known paths. For the deep version (crawl,
#   content/parameter discovery, injection indicators) use webscan-heavy.sh.
#
#   Read-only. Only scan apps you own or are explicitly authorized to test.
# =============================================================================
#
#   Requires: curl, python3.
#
#   Quick start:
#     ./webscan-lite.sh example.com
#     ./webscan-lite.sh https://app.example.com/login
#     ./webscan-lite.sh -f urls.txt --json
#     ./webscan-lite.sh --no-probe example.com      # skip well-known-path checks
#
set -uo pipefail

TIMEOUT=10
JSON=0
DO_PROBE=1
UA="arsenal-webscan-lite/1.0"
URLS=()
EXIT_CODE=0

if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'
    C_B=$'\e[34m'; C_C=$'\e[36m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_BOLD=""; C_DIM=""
fi
info()    { printf '%s[*]%s %s\n'  "${C_B}" "${C_RST}" "$*" >&2; }
ok()      { printf '%s[+]%s %s\n'  "${C_G}" "${C_RST}" "$*"; }
warn()    { printf '%s[!]%s %s\n'  "${C_Y}" "${C_RST}" "$*"; }
err()     { printf '%s[x]%s %s\n'  "${C_R}" "${C_RST}" "$*" >&2; }
field()   { printf '    %s%-22s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }
jesc()    { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//$'\n'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037\177')"; printf '%s' "$s"; }

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file) [[ -z "${2:-}" ]] && { err "missing FILE"; exit 2; }
            while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && URLS+=("$l"); done < "$2"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --no-probe)   DO_PROBE=0; shift ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           err "unknown option: $1"; usage; exit 2 ;;
        *)            URLS+=("$1"); shift ;;
    esac
done
[[ ${#URLS[@]} -eq 0 ]] && { err "no URLs given"; usage; exit 2; }
have curl    || { err "curl is required"; exit 2; }
have python3 || { err "python3 is required"; exit 2; }

normalize() { local u="$1"; [[ "$u" == http://* || "$u" == https://* ]] && echo "$u" || echo "https://$u"; }
hget() { awk -v h="$1" 'tolower($0) ~ "^" tolower(h) ":" {sub(/^[^:]*:[ \t]*/,""); v=$0} END{gsub(/\r/,"",v); print v}'; }
# ranged status code for a path (fast; first byte only)
code_of() { curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" -A "$UA" -r 0-0 "$1" 2>/dev/null; }

scan_url() {
    local raw="$1" url; url="$(normalize "$raw")"
    local scheme host base
    scheme="${url%%://*}"; host="${url#*://}"; host="${host%%/*}"; base="${scheme}://${host}"

    local hdrs body
    hdrs="$(curl -sS -L -D - -o /dev/null --max-time "$TIMEOUT" -A "$UA" "$url" 2>/dev/null)"
    body="$(curl -sS -L --max-time "$TIMEOUT" -A "$UA" --max-filesize 2000000 "$url" 2>/dev/null)"
    if [[ -z "$hdrs" ]]; then
        if [[ ${JSON} -eq 1 ]]; then printf '{"tool":"webscan-lite","host":"%s","url":"%s","reachable":false,"problems":[]}\n' "$(jesc "$host")" "$(jesc "$url")"
        else section "$url"; err "no HTTP response"; fi
        return
    fi

    local problems=() status server powered
    status="$(printf '%s' "$hdrs" | grep -aE '^HTTP/' | tail -1 | tr -d '\r')"
    server="$(printf '%s' "$hdrs" | hget 'Server')"
    powered="$(printf '%s' "$hdrs" | hget 'X-Powered-By')"

    # security headers
    [[ "$scheme" == "https" ]] && [[ -z "$(printf '%s' "$hdrs" | hget 'Strict-Transport-Security')" ]] && problems+=("missing HSTS")
    [[ -z "$(printf '%s' "$hdrs" | hget 'Content-Security-Policy')" ]] && problems+=("missing Content-Security-Policy")
    [[ -z "$(printf '%s' "$hdrs" | hget 'X-Content-Type-Options')" ]] && problems+=("missing X-Content-Type-Options: nosniff")
    [[ -z "$(printf '%s' "$hdrs" | hget 'X-Frame-Options')" && "$(printf '%s' "$hdrs" | hget 'Content-Security-Policy')" != *frame-ancestors* ]] && problems+=("clickjacking: no X-Frame-Options / frame-ancestors")
    # cookie flags
    while IFS= read -r ck; do [[ -z "$ck" ]] && continue
        local cn; cn="$(echo "$ck" | sed -E 's/^[Ss]et-[Cc]ookie:[ ]*([^=]+)=.*/\1/' | tr -d '\r')"
        echo "$ck" | grep -qi 'HttpOnly' || problems+=("cookie ${cn}: no HttpOnly")
        [[ "$scheme" == "https" ]] && { echo "$ck" | grep -qi 'Secure' || problems+=("cookie ${cn}: no Secure"); }
    done < <(printf '%s' "$hdrs" | grep -aiE '^Set-Cookie:')
    # disclosure
    echo "$server" | grep -qE '[0-9]+\.[0-9]+' && problems+=("version disclosure in Server: ${server}")
    [[ -n "$powered" ]] && problems+=("X-Powered-By disclosure: ${powered}")
    # http->https
    local redir="n/a"
    if [[ "$scheme" == "https" ]]; then
        local loc; loc="$(curl -sS -I --max-time "$TIMEOUT" -A "$UA" "http://${host}/" 2>/dev/null | hget 'Location')"
        [[ "$loc" == https://* ]] && redir="yes" || { redir="no"; problems+=("http:// does not redirect to https://"); }
    fi
    # CORS reflect
    local cors="no" ch; ch="$(curl -sS -I --max-time "$TIMEOUT" -A "$UA" -H 'Origin: https://evil.arsenal-audit.example' "$url" 2>/dev/null)"
    if printf '%s' "$ch" | hget 'Access-Control-Allow-Origin' | grep -qiE 'evil\.arsenal-audit\.example'; then
        cors="reflected"
        printf '%s' "$ch" | hget 'Access-Control-Allow-Credentials' | grep -qi true \
            && problems+=("CORS reflects arbitrary Origin + credentials (data theft)") \
            || problems+=("CORS reflects arbitrary Origin")
    fi

    # page inspection (title / forms / login / mixed content / external scripts)
    local pageinfo
    pageinfo="$(URL="$url" SCHEME="$scheme" python3 -c '
import sys,os,re,html
b=sys.stdin.read(); scheme=os.environ["SCHEME"]
t=re.search(r"<title[^>]*>(.*?)</title>", b, re.I|re.S); title=html.unescape((t.group(1).strip()[:120]) if t else "")
forms=len(re.findall(r"<form\b", b, re.I))
pw=len(re.findall(r"type=[\"\x27]?password", b, re.I))
ext=len(re.findall(r"<script[^>]+src=", b, re.I))
gen=re.search(r"<meta[^>]+name=[\"\x27]generator[\"\x27][^>]+content=[\"\x27]([^\"\x27]+)", b, re.I)
mixed=0
if scheme=="https":
    mixed=len(re.findall(r"(?:src|href)=[\"\x27]http://", b, re.I))
print("TITLE\t"+title)
print("FORMS\t%d"%forms); print("LOGIN\t%d"%pw); print("EXTSCRIPTS\t%d"%ext)
print("GENERATOR\t"+(gen.group(1) if gen else ""))
print("MIXED\t%d"%mixed)
' <<<"$body" 2>/dev/null)"
    local title forms login generator mixed
    title="$(awk -F'\t' '$1=="TITLE"{print $2}' <<<"$pageinfo")"
    forms="$(awk -F'\t' '$1=="FORMS"{print $2}' <<<"$pageinfo")"
    login="$(awk -F'\t' '$1=="LOGIN"{print $2}' <<<"$pageinfo")"
    generator="$(awk -F'\t' '$1=="GENERATOR"{print $2}' <<<"$pageinfo")"
    mixed="$(awk -F'\t' '$1=="MIXED"{print $2}' <<<"$pageinfo")"
    [[ -n "$generator" ]] && problems+=("tech disclosure: generator=${generator}")
    [[ "${mixed:-0}" -gt 0 ]] && problems+=("mixed content: ${mixed} http:// resource(s) on an https page")
    [[ "${login:-0}" -gt 0 && "$scheme" != "https" ]] && problems+=("login form served over cleartext http")

    # well-known paths + a few exposed files (soft-404 aware)
    local wellknown="" exposed=()
    if [[ ${DO_PROBE} -eq 1 ]]; then
        local baseline; baseline="$(code_of "${base}/arsenal_nonexistent_baseline_9f3a2b")"
        local rt st; rt="$(code_of "${base}/robots.txt")"; st="$(code_of "${base}/.well-known/security.txt")"
        [[ "$rt" == 200 ]] && wellknown="robots.txt"; [[ "$st" == 200 ]] && wellknown="${wellknown:+$wellknown,}security.txt"
        if [[ "$baseline" != 200 && "$baseline" != 206 ]]; then
            local p c; for p in "/.git/HEAD" "/.env" "/.svn/entries" "/config.php.bak" "/backup.zip" "/.DS_Store"; do
                c="$(code_of "${base}${p}")"; [[ "$c" == 200 || "$c" == 206 ]] && exposed+=("${p}")
            done
            [[ ${#exposed[@]} -gt 0 ]] && problems+=("exposed sensitive paths: ${exposed[*]}")
        fi
    fi

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue; [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"webscan-lite","host":"%s","url":"%s","reachable":true,"status":"%s",' "$(jesc "$host")" "$(jesc "$url")" "$(jesc "$status")"
        printf '"server":"%s","title":"%s","forms":%s,"login_form":%s,"cors":"%s","http_redirect":"%s","wellknown":"%s","problems":[%s]}\n' \
            "$(jesc "$server")" "$(jesc "$title")" "${forms:-0}" "$([[ "${login:-0}" -gt 0 ]] && echo true || echo false)" \
            "$cors" "$redir" "$(jesc "$wellknown")" "$pj"
        return
    fi
    section "$url"
    field "Status"    "${status:-?}"
    [[ -n "$server" ]] && field "Server" "$server"
    [[ -n "$title" ]]  && field "Title" "$title"
    field "Forms"     "${forms:-0}$([[ "${login:-0}" -gt 0 ]] && echo " (login form present)")"
    field "CORS"      "$cors"
    field "http->https" "$redir"
    [[ -n "$wellknown" ]] && field "Well-known" "$wellknown"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "webscan-lite — ${#URLS[@]} target(s), timeout ${TIMEOUT}s"
for u in "${URLS[@]}"; do scan_url "$u"; done
exit "${EXIT_CODE}"
