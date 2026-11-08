#!/usr/bin/env bash
#
# ssl-audit.sh — TLS/SSL posture checker & certificate analyser
# =============================================================================
#   Connects to one or more host:port endpoints and reports on the certificate
#   chain, protocol support, and common misconfigurations. Read-only: it makes
#   normal TLS handshakes, exactly like a browser would. Use it on your own
#   services or where you are authorized to test.
# =============================================================================
#
#   Requires: openssl. Optional: nmap (deeper cipher enumeration).
#
#   Quick start:
#     ./ssl-audit.sh example.com                 # defaults to :443
#     ./ssl-audit.sh example.com:8443
#     ./ssl-audit.sh -f hosts.txt                # one host[:port] per line
#     ./ssl-audit.sh --json example.com          # machine-readable output
#     ./ssl-audit.sh --ciphers example.com       # enumerate ciphers (needs nmap)
#     ./ssl-audit.sh --starttls smtp mail.example.com:25
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

# ------------------------------------------------------------------- options --
PORT_DEFAULT=443
TIMEOUT=10
JSON=0
DO_CIPHERS=0
STARTTLS=""
SERVERNAME=""        # override SNI
HOSTS=()
EXIT_CODE=0          # non-zero if any endpoint has a hard problem (expired, etc.)

# warn when a cert expires within this many days
EXPIRY_WARN_DAYS=30
EXPIRY_CRIT_DAYS=7

# ------------------------------------------------------------------- colours --
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
crit()    { printf '%s[X]%s %s\n'  "${C_R}${C_BOLD}" "${C_RST}" "$*"; }
field()   { printf '    %s%-22s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — TLS/SSL posture checker & certificate analyser

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]

OPTIONS:
    -f, --file FILE       Read host[:port] entries from FILE (one per line, # = comment)
    -p, --port PORT       Default port when host has none (default: ${PORT_DEFAULT})
    -t, --timeout SEC     Connection timeout seconds (default: ${TIMEOUT})
        --servername NAME Override SNI / server name sent in handshake
        --starttls PROTO  Use STARTTLS (smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql)
        --ciphers         Enumerate supported ciphers per protocol (requires nmap)
        --json            Emit JSON (one object per host) instead of text
        --warn-days N     Warn if cert expires within N days (default: ${EXPIRY_WARN_DAYS})
    -h, --help            Show this help

EXIT STATUS:
    0  all endpoints healthy
    1  at least one endpoint has a hard problem (expired cert, no TLS, weak proto only)
    2  usage error

NOTES:
    Read-only. Performs ordinary TLS handshakes. Only test endpoints you own or
    are authorized to assess.
EOF
}

# -------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            [[ -z "${2:-}" ]] && { err "missing FILE for $1"; exit 2; }
            while IFS= read -r line; do
                line="${line%%#*}"; line="${line//[[:space:]]/}"
                [[ -n "$line" ]] && HOSTS+=("$line")
            done < "$2"
            shift 2 ;;
        -p|--port)       PORT_DEFAULT="${2:?}"; shift 2 ;;
        -t|--timeout)    TIMEOUT="${2:?}"; shift 2 ;;
        --servername)    SERVERNAME="${2:?}"; shift 2 ;;
        --starttls)      STARTTLS="${2:?}"; shift 2 ;;
        --ciphers)       DO_CIPHERS=1; shift ;;
        --json)          JSON=1; shift ;;
        --warn-days)     EXPIRY_WARN_DAYS="${2:?}"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; while [[ $# -gt 0 ]]; do HOSTS+=("$1"); shift; done ;;
        -*)              err "unknown option: $1"; usage; exit 2 ;;
        *)               HOSTS+=("$1"); shift ;;
    esac
done

have openssl || { err "openssl is required but not found in PATH"; exit 2; }
[[ ${#HOSTS[@]} -eq 0 ]] && { err "no hosts given"; usage; exit 2; }
[[ ${DO_CIPHERS} -eq 1 ]] && ! have nmap && { warn "--ciphers needs nmap; disabling"; DO_CIPHERS=0; }

# epoch helper that works with GNU and BSD date
to_epoch() {  # <date string from openssl, e.g. "Jun  1 12:00:00 2026 GMT">
    local d="$1" e
    e="$(date -d "$d" +%s 2>/dev/null)" && { echo "$e"; return; }
    date -j -f "%b %e %T %Y %Z" "$d" +%s 2>/dev/null && return
    echo ""   # unknown
}

now_epoch() { date +%s; }

# JSON string escape
jesc() { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

# ---------------------------------------------------------- per-host handler --
audit_host() {
    local target="$1"
    local host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORT_DEFAULT}"; fi
    local sni="${SERVERNAME:-$host}"

    # collectors for JSON / summary
    local j_subject="" j_issuer="" j_san="" j_notbefore="" j_notafter=""
    local j_days="" j_keybits="" j_sigalg="" j_selfsigned="false"
    local j_hostmatch="unknown" j_chainok="unknown" j_protos="" j_problems=()

    local s_args=(-connect "${host}:${port}" -servername "$sni")
    [[ -n "$STARTTLS" ]] && s_args+=(-starttls "$STARTTLS")

    # --- grab the leaf certificate -------------------------------------------
    local cert
    cert="$(echo | timeout "${TIMEOUT}" openssl s_client "${s_args[@]}" 2>/dev/null \
            | openssl x509 2>/dev/null)"
    if [[ -z "$cert" ]]; then
        [[ ${JSON} -eq 1 ]] && {
            printf '{"tool":"ssl-audit","host":"%s","port":"%s","reachable":false,"error":"no TLS certificate / connection failed","problems":["could not establish TLS / retrieve certificate"]}\n' \
                "$(jesc "$host")" "$(jesc "$port")"
            return
        }
        section "${host}:${port}"
        crit "could not establish TLS / retrieve certificate (host down, not TLS, or filtered)"
        EXIT_CODE=1
        return
    fi

    # --- parse leaf ----------------------------------------------------------
    j_subject="$(echo "$cert" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//')"
    j_issuer="$( echo "$cert" | openssl x509 -noout -issuer  2>/dev/null | sed 's/^issuer=//')"
    j_san="$(    echo "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
                 | grep -v 'X509v3 Subject Alternative Name' | tr -d ' ' | paste -sd, -)"
    j_sigalg="$( echo "$cert" | openssl x509 -noout -text 2>/dev/null \
                 | grep -m1 'Signature Algorithm' | sed 's/.*Signature Algorithm: *//')"
    j_keybits="$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
                 | grep -oiE 'Public-Key: \(([0-9]+) bit\)' | grep -oE '[0-9]+' | head -1)"
    j_keyalg="$(echo "$cert" | openssl x509 -noout -text 2>/dev/null \
                 | grep -m1 'Public Key Algorithm' | sed 's/.*Algorithm: *//')"
    j_notbefore="$(echo "$cert" | openssl x509 -noout -startdate 2>/dev/null | sed 's/^notBefore=//')"
    j_notafter="$( echo "$cert" | openssl x509 -noout -enddate   2>/dev/null | sed 's/^notAfter=//')"

    [[ "$j_subject" == "$j_issuer" ]] && j_selfsigned="true"

    # days until expiry
    local exp_epoch now
    exp_epoch="$(to_epoch "$j_notafter")"; now="$(now_epoch)"
    if [[ -n "$exp_epoch" ]]; then
        j_days=$(( (exp_epoch - now) / 86400 ))
    fi

    # hostname match (openssl verifies -verify_hostname on connect)
    if echo | timeout "${TIMEOUT}" openssl s_client "${s_args[@]}" -verify_hostname "$host" 2>/dev/null \
            | grep -q 'Verify return code: 0'; then
        j_hostmatch="true"
    else
        # distinguish name-mismatch from other verify errors
        local vr
        vr="$(echo | timeout "${TIMEOUT}" openssl s_client "${s_args[@]}" 2>/dev/null \
              | grep -m1 'Verify return code')"
        if echo "$vr" | grep -qi 'hostname mismatch'; then j_hostmatch="false"; else j_hostmatch="unknown"; fi
    fi

    # chain verification result
    local verify
    verify="$(echo | timeout "${TIMEOUT}" openssl s_client "${s_args[@]}" 2>/dev/null \
              | grep -m1 'Verify return code')"
    if echo "$verify" | grep -q 'code: 0'; then j_chainok="true"; else j_chainok="false"; fi

    # --- protocol support probe ----------------------------------------------
    local -a proto_flags=( "ssl3:-ssl3:WEAK" "tls1:-tls1:WEAK" "tls1_1:-tls1_1:WEAK"
                           "tls1_2:-tls1_2:OK" "tls1_3:-tls1_3:OK" )
    local enabled=() weak_enabled=()
    local spec name flag grade
    for spec in "${proto_flags[@]}"; do
        IFS=: read -r name flag grade <<<"$spec"
        if echo | timeout "${TIMEOUT}" openssl s_client "${s_args[@]}" "$flag" 2>/dev/null \
                | grep -q 'BEGIN CERTIFICATE'; then
            enabled+=("$name")
            [[ "$grade" == "WEAK" ]] && weak_enabled+=("$name")
        fi
    done
    j_protos="$(IFS=,; echo "${enabled[*]}")"

    # --- problem assessment ---------------------------------------------------
    local hard=0
    if [[ -n "$j_days" ]]; then
        if   (( j_days < 0 ));                    then j_problems+=("certificate EXPIRED ${j_days#-} days ago"); hard=1
        elif (( j_days <= EXPIRY_CRIT_DAYS ));     then j_problems+=("certificate expires in ${j_days} days (critical)")
        elif (( j_days <= EXPIRY_WARN_DAYS ));     then j_problems+=("certificate expires in ${j_days} days")
        fi
    fi
    [[ "$j_selfsigned" == "true" ]]  && j_problems+=("self-signed certificate")
    [[ "$j_chainok"    == "false" ]] && { j_problems+=("chain verification failed: ${verify#*:}"); }
    [[ "$j_hostmatch"  == "false" ]] && { j_problems+=("hostname mismatch (cert not valid for ${host})"); hard=1; }
    # Key-size thresholds depend on algorithm: RSA/DSA need >=2048 bits,
    # EC keys are strong at >=256 bits (256-bit EC ~= 3072-bit RSA).
    if [[ -n "$j_keybits" ]]; then
        if echo "$j_keyalg" | grep -qiE 'ec|ed25519|ed448'; then
            (( j_keybits < 224 )) && { j_problems+=("weak EC key: ${j_keybits}-bit"); hard=1; }
        else
            (( j_keybits < 2048 )) && { j_problems+=("weak public key: ${j_keybits}-bit (${j_keyalg:-RSA})"); hard=1; }
        fi
    fi
    echo "$j_sigalg" | grep -qiE 'md5|sha1' && j_problems+=("weak signature algorithm: ${j_sigalg}")
    [[ ${#weak_enabled[@]} -gt 0 ]] && j_problems+=("deprecated protocols enabled: ${weak_enabled[*]}")
    if [[ ${#enabled[@]} -gt 0 ]] && printf '%s\n' "${enabled[@]}" | grep -qvE 'tls1_2|tls1_3'; then :; fi
    if [[ ${#enabled[@]} -eq 0 ]]; then j_problems+=("no supported TLS protocol responded"); hard=1; fi

    (( hard == 1 )) && EXIT_CODE=1

    # --- optional cipher enumeration -----------------------------------------
    local ciphers=""
    if [[ ${DO_CIPHERS} -eq 1 ]]; then
        ciphers="$(nmap --script ssl-enum-ciphers -p "$port" "$host" 2>/dev/null \
                   | sed -n '/ssl-enum-ciphers/,/^[^|]/p')"
    fi

    # --- output ---------------------------------------------------------------
    if [[ ${JSON} -eq 1 ]]; then
        local probs_json="" first=1 p
        for p in "${j_problems[@]:-}"; do
            [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && probs_json+=","
            probs_json+="\"$(jesc "$p")\""; first=0
        done
        printf '{"tool":"ssl-audit","host":"%s","port":"%s","reachable":true,' "$(jesc "$host")" "$(jesc "$port")"
        printf '"subject":"%s","issuer":"%s","san":"%s",' "$(jesc "$j_subject")" "$(jesc "$j_issuer")" "$(jesc "$j_san")"
        printf '"not_before":"%s","not_after":"%s","days_to_expiry":%s,' \
            "$(jesc "$j_notbefore")" "$(jesc "$j_notafter")" "${j_days:-null}"
        printf '"key_bits":%s,"key_alg":"%s","sig_alg":"%s","self_signed":%s,' \
            "${j_keybits:-null}" "$(jesc "$j_keyalg")" "$(jesc "$j_sigalg")" "$j_selfsigned"
        printf '"hostname_match":"%s","chain_valid":%s,' "$j_hostmatch" \
            "$([[ "$j_chainok" == "true" ]] && echo true || echo false)"
        printf '"protocols":"%s","problems":[%s]}\n' "$(jesc "$j_protos")" "$probs_json"
        return
    fi

    section "${host}:${port}"
    field "Subject"      "${j_subject:-?}"
    field "Issuer"       "${j_issuer:-?}"
    [[ -n "$j_san" ]] && field "SAN" "$j_san"
    field "Valid from"   "${j_notbefore:-?}"
    field "Valid until"  "${j_notafter:-?}"
    if [[ -n "$j_days" ]]; then
        if   (( j_days < 0 ));                then err  "    Expires in            EXPIRED (${j_days} days)"
        elif (( j_days <= EXPIRY_CRIT_DAYS )); then err  "    Expires in            ${j_days} days"
        elif (( j_days <= EXPIRY_WARN_DAYS )); then warn "    Expires in            ${j_days} days"
        else field "Expires in" "${j_days} days"; fi
    fi
    field "Public key"   "${j_keybits:-?}-bit ${j_keyalg:-}"
    field "Signature"    "${j_sigalg:-?}"
    field "Self-signed"  "$j_selfsigned"
    field "Hostname match" "$j_hostmatch"
    field "Chain valid"  "$j_chainok"
    field "Protocols"    "${j_protos:-none}"
    [[ -n "$ciphers" ]] && { printf '%s  Ciphers:%s\n' "${C_DIM}" "${C_RST}"; echo "$ciphers" | sed 's/^/      /'; }

    if [[ ${#j_problems[@]} -eq 0 || ( ${#j_problems[@]} -eq 1 && -z "${j_problems[0]}" ) ]]; then
        ok  "no issues detected"
    else
        local p
        for p in "${j_problems[@]}"; do [[ -n "$p" ]] && warn "$p"; done
    fi
}

# ---------------------------------------------------------------------- main --
[[ ${JSON} -eq 0 ]] && info "ssl-audit — ${#HOSTS[@]} endpoint(s), timeout ${TIMEOUT}s"
for h in "${HOSTS[@]}"; do
    audit_host "$h"
done
exit "${EXIT_CODE}"
