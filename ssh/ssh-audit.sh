#!/usr/bin/env bash
#
# ssh-audit.sh — SSH server probe & sshd_config hardening audit
# =============================================================================
#   Two modes:
#     remote  — connect to an SSH service and report its banner, host-key
#               fingerprints, and the key-exchange / cipher / MAC / host-key
#               algorithms it offers, flagging deprecated or weak ones.
#     local   — read a local sshd_config (default /etc/ssh/sshd_config) and
#               grade it against a hardening baseline.
#   Both are read-only. Only probe servers you own or are authorized to test.
# =============================================================================
#
#   Requires: ssh, ssh-keyscan (openssh-client). Optional: nmap, ssh-keygen.
#
#   Quick start:
#     ./ssh-audit.sh host.example.com                 # remote probe, port 22
#     ./ssh-audit.sh host.example.com:2222
#     ./ssh-audit.sh --local                          # audit /etc/ssh/sshd_config
#     ./ssh-audit.sh --local --config /path/sshd_config
#     ./ssh-audit.sh --json host.example.com
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

MODE="remote"
PORT_DEFAULT=22
TIMEOUT=10
JSON=0
CONFIG="/etc/ssh/sshd_config"
TARGETS=()
EXIT_CODE=0

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
field()   { printf '    %s%-20s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }
jesc() { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — SSH server probe & sshd_config hardening audit

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]   # remote probe
    ${SCRIPT_NAME} --local [--config FILE]                     # local config audit

OPTIONS:
    -l, --local           Audit a local sshd_config instead of probing a server
    -c, --config FILE     sshd_config path for --local (default: ${CONFIG})
    -p, --port PORT       Default port when host has none (default: ${PORT_DEFAULT})
    -t, --timeout SEC     Connection timeout seconds (default: ${TIMEOUT})
        --json            Emit JSON instead of text
    -h, --help            Show this help

EXIT STATUS:
    0  no weaknesses found
    1  at least one weakness / deprecated algorithm / risky directive found
    2  usage error

WEAK ALGORITHMS FLAGGED (remote):
    KEX   diffie-hellman-group1/group14-sha1, gss-*, *-sha1
    Host  ssh-rsa (SHA-1), ssh-dss
    Enc   *-cbc, arcfour*, 3des-*, none
    MAC   hmac-md5*, hmac-sha1*, umac-64*, *-96, *-etm excepted when sha2

NOTES:
    Read-only. Only probe servers you own or are authorized to test.
EOF
}

# -------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--local)   MODE="local"; shift ;;
        -c|--config)  CONFIG="${2:?}"; shift 2 ;;
        -p|--port)    PORT_DEFAULT="${2:?}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)           err "unknown option: $1"; usage; exit 2 ;;
        *)            TARGETS+=("$1"); shift ;;
    esac
done

# weak-pattern matcher (extended regex, case-insensitive) per algo class
WEAK_KEX='diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-|ecdh-sha2-nistp.*|rsa1024-'
WEAK_HOSTKEY='^ssh-rsa$|ssh-dss|ssh-rsa-cert|^rsa-sha$'
WEAK_ENC='-cbc|arcfour|3des-|^des|blowfish|cast128|^none$|rijndael'
WEAK_MAC='hmac-md5|hmac-sha1|hmac-sha1-96|hmac-md5-96|umac-64|^none$'

flag_weak() {  # <class-regex> <comma-list>  -> prints weak entries found
    local re="$1" list="$2" found=() a
    IFS=',' read -ra arr <<<"$list"
    for a in "${arr[@]}"; do
        [[ -z "$a" ]] && continue
        # -e so a pattern that starts with '-' (e.g. WEAK_ENC '-cbc|...') is
        # not parsed as a grep option.
        echo "$a" | grep -qiE -e "$re" && found+=("$a")
    done
    (IFS=,; echo "${found[*]}")
}

# ------------------------------------------------------------- remote probe --
probe_host() {
    local target="$1" host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORT_DEFAULT}"; fi

    have ssh-keyscan || { err "ssh-keyscan not found (install openssh-client)"; EXIT_CODE=2; return; }

    # banner + host keys
    local scan banner="" fps=()
    scan="$(timeout "${TIMEOUT}" ssh-keyscan -T "${TIMEOUT}" -p "$port" "$host" 2>/dev/null)"
    banner="$(timeout "${TIMEOUT}" bash -c "exec 3<>/dev/tcp/${host}/${port} 2>/dev/null; head -1 <&3" 2>/dev/null \
              | tr -d '\r')"

    if [[ -z "$scan" && -z "$banner" ]]; then
        if [[ ${JSON} -eq 1 ]]; then
            printf '{"tool":"ssh-audit","host":"%s","port":"%s","reachable":false,"problems":["no SSH response (host down, filtered, or not SSH)"]}\n' "$(jesc "$host")" "$(jesc "$port")"
        else
            section "${host}:${port}"; err "no SSH response (host down, filtered, or not SSH)"
        fi
        EXIT_CODE=1; return
    fi

    # fingerprints
    if have ssh-keygen && [[ -n "$scan" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && fps+=("$line")
        done < <(echo "$scan" | ssh-keygen -l -f /dev/stdin 2>/dev/null)
    fi

    # algorithm negotiation: parse a verbose connection attempt
    # (we never authenticate; -o BatchMode avoids prompts; failure is expected)
    local vv kex hostkeys enc_c2s mac_c2s
    vv="$(timeout "${TIMEOUT}" ssh -vv -p "$port" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout="${TIMEOUT}" \
            -o PreferredAuthentications=none \
            "nonexistent-audit-user@${host}" 2>&1 || true)"
    kex="$(     echo "$vv" | grep -m1 'kex: algorithm:'            | sed 's/.*algorithm: *//')"
    hostkeys="$(echo "$vv" | grep -m1 'kex: host key algorithm:'  | sed 's/.*algorithm: *//')"
    enc_c2s="$( echo "$vv" | grep -m1 'kex: server->client'       | sed -E 's/.*cipher: *([^ ]+).*/\1/')"
    mac_c2s="$( echo "$vv" | grep -m1 'kex: server->client'       | sed -E 's/.*MAC: *([^ ]+).*/\1/')"

    # Fuller lists from the server's KEXINIT if available (debug2 lines)
    local srv_kex srv_hk srv_enc srv_mac
    srv_kex="$(echo "$vv" | grep -m1 'peer server KEXINIT'  >/dev/null 2>&1; \
               echo "$vv" | grep -A20 'SSH2_MSG_KEXINIT received' 2>/dev/null | grep -m1 'kex algorithms' | sed 's/.*: //')"
    # Fallbacks: nmap ssh2-enum-algos gives authoritative full lists
    if have nmap; then
        local enum
        enum="$(nmap -p "$port" --script ssh2-enum-algos "$host" 2>/dev/null)"
        [[ -n "$enum" ]] && {
            srv_kex="$(echo "$enum"  | sed -n '/kex_algorithms/,/server_host_key/p' | grep -oE '[a-z0-9@._-]+-[a-z0-9@._-]+' | paste -sd, -)"
            srv_hk="$( echo "$enum"  | sed -n '/server_host_key_algorithms/,/encryption_algorithms/p' | grep -oE '(ssh|ecdsa|rsa|sk)-[a-z0-9@._-]+' | paste -sd, -)"
            srv_enc="$(echo "$enum"  | sed -n '/encryption_algorithms/,/mac_algorithms/p' | grep -oE '[a-z0-9@._-]+-[a-z0-9@._-]+|chacha20[a-z0-9@._-]*|aes[0-9]+-[a-z]+' | paste -sd, -)"
            srv_mac="$(echo "$enum"  | sed -n '/mac_algorithms/,/compression/p' | grep -oE 'hmac-[a-z0-9@._-]+|umac-[a-z0-9@._-]+' | paste -sd, -)"
        }
    fi
    # prefer full server lists, else negotiated single values
    local L_kex="${srv_kex:-$kex}" L_hk="${srv_hk:-$hostkeys}" L_enc="${srv_enc:-$enc_c2s}" L_mac="${srv_mac:-$mac_c2s}"

    local w_kex w_hk w_enc w_mac
    w_kex="$(flag_weak "$WEAK_KEX" "$L_kex")"
    w_hk="$( flag_weak "$WEAK_HOSTKEY" "$L_hk")"
    w_enc="$(flag_weak "$WEAK_ENC" "$L_enc")"
    w_mac="$(flag_weak "$WEAK_MAC" "$L_mac")"

    local problems=()
    [[ -n "$w_kex" ]] && problems+=("weak key-exchange: $w_kex")
    [[ -n "$w_hk"  ]] && problems+=("weak host-key algo: $w_hk")
    [[ -n "$w_enc" ]] && problems+=("weak cipher: $w_enc")
    [[ -n "$w_mac" ]] && problems+=("weak MAC: $w_mac")
    echo "$banner" | grep -qiE 'openssh_[1-6]\.' && problems+=("old OpenSSH version: $banner")
    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"ssh-audit","host":"%s","port":"%s","reachable":true,"banner":"%s",' \
            "$(jesc "$host")" "$(jesc "$port")" "$(jesc "$banner")"
        printf '"kex":"%s","host_key_algos":"%s","ciphers":"%s","macs":"%s","problems":[%s]}\n' \
            "$(jesc "$L_kex")" "$(jesc "$L_hk")" "$(jesc "$L_enc")" "$(jesc "$L_mac")" "$pj"
        return
    fi

    section "${host}:${port}"
    field "Banner" "${banner:-?}"
    local f; for f in "${fps[@]:-}"; do [[ -n "$f" ]] && field "Fingerprint" "$f"; done
    field "KEX"       "${L_kex:-?}"
    field "Host keys" "${L_hk:-?}"
    field "Ciphers"   "${L_enc:-?}"
    field "MACs"      "${L_mac:-?}"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no weak algorithms detected"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

# -------------------------------------------------------- local config audit --
audit_config() {
    [[ -r "$CONFIG" ]] || { err "cannot read config: $CONFIG"; exit 2; }

    # directive -> effective value (last non-commented wins, like sshd)
    getval() {
        grep -iE "^[[:space:]]*$1[[:space:]]" "$CONFIG" 2>/dev/null \
            | grep -vE '^[[:space:]]*#' | tail -1 \
            | sed -E "s/^[[:space:]]*$1[[:space:]]+//I" | tr -d '\r'
    }

    local problems=() goods=()
    chk() {  # chk <label> <value> <bad-regex> <recommendation>
        local label="$1" val="$2" bad="$3" rec="$4"
        if [[ -z "$val" ]]; then
            problems+=("${label}: not set (default may be insecure) — ${rec}")
        elif echo "$val" | grep -qiE "$bad"; then
            problems+=("${label}: '${val}' — ${rec}")
        else
            goods+=("${label}: ${val}")
        fi
    }

    chk "PermitRootLogin"        "$(getval PermitRootLogin)"        '^(yes|prohibit-password|without-password)$' "set to 'no'"
    chk "PasswordAuthentication" "$(getval PasswordAuthentication)" '^yes$'              "set to 'no'; use keys"
    chk "PermitEmptyPasswords"   "$(getval PermitEmptyPasswords)"   '^yes$'              "set to 'no'"
    chk "ChallengeResponseAuthentication" "$(getval ChallengeResponseAuthentication)" '^yes$' "set to 'no' unless MFA uses it"
    chk "X11Forwarding"          "$(getval X11Forwarding)"          '^yes$'              "set to 'no' unless required"
    chk "AllowTcpForwarding"     "$(getval AllowTcpForwarding)"     '^yes$'              "restrict if not a jump host"
    chk "PermitUserEnvironment"  "$(getval PermitUserEnvironment)"  '^yes$'              "set to 'no'"
    chk "Protocol"               "$(getval Protocol)"               '(^|,)1($|,)'        "SSHv1 is broken; force 2 (or omit)"
    chk "UsePAM"                 "$(getval UsePAM)"                 '^no$'               "usually 'yes'"

    # numeric / threshold checks
    local v
    v="$(getval MaxAuthTries)";  [[ -n "$v" ]] && (( v > 4 ))  && problems+=("MaxAuthTries: ${v} — lower to <=4")
    v="$(getval LoginGraceTime)"; [[ -n "$v" && "$v" =~ ^[0-9]+$ ]] && (( v > 60 )) && problems+=("LoginGraceTime: ${v}s — lower to <=60")
    v="$(getval ClientAliveInterval)"; [[ -z "$v" ]] && problems+=("ClientAliveInterval: not set — set e.g. 300 for idle timeout")

    # weak explicit algorithm lists, if present
    local c
    c="$(getval Ciphers)";      [[ -n "$c" ]] && { local w; w="$(flag_weak "$WEAK_ENC" "$c")";    [[ -n "$w" ]] && problems+=("Ciphers include weak: $w"); }
    c="$(getval MACs)";         [[ -n "$c" ]] && { local w; w="$(flag_weak "$WEAK_MAC" "$c")";    [[ -n "$w" ]] && problems+=("MACs include weak: $w"); }
    c="$(getval KexAlgorithms)"; [[ -n "$c" ]] && { local w; w="$(flag_weak "$WEAK_KEX" "$c")";   [[ -n "$w" ]] && problems+=("KexAlgorithms include weak: $w"); }

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"ssh-audit","host":"%s","findings":[%s]}\n' "$(jesc "$CONFIG")" "$pj"
        return
    fi

    section "sshd_config audit — ${CONFIG}"
    local g; for g in "${goods[@]:-}"; do [[ -n "$g" ]] && ok "$g"; done
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no hardening issues found"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

# ---------------------------------------------------------------------- main --
if [[ "$MODE" == "local" ]]; then
    audit_config
else
    [[ ${#TARGETS[@]} -eq 0 ]] && { err "no hosts given (or use --local)"; usage; exit 2; }
    have ssh || { err "ssh client not found"; exit 2; }
    [[ ${JSON} -eq 0 ]] && info "ssh-audit — ${#TARGETS[@]} host(s), timeout ${TIMEOUT}s"
    for t in "${TARGETS[@]}"; do probe_host "$t"; done
fi
exit "${EXIT_CODE}"
