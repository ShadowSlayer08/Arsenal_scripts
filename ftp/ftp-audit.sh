#!/usr/bin/env bash
#
# ftp-audit.sh — FTP / FTPS service security analyser
# =============================================================================
#   Read-only posture check for one or more FTP services (21 / 990-implicit).
#   Reports:
#     * banner / version      — vsFTPd / ProFTPD / Pure-FTPd disclosure (→ cve-lookup)
#     * anonymous login       — does USER anonymous succeed? (read-only; no upload)
#     * transport security    — explicit AUTH TLS/SSL (FEAT) or implicit FTPS (990);
#                               flags cleartext-only servers
#     * FTPS certificate       — negotiated, cert present (cross-ref ssl-audit)
#     * FTP bounce / FXP       — PORT-to-third-host bounce exposure (nmap ftp-bounce)
#     * known backdoors/RCE    — vsFTPd 2.3.4 CVE-2011-2523, ProFTPD mod_copy
#                               CVE-2015-3306 (flagged by version; active NSE
#                               trigger is opt-in via --nse-intrusive)
#   Default engine is nmap NSE; a self-contained python3 engine is the fallback.
#   AUTHORIZED USE ONLY.
# =============================================================================
#
#   Guaranteed backend: nmap OR python3 (one is enough). curl optional.
#
#   Quick start:
#     ./ftp-audit.sh ftp.example.com
#     ./ftp-audit.sh ftp.example.com:21 ftp.example.com:990
#     ./ftp-audit.sh --json ftp.example.com
#     ./ftp-audit.sh --nse-intrusive ftp.example.com    # actively test backdoors
#     ./ftp-audit.sh --no-nse ftp.example.com           # force python engine
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

PORTS_DEFAULT="21"
TIMEOUT=10
JSON=0
USE_NSE=1
NSE_INTRUSIVE=0
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
field()   { printf '    %s%-16s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }
jesc()    { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — FTP / FTPS service security analyser

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]

OPTIONS:
    -p, --ports LIST     Default ports when host has none (default: ${PORTS_DEFAULT}; e.g. 21,990)
        --nse-intrusive  Actively test vsftpd/proftpd backdoors (runs the exploit's
                         harmless 'id' probe — NOT read-only; off by default)
        --no-nse         Force the python3 engine even if nmap is installed
    -t, --timeout SEC    Connection timeout seconds (default: ${TIMEOUT})
        --json           Emit JSON (one object per host:port) instead of text
    -h, --help           Show this help

EXIT STATUS:
    0  no weaknesses found
    1  at least one weakness / finding
    2  usage error

SAFETY:
    Read-only by default. Anonymous login is tested but NOTHING is uploaded or
    deleted. Known-backdoor CVEs are flagged from the banner version only; the
    active backdoor trigger runs ONLY with --nse-intrusive. AUTHORIZED USE ONLY.
EOF
}

# ------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--ports)      PORTS_DEFAULT="${2:?}"; shift 2 ;;
        --nse-intrusive) NSE_INTRUSIVE=1; shift ;;
        --no-nse)        USE_NSE=0; shift ;;
        -t|--timeout)    TIMEOUT="${2:?}"; shift 2 ;;
        --json)          JSON=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)              err "unknown option: $1"; usage; exit 2 ;;
        *)               TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no hosts given"; usage; exit 2; }

ENGINE=""
if [[ ${USE_NSE} -eq 1 ]] && have nmap; then ENGINE="nmap"
elif have python3; then ENGINE="python3"
elif have nmap; then ENGINE="nmap"
else err "need nmap or python3"; exit 2; fi

# ---- embedded python3 FTP engine (banner, FEAT, AUTH TLS, anon login) -------
read -r -d '' FTP_PY <<'PYEOF' || true
import sys, socket, ssl
host=sys.argv[1]; port=int(sys.argv[2]); timeout=float(sys.argv[3])
implicit = (port==990)

def out(k,v):
    v=str(v).replace("\r"," ").replace("\n"," ").replace("\t"," ")
    sys.stdout.write("%s\t%s\n"%(k,v))

def recv(s):
    data=b""
    try:
        while True:
            chunk=s.recv(4096)
            if not chunk: break
            data+=chunk
            t=data.decode("latin1","replace")
            last=[l for l in t.split("\n") if l.strip()]
            if last:
                ll=last[-1].rstrip("\r")
                if (len(ll)>=4 and ll[3]==" ") or len(ll)==3: break
    except Exception:
        pass
    return data.decode("latin1","replace")

def code(resp):
    for l in resp.split("\n"):
        l=l.strip()
        if len(l)>=3 and l[:3].isdigit(): return l[:3]
    return ""

def send(s,cmd): s.sendall((cmd+"\r\n").encode("latin1","replace"))

try:
    raw=socket.create_connection((host,port),timeout=timeout)
except Exception as e:
    out("ERR","connect failed: %s"%e); sys.exit(0)
raw.settimeout(timeout)
s=raw
if implicit:
    try:
        ctx=ssl._create_unverified_context()
        s=ctx.wrap_socket(raw,server_hostname=host)
        ci=s.cipher()
        if ci: out("TLS_VERSION",ci[1])
        out("IMPLICIT_TLS","yes")
    except Exception as e:
        out("ERR","implicit TLS failed: %s"%e); sys.exit(0)

banner=recv(s)
out("BANNER", banner.split("\n")[0].strip())

# FEAT: enumerate extensions (AUTH TLS/SSL, PBSZ, PROT, MLST, EPSV, SIZE, REST)
send(s,"FEAT"); feat=recv(s)
auth_tls=False
for line in feat.split("\n"):
    f=line.strip().upper()
    if f[:3].isdigit(): f=f[4:].strip() if len(f)>4 else f
    if not f or f.startswith("211"): continue
    out("FEAT", f)
    if f.startswith("AUTH") and ("TLS" in f or "SSL" in f): auth_tls=True

# if FEAT hid it, confirm explicit TLS by trying AUTH TLS (no data channel used)
if not implicit and not auth_tls:
    send(s,"AUTH TLS"); r=recv(s)
    if code(r)=="234":
        auth_tls=True
        try:
            ctx=ssl._create_unverified_context()
            s=ctx.wrap_socket(raw,server_hostname=host)
            ci=s.cipher()
            if ci: out("TLS_VERSION",ci[1])
        except Exception: pass
out("AUTH_TLS","yes" if (auth_tls or implicit) else "no")

# anonymous login (read-only: PWD then QUIT, nothing is written)
send(s,"USER anonymous"); u=recv(s); uc=code(u)
anon="no"
if uc in ("331","332"):
    send(s,"PASS anonymous@arsenal-audit.example"); p=recv(s)
    if code(p)=="230":
        anon="yes"
        send(s,"SYST"); sy=recv(s)
        for l in sy.split("\n"):
            if l.strip()[:3]=="215": out("SYST", l.strip()[4:])
        send(s,"PWD"); recv(s)
elif uc=="230":
    anon="yes"
out("ANON", anon)
try: send(s,"QUIT"); recv(s)
except Exception: pass
PYEOF

# ---- known-vuln FTP fingerprint from banner --------------------------------
flag_ftp_cves() {  # <banner>
    local b="$1" v
    # vsFTPd 2.3.4 laughing-smiley backdoor — CVE-2011-2523 (shell on 6200/tcp)
    if echo "$b" | grep -qiE 'vsftpd'; then
        v="$(echo "$b" | grep -oiE 'vsftpd[ _]?[0-9][0-9.]*' | grep -oE '[0-9][0-9.]*' | head -1)"
        [[ "$v" == "2.3.4" ]] && PROBLEMS+=("vsFTPd 2.3.4 — CVE-2011-2523 backdoor (shell on 6200/tcp); --nse-intrusive to confirm")
    fi
    # ProFTPD mod_copy unauth RCE — CVE-2015-3306 (SITE CPFR/CPTO)
    if echo "$b" | grep -qiE 'proftpd'; then
        v="$(echo "$b" | grep -oiE 'proftpd[ _]?[0-9][0-9.a-z]*' | grep -oiE '1\.3\.[0-9][0-9a-z]*' | head -1)"
        echo "$v" | grep -qiE '^1\.3\.5$|^1\.3\.6rc[0-9]' && \
            PROBLEMS+=("ProFTPD ${v} — CVE-2015-3306 mod_copy unauth file read/write RCE (SITE CPFR/CPTO); verify with cve-lookup")
    fi
}

# ---- nmap NSE engine --------------------------------------------------------
nse_probe() {  # <host> <port>
    local host="$1" port="$2" out scripts
    scripts="ftp-anon,ftp-syst,ftp-bounce,ssl-cert"
    [[ ${NSE_INTRUSIVE} -eq 1 ]] && scripts="${scripts},ftp-vsftpd-backdoor,ftp-proftpd-backdoor"
    out="$(nmap -Pn -p "$port" --script "$scripts" --host-timeout "$((TIMEOUT*6))"s "$host" 2>/dev/null)"
    # only an OPEN port yields a banner — a 'closed'/'filtered' port line must not be mistaken for one
    NSE_BANNER="$(echo "$out" | grep -iE "^${port}/tcp[[:space:]]+open" | sed -E 's#.*/tcp[[:space:]]+open[[:space:]]+[^[:space:]]+[[:space:]]*##' | head -1 | tr -d '\r')"
    [[ -z "$NSE_BANNER" ]] && NSE_BANNER="$(echo "$out" | grep -iE 'Service Info:' | head -1 | sed 's/Service Info: //' | tr -d '\r')"
    echo "$out" | grep -qiE 'ftp-anon:.*Anonymous FTP login allowed' && NSE_ANON="yes" || NSE_ANON="no"
    echo "$out" | grep -qiE 'ftp-bounce:.*bounce working|FXP' && PROBLEMS+=("FTP bounce (FXP) allowed: nmap ftp-bounce reports PORT-to-third-host working")
    echo "$out" | grep -qiE 'ssl-cert:|AUTH TLS|AUTH SSL' && NSE_AUTHTLS="yes" || NSE_AUTHTLS="no"
    echo "$out" | grep -qiE 'vsftpd-backdoor:.*VULNERABLE|This is a backdoor' && PROBLEMS+=("vsFTPd backdoor CONFIRMED by nmap (CVE-2011-2523)")
    echo "$out" | grep -qiE 'proftpd-backdoor:.*VULNERABLE' && PROBLEMS+=("ProFTPD backdoor CONFIRMED by nmap")
}

# ---- python3 engine ---------------------------------------------------------
py_probe() {  # <host> <port>
    local host="$1" port="$2" k v
    PY_BANNER=""; PY_ANON=""; PY_AUTHTLS=""; PY_IMPLICIT=""; PY_TLS=""; PY_SYST=""; PY_DEAD=1
    while IFS=$'\t' read -r k v; do
        case "$k" in
            BANNER)       PY_BANNER="$v"; PY_DEAD=0 ;;
            ANON)         PY_ANON="$v" ;;
            AUTH_TLS)     PY_AUTHTLS="$v" ;;
            IMPLICIT_TLS) PY_IMPLICIT="$v" ;;
            TLS_VERSION)  PY_TLS="$v" ;;
            SYST)         PY_SYST="$v" ;;
            ERR)          PROBLEMS+=("probe error: $v") ;;
        esac
    done < <(python3 -I -c "$FTP_PY" "$host" "$port" "$TIMEOUT" 2>/dev/null)
}

# ------------------------------------------------------------------- audit --
audit_target() {
    local target="$1" host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORTS_DEFAULT%%,*}"; fi

    PROBLEMS=()
    local banner="" anon="" authtls="" tls="" syst="" reachable="true"
    NSE_BANNER=""; NSE_ANON=""; NSE_AUTHTLS=""
    PY_BANNER=""; PY_ANON=""; PY_AUTHTLS=""; PY_IMPLICIT=""; PY_TLS=""; PY_SYST=""; PY_DEAD=1

    if [[ "$ENGINE" == "nmap" ]]; then
        nse_probe "$host" "$port"
        banner="$NSE_BANNER"; anon="$NSE_ANON"; authtls="$NSE_AUTHTLS"
        [[ -z "$banner" && "$anon" != "yes" ]] && reachable="false"
        # the python engine also runs to get FEAT/AUTH-TLS detail nmap may miss
        if have python3; then
            py_probe "$host" "$port"
            [[ -z "$banner" ]] && banner="$PY_BANNER"
            [[ "$PY_ANON" == "yes" ]] && anon="yes"
            [[ "$PY_AUTHTLS" == "yes" || "$PY_IMPLICIT" == "yes" ]] && authtls="yes"
            tls="$PY_TLS"; syst="$PY_SYST"
            [[ ${PY_DEAD} -eq 0 ]] && reachable="true"
        fi
    else
        py_probe "$host" "$port"
        banner="$PY_BANNER"; anon="$PY_ANON"; tls="$PY_TLS"; syst="$PY_SYST"
        [[ "$PY_AUTHTLS" == "yes" || "$PY_IMPLICIT" == "yes" ]] && authtls="yes" || authtls="no"
        [[ ${PY_DEAD} -eq 1 ]] && reachable="false"
    fi

    if [[ "$reachable" == "false" ]]; then
        [[ ${JSON} -eq 0 ]] && { section "${host}:${port}  (engine: ${ENGINE})"; err "no FTP response (host down, filtered, or not FTP)"; }
        [[ ${JSON} -eq 1 ]] && printf '{"tool":"ftp-audit","host":"%s","port":"%s","reachable":false,"problems":[]}\n' "$(jesc "$host")" "$(jesc "$port")"
        return   # unreachable is not a security finding (exit stays 0), matching snmp/smtp/db
    fi

    # findings
    [[ "$anon" == "yes" ]] && PROBLEMS+=("anonymous login allowed (USER anonymous accepted; verify what is exposed)")
    if [[ "$authtls" != "yes" && "$port" != "990" ]]; then
        PROBLEMS+=("no explicit AUTH TLS/SSL — credentials & data sent in cleartext")
    fi
    flag_ftp_cves "$banner"

    [[ ${#PROBLEMS[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${PROBLEMS[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"ftp-audit","host":"%s","port":"%s","reachable":true,"engine":"%s",' \
            "$(jesc "$host")" "$(jesc "$port")" "$ENGINE"
        printf '"banner":"%s","anonymous":"%s","auth_tls":"%s","tls":"%s","syst":"%s","problems":[%s]}\n' \
            "$(jesc "$banner")" "$(jesc "$anon")" "$(jesc "$authtls")" "$(jesc "$tls")" "$(jesc "$syst")" "$pj"
        return
    fi

    section "${host}:${port}  (engine: ${ENGINE})"
    field "Banner"   "${banner:-?}"
    field "Anonymous" "${anon:-?}"
    field "AUTH TLS" "${authtls:-?}"
    [[ -n "$tls" ]]  && field "TLS" "$tls"
    [[ -n "$syst" ]] && field "SYST" "$syst"
    if [[ ${#PROBLEMS[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${PROBLEMS[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "ftp-audit — ${#TARGETS[@]} target(s), engine=${ENGINE}, timeout ${TIMEOUT}s  (AUTHORIZED USE ONLY)"
for t in "${TARGETS[@]}"; do
    if [[ "$t" == *:* ]]; then
        audit_target "$t"
    else
        IFS=',' read -ra plist <<<"$PORTS_DEFAULT"
        for pp in "${plist[@]}"; do audit_target "${t}:${pp}"; done
    fi
done
exit "${EXIT_CODE}"
