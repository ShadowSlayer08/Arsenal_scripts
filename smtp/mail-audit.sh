#!/usr/bin/env bash
#
# mail-audit.sh — SMTP / submission service security analyser
# =============================================================================
#   Read-only posture check for one or more SMTP services (25/465/587). Reports:
#     * banner / MTA + version   — Postfix/Exim/Sendmail/OpenSMTPD disclosure
#     * STARTTLS + certificate   — offered? negotiated TLS version; cert summary
#     * AUTH over cleartext      — AUTH advertised before STARTTLS (credential leak)
#     * open relay (SAFE)        — MAIL/RCPT to an external pair, NEVER sends DATA
#     * VRFY / EXPN              — user-enumeration verbs enabled?
#     * user enumeration         — opt-in VRFY/EXPN/RCPT run against a wordlist
#     * SPF / DMARC cross-ref    — quick sender-auth check (see dns-audit for depth)
#     * known-vuln MTA versions  — Exim CVE-2019-10149, OpenSMTPD CVE-2020-7247,
#                                  SMTP-smuggling CVE-2023-51764/65/66 (→ cve-lookup)
#   Default engine is nmap NSE; a self-contained python3 engine is the fallback.
#   swaks / smtp-user-enum are used when present. Assess servers you are
#   authorized to test — AUTHORIZED USE ONLY.
# =============================================================================
#
#   Guaranteed backend: nmap OR python3 (one is enough). curl not required here.
#   Optional (preferred when present): swaks, smtp-user-enum, dig, openssl.
#
#   Quick start:
#     ./mail-audit.sh mail.example.com
#     ./mail-audit.sh mail.example.com:587 mail.example.com:465
#     ./mail-audit.sh --json mail.example.com
#     ./mail-audit.sh --domain example.com mail.example.com      # SPF/DMARC for domain
#     ./mail-audit.sh --enum-users users.txt --method RCPT mail.example.com
#     ./mail-audit.sh --no-relay-test mail.example.com           # skip relay probe
#     ./mail-audit.sh --no-nse mail.example.com                  # force python engine
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

PORTS_DEFAULT="25"
TIMEOUT=10
JSON=0
USE_NSE=1
DO_RELAY=1
DOMAIN=""
ENUM_FILE=""
ENUM_METHOD="RCPT"
RELAY_FROM="relay-test@arsenal-audit.example.org"
RELAY_TO="relay-test@arsenal-audit.example.net"
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
field()   { printf '    %s%-18s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }
jesc()    { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — SMTP / submission service security analyser

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]

OPTIONS:
    -p, --ports LIST      Default ports when host has none (default: ${PORTS_DEFAULT}; e.g. 25,465,587)
    -d, --domain DOMAIN   Domain to cross-ref SPF/DMARC for (default: derived from host)
        --enum-users FILE Opt-in user enumeration wordlist (one name per line)
        --method M        Enumeration method: VRFY | EXPN | RCPT (default: ${ENUM_METHOD})
        --no-relay-test   Skip the (safe, non-delivering) open-relay probe
        --no-nse          Force the python3 engine even if nmap is installed
    -t, --timeout SEC     Connection timeout seconds (default: ${TIMEOUT})
        --json            Emit JSON (one object per host:port) instead of text
    -h, --help            Show this help

EXIT STATUS:
    0  no weaknesses found
    1  at least one weakness / finding
    2  usage error

SAFETY:
    Read-only / non-destructive. The open-relay test issues MAIL FROM + RCPT TO
    then RSET/QUIT — it NEVER sends DATA, so no message is ever relayed. User
    enumeration is OFF unless --enum-users is given. AUTHORIZED USE ONLY.
EOF
}

# ------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--ports)    PORTS_DEFAULT="${2:?}"; shift 2 ;;
        -d|--domain)   DOMAIN="${2:?}"; shift 2 ;;
        --enum-users)  ENUM_FILE="${2:?}"; shift 2 ;;
        --method)      ENUM_METHOD="${2:?}"; shift 2 ;;
        --no-relay-test) DO_RELAY=0; shift ;;
        --no-nse)      USE_NSE=0; shift ;;
        -t|--timeout)  TIMEOUT="${2:?}"; shift 2 ;;
        --json)        JSON=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)            err "unknown option: $1"; usage; exit 2 ;;
        *)             TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no hosts given"; usage; exit 2; }

ENUM_METHOD="${ENUM_METHOD^^}"
case "$ENUM_METHOD" in VRFY|EXPN|RCPT) ;; *) err "invalid --method: $ENUM_METHOD"; exit 2 ;; esac
[[ -n "$ENUM_FILE" && ! -r "$ENUM_FILE" ]] && { err "cannot read --enum-users file: $ENUM_FILE"; exit 2; }

# engine: nmap preferred (default backend), python3 is the universal fallback
ENGINE=""
if [[ ${USE_NSE} -eq 1 ]] && have nmap; then ENGINE="nmap"
elif have python3; then ENGINE="python3"
elif have nmap; then ENGINE="nmap"
else err "need nmap or python3"; exit 2; fi

# ---- embedded python3 SMTP engine (fallback + enum) -------------------------
# Prints TAB-separated KEY<TAB>VALUE lines. Never sends DATA. Implicit TLS is
# used automatically on port 465.
read -r -d '' SMTP_PY <<'PYEOF' || true
import sys, socket, ssl
host=sys.argv[1]; port=int(sys.argv[2]); timeout=float(sys.argv[3])
action=sys.argv[4]                      # probe | enum
do_relay=sys.argv[5]=="1"
rfrom=sys.argv[6]; rto=sys.argv[7]
method=sys.argv[8] if len(sys.argv)>8 else "RCPT"
implicit = (port==465)

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
        if ci: out("TLS_VERSION",ci[1]); out("TLS_CIPHER",ci[0])
        try:
            der=s.getpeercert(binary_form=True)
            if der: out("TLS_CERT","present (%d bytes)"%len(der))
        except Exception: pass
        out("STARTTLS","implicit")
    except Exception as e:
        out("ERR","implicit TLS failed: %s"%e); sys.exit(0)

banner=recv(s)
out("BANNER", banner.split("\n")[0].strip())

send(s,"EHLO arsenal-audit.local")
ehlo=recv(s)
caps=set()
for line in ehlo.split("\n"):
    line=line.strip()
    if len(line)>4 and line[:3].isdigit():
        caps.add(line[4:].strip().upper())
for c in sorted(caps):
    out("CAP", c)
has_starttls = any(c.startswith("STARTTLS") for c in caps)
has_auth = any(c.startswith("AUTH") for c in caps)
if not implicit:
    out("STARTTLS", "yes" if has_starttls else "no")
# AUTH advertised on a cleartext (non-TLS) channel = credential exposure
if has_auth and not implicit:
    out("AUTH_CLEARTEXT","yes")

# upgrade via STARTTLS to report negotiated TLS (no auth, no mail)
if has_starttls and not implicit:
    send(s,"STARTTLS")
    st=recv(s)
    if code(st)=="220":
        try:
            ctx=ssl._create_unverified_context()
            s=ctx.wrap_socket(raw,server_hostname=host)
            ci=s.cipher()
            if ci: out("TLS_VERSION",ci[1]); out("TLS_CIPHER",ci[0])
            try:
                der=s.getpeercert(binary_form=True)
                if der: out("TLS_CERT","present (%d bytes)"%len(der))
            except Exception: pass
            send(s,"EHLO arsenal-audit.local"); recv(s)
        except Exception as e:
            out("STARTTLS","failed: %s"%e)

def verb_enabled(verb):
    send(s,"%s root"%verb); r=recv(s); c=code(r)
    # 5xx with "not implemented/disabled" => disabled; 250/251/252/550-user => enabled verb
    if c in ("500","502","252") :
        return "disabled" if c in ("500","502") else "enabled"
    if c.startswith("2") or c=="550" or c=="551" or c=="553":
        return "enabled"
    return "unknown"

if action=="probe":
    out("VRFY", verb_enabled("VRFY"))
    out("EXPN", verb_enabled("EXPN"))
    if do_relay:
        # SAFE open-relay test: offer an external sender + external recipient.
        # Acceptance of RCPT TO (2xx) means relay is permitted. DATA is NEVER
        # sent, so nothing is ever delivered. Always RSET/QUIT afterwards.
        send(s,"RSET"); recv(s)
        send(s,"MAIL FROM:<%s>"%rfrom); mf=recv(s)
        if code(mf).startswith("2"):
            send(s,"RCPT TO:<%s>"%rto); rc=recv(s)
            out("RELAY","open" if code(rc).startswith("2") else "closed")
        else:
            out("RELAY","closed")
        send(s,"RSET"); recv(s)
    send(s,"QUIT"); recv(s)

elif action=="enum":
    # read candidate users on stdin; report which the server treats as valid
    send(s,"RSET"); recv(s)
    dom=host
    for raw_name in sys.stdin:
        name=raw_name.strip()
        if not name or name.startswith("#"): continue
        if method=="VRFY":
            send(s,"VRFY %s"%name); r=recv(s); c=code(r)
            if c in ("250","251","252"): out("USER_FOUND",name)
        elif method=="EXPN":
            send(s,"EXPN %s"%name); r=recv(s); c=code(r)
            if c in ("250","251","252"): out("USER_FOUND",name)
        else:  # RCPT
            send(s,"MAIL FROM:<%s>"%rfrom); recv(s)
            send(s,"RCPT TO:<%s@%s>"%(name,dom)); r=recv(s); c=code(r)
            if c in ("250","251"): out("USER_FOUND",name)
            send(s,"RSET"); recv(s)
    send(s,"QUIT"); recv(s)
PYEOF

# ---- TXT lookup (dig preferred, python3 UDP fallback) -----------------------
read -r -d '' TXT_PY <<'PYEOF' || true
import sys, socket, struct, random
name=sys.argv[1].rstrip("."); server=sys.argv[2]; timeout=float(sys.argv[3])
def enc(n):
    o=b""
    for p in n.split("."):
        if p: o+=bytes([len(p)])+p.encode()
    return o+b"\x00"
tid=random.randint(0,65535)
pkt=struct.pack(">HHHHHH",tid,0x0100,1,0,0,0)+enc(name)+struct.pack(">HH",16,1)
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(pkt,(server,53)); data,_=s.recvfrom(65535); s.close()
except Exception:
    sys.exit(0)
def rdname(d,o):
    lab=[]; jumped=False; start=o
    while True:
        if o>=len(d): break
        ln=d[o]
        if ln&0xC0==0xC0:
            if not jumped: start=o+2
            o=struct.unpack(">H",d[o:o+2])[0]&0x3FFF; jumped=True; continue
        if ln==0:
            o+=1
            if not jumped: start=o
            break
        lab.append(d[o+1:o+1+ln].decode("latin1")); o+=1+ln
    return ".".join(lab),(start if jumped else o)
try:
    qd=struct.unpack(">H",data[4:6])[0]; an=struct.unpack(">H",data[6:8])[0]; o=12
    for _ in range(qd):
        _,o=rdname(data,o); o+=4
    for _ in range(an):
        _,o=rdname(data,o)
        rtype,_,_,rdlen=struct.unpack(">HHIH",data[o:o+10]); o+=10
        rd=data[o:o+rdlen]
        if rtype==16:
            i=0; parts=[]
            while i<rdlen:
                sl=rd[i]; parts.append(rd[i+1:i+1+sl].decode("latin1")); i+=1+sl
            print("".join(parts))
        o+=rdlen
except Exception:
    sys.exit(0)
PYEOF

PY_NS="${ARSENAL_DNS:-}"
if [[ -z "$PY_NS" && -r /etc/resolv.conf ]]; then
    PY_NS="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
fi
[[ -z "$PY_NS" ]] && PY_NS="1.1.1.1"

txt_lookup() {  # <name> -> TXT records, one per line
    local name="$1"
    if have dig; then
        dig +time="$TIMEOUT" +tries=1 +short TXT "$name" 2>/dev/null | sed 's/^"//; s/"$//; s/" "//g' | tr -d '\r'
    elif have python3; then
        python3 -I -c "$TXT_PY" "$name" "$PY_NS" "$TIMEOUT" 2>/dev/null | tr -d '\r'
    fi
}

# cross-ref SPF/DMARC for a domain; appends to the global PROBLEMS array
check_sender_auth() {  # <domain>
    local d="$1" spf="" dmarc="" txt
    [[ -z "$d" ]] && return
    txt="$(txt_lookup "$d")"
    while IFS= read -r l; do [[ "$l" == v=spf1* ]] && spf="$l"; done <<<"$txt"
    dmarc="$(txt_lookup "_dmarc.$d" | grep -i 'v=DMARC1' | head -1)"
    SPF_VAL="$spf"; DMARC_VAL="$dmarc"
    if [[ -z "$spf" ]]; then PROBLEMS+=("SPF: no record for ${d} (sender spoofing easier; see dns-audit)")
    elif echo "$spf" | grep -qiE '(^| )\+?all' && ! echo "$spf" | grep -qiE '[~-]all'; then
        PROBLEMS+=("SPF: ${d} ends in +all/all (permits any sender)")
    fi
    if [[ -z "$dmarc" ]]; then PROBLEMS+=("DMARC: no record for ${d} (see dns-audit)")
    elif echo "$dmarc" | grep -qiE '(^|[;[:space:]])p=none'; then PROBLEMS+=("DMARC: ${d} policy p=none (monitor only, not enforced)")
    fi
}

# ---- known-vuln MTA fingerprint from banner/EHLO ---------------------------
# Flags flagship pre-auth / RCE CVEs by advertised version. Verify with cve-lookup.
flag_mta_cves() {  # <banner-string>
    local b="$1" v
    # Exim "Return of the WIZard" RCE — CVE-2019-10149 (4.87..4.91)
    if echo "$b" | grep -qiE 'exim'; then
        v="$(echo "$b" | grep -oiE 'exim[ _]?[0-9][0-9.]*' | grep -oE '[0-9][0-9.]*' | head -1)"
        if [[ -n "$v" ]] && awk -v x="$v" 'BEGIN{split(x,a,"."); maj=a[1]+0; min=a[2]+0; exit !(maj==4 && min>=87 && min<=91)}'; then
            PROBLEMS+=("Exim ${v}: in 4.87-4.91 range — CVE-2019-10149 RCE (CISA KEV); verify with cve-lookup")
        fi
        echo "$b" | grep -qoiE 'exim[ _]?4\.(9[0-6]|[0-8][0-9])\b' && \
            PROBLEMS+=("Exim ${v:-<4.97.1}: SMTP smuggling exposure — CVE-2023-51766 (confirm config)")
    fi
    # OpenSMTPD MAIL FROM RCE — CVE-2020-7247 (6.6)
    if echo "$b" | grep -qiE 'opensmtpd'; then
        v="$(echo "$b" | grep -oiE 'opensmtpd[ _]?[0-9][0-9.p]*' | grep -oE '[0-9][0-9.p]*' | head -1)"
        echo "$b" | grep -qiE 'opensmtpd[ _]?6\.(4|5|6)' && \
            PROBLEMS+=("OpenSMTPD ${v}: 6.4-6.6 range — CVE-2020-7247 unauth RCE (CISA KEV); verify with cve-lookup")
    fi
    # Postfix / Sendmail SMTP smuggling — CVE-2023-51764 / CVE-2023-51765 (config-dependent)
    echo "$b" | grep -qiE 'postfix' && \
        PROBLEMS+=("Postfix detected: check SMTP-smuggling exposure CVE-2023-51764 (<=3.8.4, config-dependent)")
    echo "$b" | grep -qiE 'sendmail' && \
        PROBLEMS+=("Sendmail detected: check SMTP-smuggling exposure CVE-2023-51765 (<8.18)")
}

# ---- nmap NSE engine --------------------------------------------------------
nse_probe() {  # <host> <port>  -> sets NSE_* and appends PROBLEMS
    local host="$1" port="$2" out scripts
    scripts="smtp-commands,smtp-ntlm-info,ssl-cert,ssl-enum-ciphers"
    # the open-relay probe is an active (safe, non-delivering) transaction — honor --no-relay-test
    local relay_args=()
    [[ ${DO_RELAY} -eq 1 ]] && { scripts="${scripts},smtp-open-relay"
        relay_args=(--script-args "smtp-open-relay.from=${RELAY_FROM},smtp-open-relay.to=${RELAY_TO}"); }
    [[ -n "$ENUM_FILE" ]] && scripts="${scripts},smtp-enum-users"
    out="$(nmap -Pn -p "$port" --script "$scripts" "${relay_args[@]}" \
            --host-timeout "$((TIMEOUT*6))"s "$host" 2>/dev/null)"
    NSE_RAW="$out"
    # banner / EHLO line from smtp-commands
    NSE_BANNER="$(echo "$out" | awk '/smtp-commands:/{getline; print; exit}' | sed 's/^| *//; s/^|_ *//' | tr -d '\r')"
    [[ -z "$NSE_BANNER" ]] && NSE_BANNER="$(echo "$out" | grep -iE 'Service Info:|product:' | head -1 | tr -d '\r')"
    echo "$out" | grep -qiE 'smtp-open-relay:.*Server is an open relay|appears to be an open relay' && \
        PROBLEMS+=("open relay: nmap smtp-open-relay reports relaying permitted (safe test, no DATA sent)")
    # only a false 'cleartext' claim if the host actually responded (empty out = dead/filtered)
    [[ -n "$out" ]] && ! grep -qiE 'STARTTLS' <<<"$out" && PROBLEMS+=("STARTTLS: not advertised (cleartext mail transport)")
    NSE_TLS="$(echo "$out" | grep -oiE 'TLSv1\.[0-3]|SSLv[23]' | sort -u | paste -sd, -)"
    echo "$out" | grep -qiE 'SSLv[23]|TLSv1\.0|TLSv1\.1' && \
        PROBLEMS+=("weak TLS offered on SMTP: $(echo "$out" | grep -oiE 'SSLv[23]|TLSv1\.[01]' | sort -u | paste -sd, -) (see ssl-audit)")
    # user-enum results
    if [[ -n "$ENUM_FILE" ]]; then
        local found
        found="$(echo "$out" | sed -n '/smtp-enum-users:/,/^[^|]/p' | grep -oE 'Found: .*' | sed 's/Found: //')"
        [[ -n "$found" ]] && PROBLEMS+=("user enumeration (nmap): ${found//$'\n'/, }")
    fi
    flag_mta_cves "$NSE_BANNER"
}

# ---- native-tool enumeration (preferred when present) -----------------------
enum_users_native() {  # <host> <port>  -> prints found users, one per line
    local host="$1" port="$2"
    if have smtp-user-enum; then
        smtp-user-enum -M "$ENUM_METHOD" -U "$ENUM_FILE" -t "$host" -p "$port" 2>/dev/null \
            | awk '/exists/{print $1}' | sort -u
    elif have swaks && [[ "$ENUM_METHOD" != "RCPT" ]]; then
        local u
        while IFS= read -r u; do
            u="${u%%#*}"; u="${u//[[:space:]]/}"; [[ -z "$u" ]] && continue
            swaks --server "$host:$port" --quit-after "$ENUM_METHOD" --"${ENUM_METHOD,,}" "$u" 2>/dev/null \
                | grep -qE '^<-  25[012]' && echo "$u"
        done < "$ENUM_FILE"
    else
        python3 -I -c "$SMTP_PY" "$host" "$port" "$TIMEOUT" enum "$DO_RELAY" "$RELAY_FROM" "$RELAY_TO" "$ENUM_METHOD" \
            < "$ENUM_FILE" 2>/dev/null | awk -F'\t' '$1=="USER_FOUND"{print $2}'
    fi
}

# ---- python3 engine ---------------------------------------------------------
py_probe() {  # <host> <port>
    local host="$1" port="$2" k v
    PY_BANNER=""; PY_STARTTLS=""; PY_TLS=""; PY_AUTHCLEAR=""; PY_VRFY=""; PY_EXPN=""; PY_RELAY=""
    while IFS=$'\t' read -r k v; do
        case "$k" in
            BANNER)        PY_BANNER="$v" ;;
            STARTTLS)      PY_STARTTLS="$v" ;;
            TLS_VERSION)   PY_TLS="$v" ;;
            AUTH_CLEARTEXT) PY_AUTHCLEAR="$v" ;;
            VRFY)          PY_VRFY="$v" ;;
            EXPN)          PY_EXPN="$v" ;;
            RELAY)         PY_RELAY="$v" ;;
            ERR)           PROBLEMS+=("probe error: $v") ;;
        esac
    done < <(python3 -I -c "$SMTP_PY" "$host" "$port" "$TIMEOUT" probe "$DO_RELAY" "$RELAY_FROM" "$RELAY_TO" "$ENUM_METHOD" 2>/dev/null)

    [[ -z "$PY_BANNER" && -z "$PY_STARTTLS" ]] && { PROBLEMS+=("no SMTP response (host down, filtered, or not SMTP)"); return 1; }
    [[ "$PY_STARTTLS" == "no" ]] && PROBLEMS+=("STARTTLS: not advertised (cleartext mail transport)")
    [[ "$PY_AUTHCLEAR" == "yes" ]] && PROBLEMS+=("AUTH advertised over cleartext (credentials exposed before STARTTLS)")
    [[ "$PY_VRFY" == "enabled" ]] && PROBLEMS+=("VRFY enabled (user enumeration verb)")
    [[ "$PY_EXPN" == "enabled" ]] && PROBLEMS+=("EXPN enabled (user/alias enumeration verb)")
    [[ "$PY_RELAY" == "open" ]] && PROBLEMS+=("OPEN RELAY: external MAIL FROM + RCPT TO accepted (safe test, no DATA sent)")
    flag_mta_cves "$PY_BANNER"
    return 0
}

# ------------------------------------------------------------------- audit --
audit_target() {
    local target="$1" host port dom
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORTS_DEFAULT%%,*}"; fi
    dom="$DOMAIN"; [[ -z "$dom" && "$host" == *.*.* ]] && dom="${host#*.}"
    [[ -z "$dom" && "$host" == *.* ]] && dom="$host"

    PROBLEMS=(); SPF_VAL=""; DMARC_VAL=""
    local banner="" starttls="" tls="" reachable="true"
    NSE_BANNER=""; NSE_TLS=""; NSE_RAW=""
    PY_BANNER=""; PY_STARTTLS=""; PY_TLS=""; PY_AUTHCLEAR=""; PY_VRFY=""; PY_EXPN=""; PY_RELAY=""

    if [[ "$ENGINE" == "nmap" ]]; then
        nse_probe "$host" "$port"
        banner="$NSE_BANNER"; tls="$NSE_TLS"
        echo "$NSE_RAW" | grep -qiE 'STARTTLS' && starttls="yes" || starttls="no"
        [[ "$port" == "465" ]] && starttls="implicit"
    else
        if py_probe "$host" "$port"; then :; else reachable="false"; fi
        banner="$PY_BANNER"; starttls="$PY_STARTTLS"; tls="$PY_TLS"
    fi

    # user enumeration (opt-in) — prefer native tools, fall back to python
    local enum_found=""
    if [[ -n "$ENUM_FILE" && "$reachable" == "true" ]]; then
        enum_found="$(enum_users_native "$host" "$port" | paste -sd, -)"
        [[ -n "$enum_found" ]] && PROBLEMS+=("user enumeration (${ENUM_METHOD}) valid: ${enum_found}")
    fi

    # SPF / DMARC cross-reference (independent of the SMTP engine)
    check_sender_auth "$dom"

    [[ ${#PROBLEMS[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${PROBLEMS[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"mail-audit","host":"%s","port":"%s","reachable":%s,"engine":"%s",' \
            "$(jesc "$host")" "$(jesc "$port")" "$reachable" "$ENGINE"
        printf '"banner":"%s","starttls":"%s","tls":"%s","spf":"%s","dmarc":"%s","users":"%s","problems":[%s]}\n' \
            "$(jesc "$banner")" "$(jesc "$starttls")" "$(jesc "$tls")" \
            "$(jesc "$SPF_VAL")" "$(jesc "$DMARC_VAL")" "$(jesc "$enum_found")" "$pj"
        return
    fi

    section "${host}:${port}  (engine: ${ENGINE})"
    field "Banner"    "${banner:-?}"
    field "STARTTLS"  "${starttls:-?}"
    [[ -n "$tls" ]]       && field "TLS"   "$tls"
    [[ -n "$SPF_VAL" ]]   && field "SPF"   "$SPF_VAL"
    [[ -n "$DMARC_VAL" ]] && field "DMARC" "$DMARC_VAL"
    [[ -n "$enum_found" ]] && field "Users" "$enum_found"
    if [[ ${#PROBLEMS[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${PROBLEMS[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "mail-audit — ${#TARGETS[@]} target(s), engine=${ENGINE}, timeout ${TIMEOUT}s  (AUTHORIZED USE ONLY)"
for t in "${TARGETS[@]}"; do
    # expand a bare host into each default port when no :port was given
    if [[ "$t" == *:* ]]; then
        audit_target "$t"
    else
        IFS=',' read -ra plist <<<"$PORTS_DEFAULT"
        for pp in "${plist[@]}"; do audit_target "${t}:${pp}"; done
    fi
done
exit "${EXIT_CODE}"
