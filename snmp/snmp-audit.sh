#!/usr/bin/env bash
#
# snmp-audit.sh — SNMP exposure & community-string analyser (UDP/161)
# =============================================================================
#   Read-only posture check for one or more SNMP agents. Reports:
#     * reachability            — does the agent answer at all?
#     * community guessing      — small default list (public/private/...) over
#                                 v2c then v1; any reply == readable SNMP
#     * version in use          — SNMPv1 / v2c (no auth, cleartext) vs v3 (USM)
#     * v3 availability          — engine-ID discovery probe (Report PDU)
#     * sysDescr highlights     — OS / device / software banner (→ cve-lookup)
#     * info exposure           — system group readable (contact/location/name)
#     * writable-community risk — heuristic by default; opt-in no-op SET test
#                                 (--write-test, needs snmpset). Net-SNMP <=5.8
#                                 + RW == CVE-2020-15862 EXTEND-MIB root RCE.
#   Default engine is nmap NSE; a self-contained python3 engine is the fallback.
#   onesixtyone / snmpwalk / snmp-check are used when present. AUTHORIZED USE ONLY.
# =============================================================================
#
#   Guaranteed backend: nmap OR python3 (one is enough).
#   Optional (preferred when present): onesixtyone, snmpwalk, snmpget, snmpset,
#   snmp-check.
#
#   Quick start:
#     ./snmp-audit.sh 203.0.113.10
#     ./snmp-audit.sh --communities public,private,community 203.0.113.10
#     ./snmp-audit.sh --json 203.0.113.10
#     ./snmp-audit.sh --write-test 203.0.113.10        # opt-in, needs snmpset
#     ./snmp-audit.sh --no-nse 203.0.113.10            # force python engine
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

PORT_DEFAULT=161
TIMEOUT=5
JSON=0
USE_NSE=1
WRITE_TEST=0
COMMUNITIES="public,private,community,manager,cisco,snmp,admin,default,read,write,test,guest,security,monitor,netman"
COMM_FILE=""
TARGETS=()
EXIT_CODE=0
# community names commonly configured read-write (heuristic risk flag)
RW_LIKELY="private|write|manager|admin|secret|rw|netman|security"

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
${C_BOLD}${SCRIPT_NAME}${C_RST} — SNMP exposure & community-string analyser

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]

OPTIONS:
    -c, --communities LIST  Comma-separated community list to try (default: built-in small list)
    -C, --community-file F  File of community strings, one per line
    -p, --port PORT         Default UDP port (default: ${PORT_DEFAULT})
        --write-test        Opt-in writable-community probe via snmpset (no-op SET of
                            sysLocation back to its own value). Requires net-snmp snmpset.
        --no-nse            Force the python3 engine even if nmap is installed
    -t, --timeout SEC       Per-request timeout seconds (default: ${TIMEOUT})
        --json              Emit JSON (one object per host) instead of text
    -h, --help              Show this help

EXIT STATUS:
    0  no readable community / no issues
    1  at least one weakness / finding
    2  usage error

SAFETY:
    Read-only by default — community guessing and GETs only. The writable test is
    OFF unless --write-test is given, and even then it writes a value back to
    itself (no state change). AUTHORIZED USE ONLY.
EOF
}

# ------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--communities)   COMMUNITIES="${2:?}"; shift 2 ;;
        -C|--community-file) COMM_FILE="${2:?}"; shift 2 ;;
        -p|--port)          PORT_DEFAULT="${2:?}"; shift 2 ;;
        --write-test)       WRITE_TEST=1; shift ;;
        --no-nse)           USE_NSE=0; shift ;;
        -t|--timeout)       TIMEOUT="${2:?}"; shift 2 ;;
        --json)             JSON=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        --)                 shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)                 err "unknown option: $1"; usage; exit 2 ;;
        *)                  TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no hosts given"; usage; exit 2; }

# build community list (file overrides/extends the default)
if [[ -n "$COMM_FILE" ]]; then
    [[ -r "$COMM_FILE" ]] || { err "cannot read --community-file: $COMM_FILE"; exit 2; }
    COMMUNITIES=""
    while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && COMMUNITIES+="${COMMUNITIES:+,}$l"; done < "$COMM_FILE"
fi

ENGINE=""
if [[ ${USE_NSE} -eq 1 ]] && have nmap; then ENGINE="nmap"
elif have python3; then ENGINE="python3"
elif have nmap; then ENGINE="nmap"
else err "need nmap or python3"; exit 2; fi

# ---- embedded python3 SNMP engine (BER GetRequest; v1/v2c + v3 discovery) ---
read -r -d '' SNMP_PY <<'PYEOF' || true
import sys, socket, struct, random
host=sys.argv[1]; port=int(sys.argv[2]); timeout=float(sys.argv[3])
communities=[c for c in sys.argv[4].split(",") if c]
OIDS=[("sysDescr","1.3.6.1.2.1.1.1.0"),("sysObjectID","1.3.6.1.2.1.1.2.0"),
      ("sysUpTime","1.3.6.1.2.1.1.3.0"),("sysContact","1.3.6.1.2.1.1.4.0"),
      ("sysName","1.3.6.1.2.1.1.5.0"),("sysLocation","1.3.6.1.2.1.1.6.0")]

def out(*a): sys.stdout.write("\t".join(str(x).replace("\t"," ").replace("\n"," ").replace("\r"," ") for x in a)+"\n")
def enc_len(n):
    if n<0x80: return bytes([n])
    b=[]
    while n: b.insert(0,n&0xff); n>>=8
    return bytes([0x80|len(b)])+bytes(b)
def tlv(tag,val): return bytes([tag])+enc_len(len(val))+val
def enc_int(n):
    if n==0: return tlv(0x02,b"\x00")
    o=[]; v=n
    while v: o.insert(0,v&0xff); v>>=8
    if o[0]&0x80: o.insert(0,0)
    return tlv(0x02,bytes(o))
def enc_str(s):
    if isinstance(s,str): s=s.encode("latin1","replace")
    return tlv(0x04,s)
def enc_oid(oid):
    p=[int(x) for x in oid.split(".")]
    body=[40*p[0]+p[1]]
    for a in p[2:]:
        if a<0x80: body.append(a)
        else:
            st=[a&0x7f]; a>>=7
            while a: st.insert(0,(a&0x7f)|0x80); a>>=7
            body.extend(st)
    return tlv(0x06,bytes(body))

def get_request(version,community,oids):
    rid=random.randint(1,0x7fffffff)
    vbl=b""
    for o in oids: vbl+=tlv(0x30, enc_oid(o)+tlv(0x05,b""))
    pdu=tlv(0xA0, enc_int(rid)+enc_int(0)+enc_int(0)+tlv(0x30,vbl))
    msg=tlv(0x30, enc_int(version)+enc_str(community)+pdu)
    return rid,msg

def parse_len(d,o):
    n=d[o]; o+=1
    if n<0x80: return n,o
    k=n&0x7f; v=0
    for _ in range(k): v=(v<<8)|d[o]; o+=1
    return v,o
def parse_tlv(d,o):
    tag=d[o]; o+=1
    ln,o=parse_len(d,o)
    return tag,d[o:o+ln],o+ln
def oid_str(b):
    if not b: return ""
    first=b[0]; res=[str(first//40),str(first%40)]; v=0
    for x in b[1:]:
        v=(v<<7)|(x&0x7f)
        if not x&0x80: res.append(str(v)); v=0
    return ".".join(res)
def val_str(tag,b):
    if tag==0x04: return b.decode("latin1","replace")
    if tag==0x06: return oid_str(b)
    if tag in (0x02,0x41,0x42,0x43,0x46):
        v=0
        for x in b: v=(v<<8)|x
        return str(v)
    if tag==0x40 and len(b)==4: return ".".join(str(x) for x in b)
    if tag==0x05: return ""
    return b.decode("latin1","replace")

def try_community(version,community):
    rid,msg=get_request(version,community,[o for _,o in OIDS])
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(msg,(host,port)); data,_=s.recvfrom(65535); s.close()
    except Exception:
        return None
    try:
        _,body,_=parse_tlv(data,0)          # outer SEQUENCE
        o=0
        _,_,o=parse_tlv(body,o)             # version
        _,_,o=parse_tlv(body,o)             # community
        ptag,pdu,_=parse_tlv(body,o)        # response PDU (0xA2)
        po=0
        _,_,po=parse_tlv(pdu,po)            # request-id
        _,errb,po=parse_tlv(pdu,po)         # error-status
        _,_,po=parse_tlv(pdu,po)            # error-index
        _,vbl,_=parse_tlv(pdu,po)           # varbind list
        vo=0; res={}
        while vo<len(vbl):
            _,vb,vo=parse_tlv(vbl,vo)
            io=0
            _,oidb,io=parse_tlv(vb,io)
            vtag,valb,io=parse_tlv(vb,io)
            res[oid_str(oidb)]=val_str(vtag,valb)
        return res
    except Exception:
        return None

def v3_discovery():
    # SNMPv3 engine-ID discovery: empty USM, reportable flag set. Any reply
    # (a Report PDU) means v3/USM is available.
    mid=random.randint(1,0x7fffffff)
    ghdr=tlv(0x30, enc_int(mid)+enc_int(65507)+enc_str(bytes([0x04]))+enc_int(3))
    usm=tlv(0x30, enc_str(b"")+enc_int(0)+enc_int(0)+enc_str(b"")+enc_str(b"")+enc_str(b""))
    sp=enc_str(usm)
    spdu=tlv(0x30, enc_str(b"")+enc_str(b"")+tlv(0xA0, enc_int(mid)+enc_int(0)+enc_int(0)+tlv(0x30,b"")))
    msg=tlv(0x30, enc_int(3)+ghdr+sp+spdu)
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(msg,(host,port)); data,_=s.recvfrom(65535); s.close()
    except Exception:
        return None
    # if we got any SNMPv3 datagram back, report supported + engineID if parseable
    try:
        _,body,_=parse_tlv(data,0)
        o=0
        _,verb,o=parse_tlv(body,o)
        if val_str(0x02,verb)!="3": return "supported"
        _,_,o=parse_tlv(body,o)             # msgGlobalData
        _,spb,o=parse_tlv(body,o)           # msgSecurityParameters (OCTET STRING)
        _,usmb,_=parse_tlv(spb,0)           # USM SEQUENCE
        _,eid,_=parse_tlv(usmb,0)           # engineID OCTET STRING
        return "supported engineID="+eid.hex()
    except Exception:
        return "supported"

found=False
for comm in communities:
    for ver,label in ((1,"v2c"),(0,"v1")):
        res=try_community(ver,comm)
        if res is not None:
            found=True
            out("COMMUNITY_OK",comm,label)
            for nm,oid in OIDS:
                if oid in res and res[oid]!="":
                    out("SYS",nm,res[oid])
            break
    if found: break

v3=v3_discovery()
if v3: out("V3",v3)
if not found and not v3: out("DEAD","no SNMP response")
PYEOF

# ---- nmap NSE engine --------------------------------------------------------
nse_probe() {  # <host> <port>
    local host="$1" port="$2" out commdb=""
    # hand nmap our community list via a temp db so guessing matches --communities
    commdb="$(mktemp 2>/dev/null || echo "")"
    if [[ -n "$commdb" ]]; then printf '%s\n' "${COMMUNITIES//,/$'\n'}" > "$commdb"; fi
    out="$(nmap -Pn -sU -p "$port" \
            --script snmp-info,snmp-sysdescr,snmp-brute \
            ${commdb:+--script-args "snmp-brute.communitiesdb=$commdb"} \
            --host-timeout "$((TIMEOUT*10))"s "$host" 2>/dev/null)"
    [[ -n "$commdb" ]] && rm -f "$commdb"
    # communities discovered by snmp-brute ("public - Valid credentials")
    NSE_COMMS="$(echo "$out" | grep -iE 'Valid credentials' | sed -E 's/\|_? *//; s/ - Valid credentials.*//' | awk '{print $1}' | sort -u | paste -sd, -)"
    NSE_SYSDESCR="$(echo "$out" | grep -iE 'snmp-sysdescr|Software:|System description' | sed -E 's/^\|_? *//' | head -3 | paste -sd' ' -)"
    [[ -z "$NSE_SYSDESCR" ]] && NSE_SYSDESCR="$(echo "$out" | sed -n '/snmp-info/,/^[^|]/p' | grep -iE 'engineIDData|enterprise' | head -1 | sed -E 's/^\|_? *//')"
}

# ---- python3 engine ---------------------------------------------------------
py_probe() {  # <host> <port>
    local host="$1" port="$2" k a b
    PY_COMMS=""; PY_VER=""; PY_SYSDESCR=""; PY_SYSNAME=""; PY_SYSLOC=""; PY_V3=""; PY_DEAD=1
    while IFS=$'\t' read -r k a b; do
        case "$k" in
            COMMUNITY_OK) PY_COMMS="${PY_COMMS:+$PY_COMMS,}$a"; PY_VER="$b"; PY_DEAD=0 ;;
            SYS)
                case "$a" in
                    sysDescr)   PY_SYSDESCR="$b" ;;
                    sysName)    PY_SYSNAME="$b" ;;
                    sysLocation) PY_SYSLOC="$b" ;;
                esac ;;
            V3)   PY_V3="$a"; PY_DEAD=0 ;;
            DEAD) PY_DEAD=1 ;;
        esac
    done < <(python3 -I -c "$SNMP_PY" "$host" "$port" "$TIMEOUT" "$COMMUNITIES" 2>/dev/null)
}

# ---- sysDescr -> known-vuln hints ------------------------------------------
flag_sysdescr_cves() {  # <sysdescr> <rw_present:0/1>
    local d="$1" rw="$2" v
    if echo "$d" | grep -qiE 'net-snmp|net snmp'; then
        v="$(echo "$d" | grep -oiE 'net-snmp[^0-9]*[0-9][0-9.]*' | grep -oE '[0-9][0-9.]*' | head -1)"
        if [[ "$rw" == "1" ]]; then
            PROBLEMS+=("Net-SNMP ${v:-} with RW community — CVE-2020-15862 EXTEND-MIB arbitrary command exec as root (if <=5.8)")
        elif [[ -n "$v" ]]; then
            PROBLEMS+=("Net-SNMP ${v} detected — if a RW community exists, CVE-2020-15862 (EXTEND-MIB) applies; verify with cve-lookup")
        fi
    fi
    echo "$d" | grep -qiE 'Cisco IOS' && PROBLEMS+=("Cisco IOS via SNMP — config exfil/modification risk if RW; cross-ref cve-lookup on IOS version")
}

# ---- opt-in writable-community probe (no-op SET, needs native snmpset) ------
write_test() {  # <host> <port> <comma-communities> -> echoes RW community or ""
    local host="$1" port="$2" comms="$3" c cur
    have snmpset || { PROBLEMS+=("--write-test requested but snmpset (net-snmp) not installed; skipped"); return; }
    IFS=',' read -ra carr <<<"$comms"
    for c in "${carr[@]}"; do
        [[ -z "$c" ]] && continue
        cur="$(snmpget -v2c -c "$c" -Ovq -t "$TIMEOUT" -r0 "$host":"$port" 1.3.6.1.2.1.1.6.0 2>/dev/null)"
        [[ -z "$cur" ]] && cur="$(snmpget -v1 -c "$c" -Ovq -t "$TIMEOUT" -r0 "$host":"$port" 1.3.6.1.2.1.1.6.0 2>/dev/null)"
        # write sysLocation back to its own value (no state change)
        if snmpset -v2c -c "$c" -t "$TIMEOUT" -r0 "$host":"$port" 1.3.6.1.2.1.1.6.0 s "${cur:- }" >/dev/null 2>&1; then
            echo "$c"; return
        fi
    done
}

# ------------------------------------------------------------------- audit --
audit_target() {
    local target="$1" host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORT_DEFAULT}"; fi

    PROBLEMS=()
    local comms="" ver="" sysdescr="" sysname="" sysloc="" v3="" reachable="true" rw=""
    NSE_COMMS=""; NSE_SYSDESCR=""
    PY_COMMS=""; PY_VER=""; PY_SYSDESCR=""; PY_SYSNAME=""; PY_SYSLOC=""; PY_V3=""; PY_DEAD=1

    # onesixtyone (preferred) can accelerate/augment community guessing
    if have onesixtyone; then
        local o161
        o161="$(printf '%s\n' "${COMMUNITIES//,/$'\n'}" | onesixtyone -c /dev/stdin "$host" 2>/dev/null | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]')"
        [[ -n "$o161" ]] && comms="$o161"
    fi

    if [[ "$ENGINE" == "nmap" ]]; then
        nse_probe "$host" "$port"
        [[ -n "$NSE_COMMS" ]] && comms="${comms:+$comms,}$NSE_COMMS"
        sysdescr="$NSE_SYSDESCR"
        [[ -z "$comms" && -z "$sysdescr" ]] && reachable="false"
    else
        py_probe "$host" "$port"
        [[ -n "$PY_COMMS" ]] && comms="${comms:+$comms,}$PY_COMMS"
        ver="$PY_VER"; sysdescr="$PY_SYSDESCR"; sysname="$PY_SYSNAME"; sysloc="$PY_SYSLOC"; v3="$PY_V3"
        [[ ${PY_DEAD} -eq 1 ]] && reachable="false"
    fi
    # de-dup communities
    [[ -n "$comms" ]] && comms="$(printf '%s\n' "${comms//,/$'\n'}" | awk 'NF && !seen[$0]++' | paste -sd, -)"

    # richer sysDescr via snmpwalk when present and a community was found
    if [[ -z "$sysdescr" && -n "$comms" ]] && have snmpwalk; then
        local c1="${comms%%,*}"
        sysdescr="$(snmpwalk -v2c -c "$c1" -Ovq -t "$TIMEOUT" -r0 "$host":"$port" 1.3.6.1.2.1.1.1.0 2>/dev/null | head -1)"
    fi

    if [[ "$reachable" == "false" ]]; then
        [[ ${JSON} -eq 0 ]] && { section "${host}:${port}  (engine: ${ENGINE})"; ok "no SNMP response (agent down, filtered, or v3-only with auth)"; }
        [[ ${JSON} -eq 1 ]] && printf '{"tool":"snmp-audit","host":"%s","port":"%s","reachable":false,"problems":[]}\n' "$(jesc "$host")" "$(jesc "$port")"
        return
    fi

    # findings
    if [[ -n "$comms" ]]; then
        PROBLEMS+=("readable community string(s): ${comms} (${ver:-v1/v2c} — no auth, cleartext)")
        echo ",$comms," | grep -qiE ",(${RW_LIKELY})," && \
            PROBLEMS+=("community in ${comms} matches a commonly read-write name — test write access (--write-test)")
    fi

    # opt-in writable test
    if [[ ${WRITE_TEST} -eq 1 && -n "$comms" ]]; then
        rw="$(write_test "$host" "$port" "$comms")"
        [[ -n "$rw" ]] && PROBLEMS+=("WRITABLE community confirmed: '${rw}' accepts SNMP SET (full device read/write)")
    fi

    [[ -n "$sysdescr" ]] && flag_sysdescr_cves "$sysdescr" "$([[ -n "$rw" ]] && echo 1 || echo 0)"
    [[ -n "$v3" ]] || PROBLEMS+=("SNMPv3 not detected — only unauthenticated v1/v2c available")

    [[ ${#PROBLEMS[@]} -gt 0 ]] && EXIT_CODE=1

    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${PROBLEMS[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"snmp-audit","host":"%s","port":"%s","reachable":true,"engine":"%s",' \
            "$(jesc "$host")" "$(jesc "$port")" "$ENGINE"
        printf '"communities":"%s","version":"%s","sysdescr":"%s","sysname":"%s","v3":"%s","problems":[%s]}\n' \
            "$(jesc "$comms")" "$(jesc "$ver")" "$(jesc "$sysdescr")" "$(jesc "$sysname")" "$(jesc "$v3")" "$pj"
        return
    fi

    section "${host}:${port}  (engine: ${ENGINE})"
    field "Communities" "${comms:-none}"
    [[ -n "$ver" ]]      && field "Version"  "$ver"
    [[ -n "$sysdescr" ]] && field "sysDescr" "$sysdescr"
    [[ -n "$sysname" ]]  && field "sysName"  "$sysname"
    [[ -n "$sysloc" ]]   && field "sysLocation" "$sysloc"
    field "SNMPv3"       "${v3:-not detected}"
    if [[ ${#PROBLEMS[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${PROBLEMS[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "snmp-audit — ${#TARGETS[@]} host(s), engine=${ENGINE}, timeout ${TIMEOUT}s  (AUTHORIZED USE ONLY)"
for t in "${TARGETS[@]}"; do audit_target "$t"; done
exit "${EXIT_CODE}"
