#!/usr/bin/env bash
#
# ldap-audit.sh — LDAP / Active Directory exposure analyser
# =============================================================================
#   Read-only probe of an LDAP / Active Directory service. For each target it
#   reports and flags:
#     * anon bind    — does an anonymous (unauthenticated) bind succeed
#     * rootDSE      — naming contexts, server/DNS name, SASL mechs (no creds)
#     * domain level — Active Directory domain/forest functional level
#     * anon enum    — can an anonymous bind read user/group objects (leak)
#     * LDAPS        — is 636/tcp (LDAP-over-TLS) offered
#     * StartTLS     — is the StartTLS extended operation offered on 389
#     * signing      — is LDAP signing enforced (hint: NTLM-relay exposure)
#   Default backend is nmap NSE (ldap-rootdse / ldap-search); a built-in
#   python3 LDAP client is the universal fallback and also drives the
#   TLS / signing probes nmap cannot do. `ldapsearch` is used when present.
#   Only probe directories you own or are explicitly authorized to test.
# =============================================================================
#
#   Requires: python3 (universal). Optional/preferred: nmap, ldapsearch, openssl.
#
#   Quick start:
#     ./ldap-audit.sh dc01.corp.local                 # LDAP on 389 (+636 probe)
#     ./ldap-audit.sh 10.0.0.5:389
#     ./ldap-audit.sh -f dcs.txt
#     ./ldap-audit.sh --json dc01.corp.local
#     ./ldap-audit.sh --no-signing dc01.corp.local    # skip the bogus-cred bind
#
set -uo pipefail

PORT_DEFAULT=389
LDAPS_PORT=636
TIMEOUT=10
JSON=0
DO_SIGNING=1
DO_ENUM=1
PREFER_NMAP=1
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

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            [[ -z "${2:-}" ]] && { err "missing FILE"; exit 2; }
            while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && TARGETS+=("$l"); done < "$2"
            shift 2 ;;
        -p|--port)      PORT_DEFAULT="${2:?}"; shift 2 ;;
        -t|--timeout)   TIMEOUT="${2:?}"; shift 2 ;;
        --no-signing)   DO_SIGNING=0; shift ;;
        --no-enum)      DO_ENUM=0; shift ;;
        --no-nmap)      PREFER_NMAP=0; shift ;;
        --json)         JSON=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        --)             shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)             err "unknown option: $1"; usage; exit 2 ;;
        *)              TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no targets given"; usage; exit 2; }

have python3 || { err "python3 is required (universal LDAP backend)"; exit 2; }

# =============================================================================
# Embedded minimal LDAPv3 client (stdlib only). Used for the TLS/signing probes
# that nmap cannot perform, and as the full fallback when nmap is absent.
# Sub-commands, each prints one JSON object to stdout:
#   interrogate HOST PORT TIMEOUT DO_ENUM     plaintext: anon bind + rootDSE +
#                                             (optional) anon object enum +
#                                             StartTLS probe (separate conn)
#   signing     HOST PORT TIMEOUT             cleartext bogus-cred simple bind
#   ldaps       HOST PORT TIMEOUT             TLS wrap + anon bind + rootDSE
# =============================================================================
read -r -d '' LDAP_PY <<'PYEOF' || true
import sys, socket, ssl, json, random

def enc_len(n):
    if n < 0x80: return bytes([n])
    b = b""
    while n: b = bytes([n & 0xFF]) + b; n >>= 8
    return bytes([0x80 | len(b)]) + b

def tlv(tag, c): return bytes([tag]) + enc_len(len(c)) + c

def enc_int(n):
    if n == 0: return b"\x00"
    b = b""; v = n
    while v: b = bytes([v & 0xFF]) + b; v >>= 8
    if b[0] & 0x80: b = b"\x00" + b
    return b

def INTEGER(n): return tlv(0x02, enc_int(n))
def ENUM(n):    return tlv(0x0A, enc_int(n))
def BOOL(v):    return tlv(0x01, b"\xff" if v else b"\x00")
def OCTET(s):
    if isinstance(s, str): s = s.encode()
    return tlv(0x04, s)
def SEQ(*it):   return tlv(0x30, b"".join(it))

def bind_req(mid, dn="", pw=""):
    auth = tlv(0x80, pw.encode() if isinstance(pw, str) else pw)   # simple [0]
    return SEQ(INTEGER(mid), tlv(0x60, INTEGER(3) + OCTET(dn) + auth))

def present(attr):      return tlv(0x87, attr.encode())           # filter present [7]
def search_req(mid, base, scope, flt, attrs, size=0):
    aseq = SEQ(*[OCTET(a) for a in attrs]) if attrs else tlv(0x30, b"")
    body = (OCTET(base) + ENUM(scope) + ENUM(0) + INTEGER(size) +
            INTEGER(0) + BOOL(False) + flt + aseq)
    return SEQ(INTEGER(mid), tlv(0x63, body))                     # searchRequest [3]

def starttls_req(mid):
    return SEQ(INTEGER(mid), tlv(0x77, tlv(0x80, b"1.3.6.1.4.1.1466.20037")))

def rd_len(buf, i):
    l = buf[i]; i += 1
    if l & 0x80:
        n = l & 0x7F; l = 0
        for _ in range(n): l = (l << 8) | buf[i]; i += 1
    return l, i

def rd_tlv(buf, i):
    tag = buf[i]; i += 1
    length, i = rd_len(buf, i)
    return tag, buf[i:i + length], i + length

def recvn(sock, n):
    d = b""
    while len(d) < n:
        c = sock.recv(n - len(d))
        if not c: break
        d += c
    return d

def recv_ldap(sock):
    b0 = recvn(sock, 1)
    if not b0: return None
    l0 = recvn(sock, 1)
    if not l0: return None
    l0 = l0[0]
    if l0 & 0x80:
        lb = recvn(sock, l0 & 0x7F); length = 0
        for c in lb: length = (length << 8) | c
    else:
        length = l0
    return b0 + bytes([l0]) + recvn(sock, length)

def op_of(msg):
    _, content, _ = rd_tlv(msg, 0)
    _, _, j = rd_tlv(content, 0)          # messageID
    tag, opc, _ = rd_tlv(content, j)      # protocolOp
    return tag, opc

def result_code(opc):
    _, c, _ = rd_tlv(opc, 0)
    return int.from_bytes(c, "big") if c else -1

def parse_entry(opc):
    _, dn, j = rd_tlv(opc, 0)
    attrs = {}
    try:
        _, aseq, _ = rd_tlv(opc, j)
        k = 0
        while k < len(aseq):
            _, part, k = rd_tlv(aseq, k)
            _, atype, m = rd_tlv(part, 0)
            _, vset, _ = rd_tlv(part, m)
            vals, p = [], 0
            while p < len(vset):
                _, v, p = rd_tlv(vset, p)
                vals.append(v.decode("latin1"))
            attrs[atype.decode("latin1")] = vals
    except Exception:
        pass
    return dn.decode("latin1"), attrs

ROOTDSE_ATTRS = ["namingContexts", "defaultNamingContext", "rootDomainNamingContext",
                 "domainFunctionality", "forestFunctionality",
                 "domainControllerFunctionality", "dnsHostName", "serverName",
                 "ldapServiceName", "supportedSASLMechanisms",
                 "supportedCapabilities", "supportedLDAPVersion"]

def connect(host, port, timeout, tls=False):
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s

def do_bind(sock, mid, dn="", pw=""):
    sock.sendall(bind_req(mid, dn, pw))
    msg = recv_ldap(sock)
    if not msg: return -1
    tag, opc = op_of(msg)
    return result_code(opc) if tag == 0x61 else -1

def do_rootdse(sock, mid):
    sock.sendall(search_req(mid, "", 0, present("objectClass"), ROOTDSE_ATTRS, 0))
    attrs = {}
    while True:
        msg = recv_ldap(sock)
        if not msg: break
        tag, opc = op_of(msg)
        if tag == 0x64:
            _, a = parse_entry(opc); attrs.update(a)
        elif tag == 0x65:
            break
    return attrs

def do_enum(sock, mid, base):
    sock.sendall(search_req(mid, base, 2, present("objectClass"),
                            ["sAMAccountName", "cn", "objectClass"], 5))
    count, sample = 0, []
    while True:
        msg = recv_ldap(sock)
        if not msg: break
        tag, opc = op_of(msg)
        if tag == 0x64:
            dn, a = parse_entry(opc); count += 1
            nm = (a.get("sAMAccountName") or a.get("cn") or [dn])[0]
            if len(sample) < 5: sample.append(nm)
        elif tag == 0x73:
            continue
        elif tag == 0x65:
            break
    return count, sample

def j(obj): print(json.dumps(obj)); sys.exit(0)

def main():
    cmd, host, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
    if cmd == "interrogate":
        do_enum_flag = len(sys.argv) > 5 and sys.argv[5] == "1"
        out = {"reachable": False, "anon_bind": False, "attrs": {},
               "starttls": False, "enum_count": -1, "enum_sample": []}
        # StartTLS on its own connection (must precede any bind)
        try:
            s = connect(host, port, timeout)
            s.sendall(starttls_req(1)); m = recv_ldap(s)
            if m:
                tag, opc = op_of(m)
                out["starttls"] = (tag == 0x78 and result_code(opc) == 0)
            s.close()
        except Exception:
            pass
        # anon bind + rootDSE + enum
        try:
            s = connect(host, port, timeout)
            out["reachable"] = True
            out["anon_bind"] = (do_bind(s, 1) == 0)
            out["attrs"] = do_rootdse(s, 2)
            base = (out["attrs"].get("defaultNamingContext")
                    or out["attrs"].get("namingContexts") or [""])
            base = base[0] if base else ""
            if do_enum_flag and base:
                c, smp = do_enum(s, 3, base)
                out["enum_count"], out["enum_sample"] = c, smp
            s.close()
        except Exception as e:
            out["error"] = str(e)
        j(out)
    elif cmd == "signing":
        # A credentialed simple bind over cleartext with a bogus principal.
        # strongerAuthRequired(8) => signing/TLS enforced; invalidCredentials(49)
        # or success(0) => cleartext bind processed => signing NOT enforced.
        out = {"reachable": False, "bind_result": -1, "signing_required": None}
        try:
            s = connect(host, port, timeout); out["reachable"] = True
            rc = do_bind(s, 1, "CN=arsenal-signing-probe", "arsenal-signing-probe-" + str(random.randint(1000, 9999)))
            out["bind_result"] = rc
            if rc == 8:   out["signing_required"] = True
            elif rc in (0, 49, 48): out["signing_required"] = False
            s.close()
        except Exception as e:
            out["error"] = str(e)
        j(out)
    elif cmd == "ldaps":
        out = {"ldaps": False, "tls_version": "", "cipher": "", "attrs": {}}
        try:
            s = connect(host, port, timeout, tls=True)
            out["ldaps"] = True
            try:
                out["tls_version"] = s.version() or ""
                ci = s.cipher()
                out["cipher"] = ci[0] if ci else ""
            except Exception:
                pass
            if do_bind(s, 1) in (0, 49, 48, 8):
                out["attrs"] = do_rootdse(s, 2)
            s.close()
        except Exception as e:
            out["error"] = str(e)
        j(out)
    else:
        print("{}"); sys.exit(0)

try:
    main()
except Exception as e:
    print(json.dumps({"error": str(e)})); sys.exit(0)
PYEOF

pyprobe() { python3 -c "$LDAP_PY" "$@" 2>/dev/null; }

# jget <json> <key> — scalar string/number/bool value for a top-level-ish key
jget() { JS="$1" KEY="$2" python3 -c '
import sys, os, json
try: d = json.loads(os.environ["JS"])
except Exception: d = {}
def walk(o, k):
    if isinstance(o, dict):
        if k in o: return o[k]
        for v in o.values():
            r = walk(v, k)
            if r is not None: return r
    return None
v = walk(d, os.environ["KEY"])
if isinstance(v, bool): print("true" if v else "false")
elif v is None: print("")
elif isinstance(v, (list,)): print(";".join(str(x) for x in v))
else: print(v)
' 2>/dev/null; }

# jget_attr <interrogate-json> <ldap-attr>  — first value of a rootDSE attr
jget_attr() { JS="$1" KEY="$2" python3 -c '
import sys, os, json
try: a = json.loads(os.environ["JS"]).get("attrs", {})
except Exception: a = {}
v = a.get(os.environ["KEY"]) or []
print(v[0] if v else "")
' 2>/dev/null; }

# functional-level number -> Windows Server generation
dfl_name() {
    case "$1" in
        0) echo "Windows 2000" ;;
        1) echo "Server 2003 interim" ;;
        2) echo "Server 2003" ;;
        3) echo "Server 2008" ;;
        4) echo "Server 2008 R2" ;;
        5) echo "Server 2012" ;;
        6) echo "Server 2012 R2" ;;
        7) echo "Server 2016+ (2016/2019/2022/2025)" ;;
        *) echo "unknown" ;;
    esac
}

# -------------------------------------------------------------- nmap backend --
# Parse `nmap --script ldap-rootdse` text into "attr: value" we can grep.
nmap_rootdse() {
    local host="$1" port="$2"
    nmap -Pn -n -p "$port" --script ldap-rootdse \
         --host-timeout "$((TIMEOUT * 3))s" "$host" 2>/dev/null \
      | sed -n 's/^|[_ ]*//p'
}
# nmap ldap-search with an anonymous bind; count returned objects.
nmap_enum_count() {
    local host="$1" port="$2" out
    out="$(nmap -Pn -n -p "$port" --script ldap-search \
           --script-args 'ldap.qfilter=all,ldap.maxobjects=5' \
           --host-timeout "$((TIMEOUT * 3))s" "$host" 2>/dev/null)"
    echo "$out" | grep -ciE 'dn:|sAMAccountName:|objectClass:'
}

audit_target() {
    local target="$1" host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORT_DEFAULT}"; fi

    local problems=()
    local reachable="false" anon_bind="false" starttls="false" ldaps="false"
    local naming_contexts="" default_nc="" dfl_num="" dfl="" dnshost="" sasl=""
    local enum_count=-1 enum_sample="" signing_required="null"

    # --- core interrogation (rootDSE / anon bind / enum / StartTLS) ----------
    local interro use_nmap_ro=0
    if [[ ${PREFER_NMAP} -eq 1 ]] && have nmap; then use_nmap_ro=1; fi

    # python interrogation always runs: it yields anon-bind, StartTLS, and acts
    # as the rootDSE/enum source when nmap is absent or returns nothing.
    interro="$(pyprobe interrogate "$host" "$port" "$TIMEOUT" "$DO_ENUM")"
    [[ "$(jget "$interro" reachable)" == "true" ]] && reachable="true"
    [[ "$(jget "$interro" anon_bind)" == "true" ]] && anon_bind="true"
    [[ "$(jget "$interro" starttls)" == "true" ]] && starttls="true"

    naming_contexts="$(jget_attr "$interro" namingContexts)"
    default_nc="$(jget_attr "$interro" defaultNamingContext)"
    dfl_num="$(jget_attr "$interro" domainFunctionality)"
    dnshost="$(jget_attr "$interro" dnsHostName)"
    sasl="$(jget_attr "$interro" supportedSASLMechanisms)"
    enum_count="$(jget "$interro" enum_count)"; [[ -z "$enum_count" ]] && enum_count=-1
    enum_sample="$(jget "$interro" enum_sample)"

    # Prefer nmap's authoritative rootDSE parse when available.
    if [[ $use_nmap_ro -eq 1 ]]; then
        local nro; nro="$(nmap_rootdse "$host" "$port")"
        if [[ -n "$nro" ]]; then
            reachable="true"
            local v
            v="$(echo "$nro" | sed -n 's/.*defaultNamingContext: *//p' | head -1)"; [[ -n "$v" ]] && default_nc="$v"
            v="$(echo "$nro" | sed -n 's/.*[^a-zA-Z]namingContexts: *//p;s/^namingContexts: *//p' | head -1)"; [[ -n "$v" ]] && naming_contexts="$v"
            v="$(echo "$nro" | sed -n 's/.*domainFunctionality: *//p' | head -1)"; [[ -n "$v" ]] && dfl_num="$v"
            v="$(echo "$nro" | sed -n 's/.*dnsHostName: *//p' | head -1)"; [[ -n "$v" ]] && dnshost="$v"
        fi
        if [[ "$enum_count" == "-1" && ${DO_ENUM} -eq 1 ]]; then
            enum_count="$(nmap_enum_count "$host" "$port")"
        fi
    fi

    if [[ "$reachable" != "true" ]]; then
        if [[ ${JSON} -eq 1 ]]; then
            printf '{"tool":"ldap-audit","host":"%s","port":"%s","reachable":false,"problems":["no LDAP response (host down, filtered, or not LDAP)"]}\n' "$(jesc "$host")" "$(jesc "$port")"
        else
            section "${host}:${port}"; err "no LDAP response (host down, filtered, or not LDAP)"
        fi
        EXIT_CODE=1; return
    fi

    # --- LDAPS (636) ---------------------------------------------------------
    local ldaps_j tlsver=""
    ldaps_j="$(pyprobe ldaps "$host" "$LDAPS_PORT" "$TIMEOUT")"
    if [[ "$(jget "$ldaps_j" ldaps)" == "true" ]]; then
        ldaps="true"; tlsver="$(jget "$ldaps_j" tls_version)"
    fi

    # --- signing hint (optional bogus-cred cleartext bind) -------------------
    if [[ ${DO_SIGNING} -eq 1 ]]; then
        local sj; sj="$(pyprobe signing "$host" "$port" "$TIMEOUT")"
        signing_required="$(jget "$sj" signing_required)"; [[ -z "$signing_required" ]] && signing_required="null"
    fi

    # --- findings ------------------------------------------------------------
    if [[ "$anon_bind" == "true" ]]; then
        problems+=("LOW: anonymous bind accepted (rootDSE / server metadata readable without credentials)")
    fi
    if [[ -n "$dfl_num" ]]; then
        dfl="$(dfl_name "$dfl_num")"
        if [[ "$dfl_num" =~ ^[0-9]+$ ]]; then
            if (( dfl_num <= 2 )); then
                problems+=("HIGH: legacy domain functional level ${dfl_num} (${dfl}) — end-of-life OS, weak Kerberos crypto defaults")
            elif (( dfl_num <= 4 )); then
                problems+=("MEDIUM: old domain functional level ${dfl_num} (${dfl}) — likely EOL DC OS")
            fi
        fi
    fi
    if [[ ${DO_ENUM} -eq 1 && "$enum_count" =~ ^[0-9]+$ && "$enum_count" -gt 0 ]]; then
        problems+=("HIGH: anonymous directory enumeration allowed — ${enum_count}+ object(s) readable without auth (user/group harvesting for spraying & AS-REP roasting)")
    fi
    if [[ "$ldaps" != "true" ]]; then
        problems+=("MEDIUM: LDAPS (636/tcp) not available — directory traffic has no TLS channel")
    fi
    if [[ "$ldaps" != "true" && "$starttls" != "true" ]]; then
        problems+=("MEDIUM: neither LDAPS nor StartTLS offered — binds/queries travel in cleartext")
    fi
    if [[ "$signing_required" == "false" ]]; then
        problems+=("HIGH: LDAP signing not enforced (hint) — cleartext simple bind accepted; DC likely relay-vulnerable (NTLM relay to LDAP, cf. CVE-2017-8563 / ADV190023)")
    fi
    if [[ "$ldaps" == "true" ]]; then
        problems+=("INFO: LDAPS present — channel-binding (CBT/ADV190023) enforcement needs an authenticated NTLM bind to confirm (verify with NetExec 'nxc ldap' or LdapRelayScan)")
    fi

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    # --- output --------------------------------------------------------------
    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"ldap-audit","host":"%s","port":"%s","reachable":true,' "$(jesc "$host")" "$(jesc "$port")"
        printf '"anon_bind":%s,"ldaps":%s,"starttls":%s,' "$anon_bind" "$ldaps" "$starttls"
        printf '"naming_contexts":"%s","default_nc":"%s","dfl":"%s","dns_host":"%s","sasl_mechs":"%s",' \
            "$(jesc "$naming_contexts")" "$(jesc "$default_nc")" "$(jesc "${dfl_num:+$dfl_num ($dfl)}")" "$(jesc "$dnshost")" "$(jesc "$sasl")"
        printf '"anon_enum_count":%s,"anon_enum_sample":"%s","signing_required":%s,"problems":[%s]}\n' \
            "$([[ "$enum_count" =~ ^[0-9]+$ ]] && echo "$enum_count" || echo null)" \
            "$(jesc "$enum_sample")" "$signing_required" "$pj"
        return
    fi

    section "${host}:${port}"
    field "Reachable"   "yes"
    field "Anon bind"   "$anon_bind"
    [[ -n "$naming_contexts" ]] && field "Naming contexts" "$naming_contexts"
    [[ -n "$default_nc"      ]] && field "Default NC"       "$default_nc"
    [[ -n "$dfl_num"         ]] && field "Domain level"     "${dfl_num} (${dfl})"
    [[ -n "$dnshost"         ]] && field "DNS host"         "$dnshost"
    [[ -n "$sasl"            ]] && field "SASL mechs"       "$sasl"
    field "LDAPS (636)"  "$ldaps${tlsver:+ ($tlsver)}"
    field "StartTLS"     "$starttls"
    [[ "$enum_count" =~ ^[0-9]+$ && "$enum_count" -ge 0 ]] && field "Anon enum" "${enum_count} object(s)${enum_sample:+ — $enum_sample}"
    [[ ${DO_SIGNING} -eq 1 ]] && field "Signing req" "$signing_required"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no exposures detected"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

# ---------------------------------------------------------------------- main --
if [[ ${JSON} -eq 0 ]]; then
    bk="python3"; { [[ ${PREFER_NMAP} -eq 1 ]] && have nmap; } && bk="nmap NSE + python3"
    info "ldap-audit — ${#TARGETS[@]} target(s), backend=${bk}, timeout ${TIMEOUT}s"
    warn "authorized-use only: probe directories you own or are permitted to test"
fi
for t in "${TARGETS[@]}"; do audit_target "$t"; done
exit "${EXIT_CODE}"
