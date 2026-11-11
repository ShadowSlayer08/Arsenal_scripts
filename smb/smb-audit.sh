#!/usr/bin/env bash
#
# smb-audit.sh — SMB / NetBIOS / RPC enumeration & posture audit
# =============================================================================
#   Read-only probe of an SMB service (TCP 445, or NetBIOS 139). Reports:
#     * SMB dialects offered, flagging SMBv1 (NT LM 0.12)
#     * whether message signing is REQUIRED (SMB/NTLM-relay & MITM exposure)
#     * whether a null (anonymous) or guest session is accepted
#     * shares visible anonymously and which are readable / writable
#     * host OS / domain / workgroup / FQDN
#     * users enumerable over MS-RPC (SAMR QueryDisplayInfo / LSA RID cycling)
#
#   Default backend is nmap's smb-* NSE scripts (guaranteed present here). If
#   nmap is missing, a built-in python3 SMB negotiate covers dialect + signing.
#   Native tools (smbclient, rpcclient, nmblookup, netexec/nxc, smbmap) are
#   used to enrich results when installed, and skipped cleanly when not.
#
#   Read-only & non-destructive: it negotiates and enumerates only — it never
#   writes, deletes, or executes on the target. RID/user and share enumeration
#   is read-only but IS logged by the target; use --safe to skip the noisy RPC
#   enumeration. The optional --vuln checks (MS17-010 / SMBGhost) are detection
#   only, never exploitation.
#   Authorized / lab / CTF use ONLY — probe hosts you own or are cleared to test.
# =============================================================================
#
#   Requires: nmap (default backend) OR python3 (negotiate fallback).
#   Optional / enriching: smbclient, rpcclient, nmblookup (samba-client);
#                         nxc (NetExec); smbmap.
#
#   Quick start:
#     ./smb-audit.sh 10.0.0.10
#     ./smb-audit.sh 10.0.0.10:445 dc01.lab.local
#     ./smb-audit.sh --safe 10.0.0.10         # negotiate-only, no RPC enum
#     ./smb-audit.sh --vuln 10.0.0.10         # add MS17-010 / SMBGhost NSE
#     ./smb-audit.sh --json 10.0.0.10 | ../lib/report.sh --from-json -
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

PORT_DEFAULT=445
TIMEOUT=25
JSON=0
SAFE=0
VULN=0
BACKEND="auto"          # auto | nmap | python
TARGETS=()
EXIT_CODE=0

if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'
    C_B=$'\e[34m'; C_C=$'\e[36m'; C_M=$'\e[35m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_M=""; C_BOLD=""; C_DIM=""
fi
info()    { printf '%s[*]%s %s\n'  "${C_B}"   "${C_RST}" "$*"; }
ok()      { printf '%s[+]%s %s\n'  "${C_G}"   "${C_RST}" "$*"; }
warn()    { printf '%s[!]%s %s\n'  "${C_Y}"   "${C_RST}" "$*"; }
err()     { printf '%s[x]%s %s\n'  "${C_R}"   "${C_RST}" "$*"; }
crit()    { printf '%s[X]%s %s\n'  "${C_M}"   "${C_RST}" "$*"; }
field()   { printf '    %s%-18s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }
jesc() { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }
# run with a wall-clock cap when `timeout` exists, else run bare
cap()  { if have timeout; then timeout "$TIMEOUT" "$@"; else "$@"; fi; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — SMB / NetBIOS / RPC enumeration & posture audit

USAGE:
    ${SCRIPT_NAME} [options] <host[:port]> [host[:port] ...]

OPTIONS:
    -p, --port PORT     Default port when host has none (default: ${PORT_DEFAULT})
    -t, --timeout SEC   Per-step wall-clock cap (default: ${TIMEOUT})
        --safe          Negotiate-only: dialects + signing + OS. Skip the
                        (read-only but logged) RPC share/user enumeration.
        --vuln          Also run detection-only NSE: smb-vuln-ms17-010 and
                        smb-vuln-cve-2020-0796 (SMBGhost).
        --backend B     auto | nmap | python  (default: auto)
        --json          Emit JSON instead of text
    -h, --help          Show this help

CHECKS & SEVERITY:
    smbv1-enabled               SMBv1/NT LM 0.12 offered ............. HIGH
    smb-signing-not-required    signing not enforced (relay risk) .... HIGH
    smb-null-session            anonymous session accepted ........... HIGH
    smb-guest-session           guest account accepted ............... MEDIUM
    smb-share-anon-readable     non-IPC\$ share readable anonymously .. HIGH
    smb-share-anon-writable     non-IPC\$ share writable anonymously .. CRITICAL
    smb-eol-os                  end-of-life Windows version .......... HIGH
    smb-rid-user-enum           users enumerable over MS-RPC ......... MEDIUM
    smb-os-domain-disclosure    OS/domain/workgroup disclosed ........ INFO
    smb-vuln-ms17-010           EternalBlue (CVE-2017-0144) .......... CRITICAL
    smb-vuln-smbghost           SMBGhost (CVE-2020-0796) ............. CRITICAL

EXIT STATUS:
    0  no weaknesses found
    1  at least one finding
    2  usage error

JSON SCHEMA (one object per target):
    {"tool":"smb-audit","host":..,"port":..,"reachable":..,"problems":[..],
     "dialects":[..],"smbv1":..,"signing":..,"null_session":..,
     "guest_session":..,"os":..,"domain":..,"workgroup":..,"fqdn":..,
     "shares":[{"name":..,"anonymous":..,"current":..}],
     "users":[{"name":..,"rid":..}],"checks":[{"id":..,"severity":..,"status":..}]}

NOTES:
    Read-only. Only probe hosts you own or are explicitly authorized to test.
    Pipe --json into ../lib/report.sh, and feed disclosed OS/version into
    ../vuln/cve-lookup.sh to resolve CVEs + public exploits.
EOF
}

# ------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)    PORT_DEFAULT="${2:?}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --safe)       SAFE=1; shift ;;
        --vuln)       VULN=1; shift ;;
        --backend)    BACKEND="${2:?}"; shift 2 ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)           err "unknown option: $1"; usage; exit 2 ;;
        *)            TARGETS+=("$1"); shift ;;
    esac
done

case "$BACKEND" in auto|nmap|python) ;; *) err "invalid --backend: $BACKEND"; exit 2 ;; esac

# =============================================================================
# python3 parser for nmap -oX output. Reads XML on stdin, port as argv[1],
# prints TAB-separated KEY<TAB>VALUE lines the shell consumes. Kept logic-free
# beyond extraction; weak-condition decisions stay in bash.
# =============================================================================
read -r -d '' PARSE_PY <<'PY' || true
import sys, re
import xml.etree.ElementTree as ET

want_port = sys.argv[1] if len(sys.argv) > 1 else "445"
raw = sys.stdin.buffer.read()
def emit(k, v):
    v = re.sub(r'[\r\n\t]+', ' ', str(v)).strip()
    if v != "":
        sys.stdout.write("%s\t%s\n" % (k, v))

try:
    root = ET.fromstring(raw)
except Exception:
    sys.exit(0)

scripts = {}
port_open = False
for host in root.iter('host'):
    for port in host.iter('port'):
        if port.get('portid') == want_port:
            st = port.find('state')
            if st is not None and st.get('state') == 'open':
                port_open = True
        for s in port.iter('script'):
            scripts[s.get('id')] = s.get('output') or ""
    for hs in host.iter('hostscript'):
        for s in hs.iter('script'):
            scripts[s.get('id')] = s.get('output') or ""
emit("PORT_OPEN", "yes" if port_open else "no")

def lines(txt):
    out = []
    for ln in (txt or "").splitlines():
        ln = ln.strip()
        if ln.startswith('|_'): ln = ln[2:].strip()
        elif ln.startswith('|'): ln = ln[1:].strip()
        if ln:
            out.append(ln)
    return out

# ---- smb-protocols: dialects + SMBv1 ----
sp = scripts.get('smb-protocols', '')
if sp:
    for ln in lines(sp):
        if re.search(r'SMBv1|NT LM 0\.12', ln, re.I):
            emit("SMBV1", "yes")
            emit("DIALECT", "NT LM 0.12 (SMBv1)")
        elif re.match(r'^\d\.\d(\.\d)?$', ln):
            emit("DIALECT", ln)

# ---- signing: smb2-security-mode (preferred) then smb-security-mode ----
def signing_verdict(txt):
    t = (txt or "").lower()
    if not t:
        return ""
    if 'enabled and required' in t or re.search(r'signing.*required', t) or 'message_signing: required' in t:
        req = True
    else:
        req = False
    if ('not required' in t or 'disabled' in t or 'message_signing: supported' in t
            or 'message_signing: disabled' in t):
        req = False
    return "required" if req else "not_required"

s2 = scripts.get('smb2-security-mode', '')
s1 = scripts.get('smb-security-mode', '')
v2 = signing_verdict(s2)
v1 = signing_verdict(s1)
final = v2 or v1
if final:
    emit("SIGNING", final)
for ln in lines(s2) + lines(s1):
    if re.search(r'signing', ln, re.I):
        emit("SIGNING_TEXT", ln)
    m = re.search(r'account_used:\s*(.*)', ln, re.I)
    if m:
        emit("ACCOUNT_USED", m.group(1).strip())

# ---- smb-os-discovery ----
osd = scripts.get('smb-os-discovery', '')
for ln in lines(osd):
    for key, lbl in (('OS:', 'OS'), ('OS CPE:', 'OS_CPE'), ('Computer name:', 'COMPUTER'),
                     ('Domain name:', 'DOMAIN'), ('Forest name:', 'FOREST'),
                     ('FQDN:', 'FQDN'), ('Workgroup:', 'WORKGROUP'),
                     ('System time:', 'SYSTIME')):
        if ln.startswith(key):
            emit(lbl, ln[len(key):].strip())

# ---- smb-enum-shares: name | anon | current | type ----
shr = scripts.get('smb-enum-shares', '')
if shr:
    cur = None
    data = {}
    def flush():
        if cur:
            emit("SHARE", "%s|%s|%s|%s" % (cur, data.get('anon', '?'),
                                           data.get('cur', '?'), data.get('type', '')))
    for ln in lines(shr):
        if ln.lower().startswith('account_used') or ln.lower().startswith('note'):
            continue
        m = re.match(r'^([A-Za-z0-9._$\-]+):?$', ln)
        ma = re.match(r'Anonymous access:\s*(.*)', ln, re.I)
        mc = re.match(r'Current user access:\s*(.*)', ln, re.I)
        mt = re.match(r'Type:\s*(.*)', ln, re.I)
        if m:
            flush(); cur = m.group(1); data = {}
        elif ma:
            data['anon'] = ma.group(1).strip() or '<none>'
        elif mc:
            data['cur'] = mc.group(1).strip() or '<none>'
        elif mt:
            data['type'] = mt.group(1).strip()
    flush()

# ---- smb-enum-users: DOMAIN\name (RID: n) ----
usr = scripts.get('smb-enum-users', '')
if usr:
    for ln in lines(usr):
        m = re.search(r'([^\s\\]+\\[^\s()]+)\s*\(RID:\s*(\d+)\)', ln)
        if m:
            emit("USER", "%s|%s" % (m.group(1), m.group(2)))

# ---- vuln scripts ----
for vid, label in (('smb-vuln-ms17-010', 'ms17-010'),
                   ('smb-vuln-cve-2020-0796', 'smbghost')):
    vt = scripts.get(vid, '')
    if vt and re.search(r'VULNERABLE', vt, re.I):
        ids = ",".join(re.findall(r'(CVE-\d{4}-\d+|MS\d\d-\d\d\d)', vt)) or label
        emit("VULN", "%s|VULNERABLE|%s" % (label, ids))
PY

# =============================================================================
# python3 negotiate fallback (used when nmap is absent / --backend python).
# Sends an SMB2 NEGOTIATE (dialects 2.0.2..3.0.2) to read DialectRevision +
# server SecurityMode, then an SMB1 NEGOTIATE to test NT LM 0.12. Best-effort;
# never raises. Prints the same TSV keys (DIALECT / SMBV1 / SIGNING).
# =============================================================================
read -r -d '' NEG_PY <<'PY' || true
import sys, socket, os, struct

host = sys.argv[1]; port = int(sys.argv[2]); tmo = float(sys.argv[3])

def emit(k, v): sys.stdout.write("%s\t%s\n" % (k, v))

def nb(payload):  # NetBIOS session wrapper
    return b"\x00" + len(payload).to_bytes(3, "big") + payload

def recv_nb(s):
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c: return b""
        hdr += c
    n = int.from_bytes(hdr[1:4], "big")
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: break
        buf += c
    return buf

DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}

# ---- SMB2 negotiate ----
try:
    h = (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" + b"\x00\x00\x00\x00"
         + struct.pack("<H", 0) + b"\x00\x00" + b"\x00\x00\x00\x00"
         + b"\x00\x00\x00\x00" + b"\x00" * 8 + b"\x00\x00\x00\x00"
         + b"\x00\x00\x00\x00" + b"\x00" * 8 + b"\x00" * 16)
    dl = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (struct.pack("<H", 36) + struct.pack("<H", len(dl)) + struct.pack("<H", 1)
            + b"\x00\x00" + b"\x00\x00\x00\x00" + os.urandom(16) + b"\x00" * 8
            + b"".join(struct.pack("<H", d) for d in dl))
    s = socket.create_connection((host, port), timeout=tmo)
    s.settimeout(tmo)
    s.sendall(nb(h + body))
    r = recv_nb(s); s.close()
    if len(r) >= 68 and r[0:4] == b"\xfeSMB" and r[8:12] == b"\x00\x00\x00\x00":
        sec = struct.unpack("<H", r[66:68])[0]
        rev = struct.unpack("<H", r[68:70])[0] if len(r) >= 70 else 0
        if rev in DIALECTS: emit("DIALECT", DIALECTS[rev])
        emit("SIGNING", "required" if (sec & 0x2) else "not_required")
except Exception:
    pass

# ---- SMB1 negotiate: is NT LM 0.12 accepted? ----
try:
    dlg = b"\x02NT LM 0.12\x00"
    smb1 = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\x01\x28"
            + b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 4 + b"\x00" * 2 + b"\x00\x00"
            + b"\xff\xfe" + b"\x00\x00" + b"\x00\x00"
            + b"\x00" + struct.pack("<H", len(dlg)) + dlg)
    s = socket.create_connection((host, port), timeout=tmo)
    s.settimeout(tmo)
    s.sendall(nb(smb1))
    r = recv_nb(s); s.close()
    if len(r) >= 37 and r[4:8] == b"\xffSMB" and r[9:13] == b"\x00\x00\x00\x00":
        didx = struct.unpack("<H", r[37:39])[0] if len(r) >= 39 else 0xFFFF
        if didx != 0xFFFF:
            emit("SMBV1", "yes"); emit("DIALECT", "NT LM 0.12 (SMBv1)")
except Exception:
    pass
PY

# ---------------------------------------------------------- end-of-life OS --
# returns non-empty (the matched label) when an OS string is a known EOL build
eol_os() {
    local os="$1"
    case "$os" in
        *"Windows 2000"*|*"Windows XP"*|*"Server 2003"*|*"Windows Vista"*|\
        *"Windows 7"*|*"Server 2008"*|*"Windows 8"*|\
        *"Server 2012"*) printf '%s' "$os"; return 0 ;;
    esac
    return 1
}

# ----------------------------------------------------------- native enrich --
# All read-only. Each sets global flags / appends to arrays when it learns more.
enrich_native() {
    local host="$1"
    # smbclient: null + guest share listing
    if have smbclient; then
        local nullout guestout
        nullout="$(cap smbclient -N -g -L "//${host}" 2>/dev/null)"
        if printf '%s' "$nullout" | grep -qiE '^(Disk|IPC|Printer)\|'; then
            NULL_SESSION="yes"
            while IFS='|' read -r stype sname _; do
                [[ "$stype" =~ ^(Disk|IPC|Printer)$ ]] || continue
                [[ -n "$sname" ]] && SHARE_NAMES+=("$sname")
            done < <(printf '%s\n' "$nullout")
        fi
        guestout="$(cap smbclient -U 'guest%' -g -L "//${host}" 2>/dev/null)"
        printf '%s' "$guestout" | grep -qiE '^(Disk|IPC|Printer)\|' && GUEST_SESSION="yes"
    fi
    # rpcclient: null-session user enumeration over SAMR
    if have rpcclient; then
        local ru
        ru="$(cap rpcclient -N -U "" "$host" -c 'enumdomusers' 2>/dev/null)"
        while IFS= read -r line; do
            [[ "$line" =~ user:\[([^]]+)\][[:space:]]*rid:\[0x([0-9a-fA-F]+)\] ]] || continue
            NULL_SESSION="yes"
            local uname rid
            uname="${BASH_REMATCH[1]}"
            rid=$(( 16#${BASH_REMATCH[2]} ))
            USERS+=("${uname}|${rid}")
        done < <(printf '%s\n' "$ru")
        # OS / domain via srvinfo when not already known
        if [[ -z "$OSV" ]]; then
            local si
            si="$(cap rpcclient -N -U "" "$host" -c 'srvinfo' 2>/dev/null | head -2)"
            [[ -n "$si" ]] && OSV="$(printf '%s' "$si" | tail -1 | sed 's/^[[:space:]]*//')"
        fi
    fi
    # nmblookup: NetBIOS workgroup
    if have nmblookup && [[ -z "$WORKGROUP" ]]; then
        local nb
        nb="$(cap nmblookup -A "$host" 2>/dev/null | grep -i '<1e>\|<00> - <GROUP>' | head -1)"
        [[ -n "$nb" ]] && WORKGROUP="$(printf '%s' "$nb" | awk '{print $1}')"
    fi
    # netexec (nxc): authoritative signing / SMBv1 from its banner line
    if have nxc; then
        local banner
        banner="$(cap nxc smb "$host" -u '' -p '' 2>&1 | grep -m1 -iE 'signing:')"
        if [[ -n "$banner" ]]; then
            if printf '%s' "$banner" | grep -qiE 'signing:False'; then SIGNING="not_required"
            elif printf '%s' "$banner" | grep -qiE 'signing:True'; then
                [[ -z "$SIGNING" ]] && SIGNING="required"
            fi
            printf '%s' "$banner" | grep -qiE 'SMBv1:True' && SMBV1="yes"
        fi
    fi
}

# ------------------------------------------------------------- run one host --
audit_host() {
    local target="$1" host port
    host="${target%%:*}"
    if [[ "$target" == *:* ]]; then port="${target##*:}"; else port="${PORT_DEFAULT}"; fi

    # per-host state
    local REACHABLE="no" SMBV1="" SIGNING="" SIGNING_TEXT="" ACCOUNT_USED=""
    local OSV="" OS_CPE="" COMPUTER="" DOMAIN="" FOREST="" FQDN="" WORKGROUP="" SYSTIME=""
    local NULL_SESSION="" GUEST_SESSION=""
    local DIALECTS=() SHARES=() SHARE_NAMES=() USERS=() VULNS=()
    local problems=() checks=()

    # choose backend
    local use="$BACKEND"
    if [[ "$use" == "auto" ]]; then
        if have nmap; then use="nmap"; elif have python3; then use="python"; else
            err "neither nmap nor python3 available"; EXIT_CODE=2; return
        fi
    fi
    [[ "$use" == "nmap"   ]] && ! have nmap    && { err "nmap not found"; EXIT_CODE=2; return; }
    [[ "$use" == "python" ]] && ! have python3 && { err "python3 not found"; EXIT_CODE=2; return; }

    # ---------------- gather via nmap NSE (default backend) ----------------
    local kv=""
    if [[ "$use" == "nmap" ]]; then
        local scripts="smb-protocols,smb2-security-mode,smb-security-mode,smb-os-discovery"
        [[ $SAFE -eq 0 ]] && scripts+=",smb-enum-shares,smb-enum-users"
        [[ $VULN -eq 1 ]] && scripts+=",smb-vuln-ms17-010,smb-vuln-cve-2020-0796"
        local xml
        xml="$(nmap -Pn -n -sT -p "$port" --host-timeout "${TIMEOUT}s" \
                   -oX - --script "$scripts" "$host" 2>/dev/null)"
        kv="$(printf '%s' "$xml" | python3 -I -c "$PARSE_PY" "$port" 2>/dev/null)"
    else
        kv="$(python3 -I -c "$NEG_PY" "$host" "$port" "$TIMEOUT" 2>/dev/null)"
        # a dialect or signing line implies the port answered SMB
        printf '%s' "$kv" | grep -qE '^(DIALECT|SIGNING|SMBV1)\b' && REACHABLE="yes"
    fi

    # ---------------- fold the TSV into per-host state ----------------
    while IFS=$'\t' read -r key val; do
        [[ -z "$key" ]] && continue
        case "$key" in
            PORT_OPEN)    [[ "$val" == "yes" ]] && REACHABLE="yes" ;;
            DIALECT)      DIALECTS+=("$val") ;;
            SMBV1)        SMBV1="yes" ;;
            SIGNING)      [[ -z "$SIGNING" ]] && SIGNING="$val" ;;
            SIGNING_TEXT) [[ -z "$SIGNING_TEXT" ]] && SIGNING_TEXT="$val" ;;
            ACCOUNT_USED) ACCOUNT_USED="$val" ;;
            OS)           OSV="$val" ;;
            OS_CPE)       OS_CPE="$val" ;;
            COMPUTER)     COMPUTER="$val" ;;
            DOMAIN)       DOMAIN="$val" ;;
            FOREST)       FOREST="$val" ;;
            FQDN)         FQDN="$val" ;;
            WORKGROUP)    WORKGROUP="$val" ;;
            SYSTIME)      SYSTIME="$val" ;;
            SHARE)        SHARES+=("$val") ;;
            USER)         USERS+=("$val") ;;
            VULN)         VULNS+=("$val") ;;
        esac
    done < <(printf '%s\n' "$kv")

    # dialects / shares / users imply the service answered
    { [[ ${#DIALECTS[@]} -gt 0 ]] || [[ ${#SHARES[@]} -gt 0 ]] || [[ -n "$OSV" ]]; } && REACHABLE="yes"

    # ---------------- native enrichment (preferred-when-present) ----------
    if [[ "$REACHABLE" == "yes" && $SAFE -eq 0 ]]; then
        enrich_native "$host"
    elif [[ "$REACHABLE" == "yes" ]]; then
        # even in --safe mode let nxc confirm signing/SMBv1 if present
        if have nxc; then
            local b
            b="$(cap nxc smb "$host" -u '' -p '' 2>&1 | grep -m1 -iE 'signing:')"
            printf '%s' "$b" | grep -qiE 'signing:False' && SIGNING="not_required"
            printf '%s' "$b" | grep -qiE 'SMBv1:True'    && SMBV1="yes"
        fi
    fi

    # account_used hints at null/guest
    if [[ -z "$GUEST_SESSION" && "${ACCOUNT_USED,,}" == "guest" ]]; then GUEST_SESSION="yes"; fi
    if [[ -z "$NULL_SESSION" ]]; then
        { [[ -z "$ACCOUNT_USED" || "$ACCOUNT_USED" == "<blank>" ]] && [[ ${#SHARES[@]} -gt 0 || ${#USERS[@]} -gt 0 ]]; } && NULL_SESSION="yes"
    fi

    # ======================= evaluate weak conditions =======================
    addck() { checks+=("$1|$2|$3"); }   # id|severity|status

    if [[ "$REACHABLE" != "yes" ]]; then
        if [[ $JSON -eq 1 ]]; then
            printf '{"tool":"smb-audit","host":"%s","port":"%s","reachable":false,"problems":["no SMB response (host down, filtered, or not SMB)"]}\n' \
                "$(jesc "$host")" "$(jesc "$port")"
        else
            section "${host}:${port}"; err "no SMB response (host down, filtered, or not SMB)"
        fi
        EXIT_CODE=1; return
    fi

    # SMBv1
    if [[ "$SMBV1" == "yes" ]]; then
        problems+=("[HIGH] smbv1-enabled: SMBv1 (NT LM 0.12) offered — deprecated; MS17-010/EternalBlue & WannaCry surface")
        addck smbv1-enabled HIGH fail
    else
        addck smbv1-enabled HIGH pass
    fi

    # signing
    case "$SIGNING" in
        not_required)
            problems+=("[HIGH] smb-signing-not-required: message signing not enforced — SMB/NTLM-relay & MITM risk${SIGNING_TEXT:+ (${SIGNING_TEXT})}")
            addck smb-signing-not-required HIGH fail ;;
        required) addck smb-signing-not-required HIGH pass ;;
        *)        addck smb-signing-not-required HIGH unknown ;;
    esac

    # null session
    if [[ "$NULL_SESSION" == "yes" ]]; then
        problems+=("[HIGH] smb-null-session: null/anonymous session accepted — unauthenticated enumeration possible")
        addck smb-null-session HIGH fail
    else
        addck smb-null-session HIGH pass
    fi

    # guest session
    if [[ "$GUEST_SESSION" == "yes" ]]; then
        problems+=("[MEDIUM] smb-guest-session: guest account accepted — unauthenticated access")
        addck smb-guest-session MEDIUM fail
    else
        addck smb-guest-session MEDIUM pass
    fi

    # anonymous share access  (IPC$ anon READ is normal and excluded)
    local anon_read=0 anon_write=0 s
    for s in "${SHARES[@]:-}"; do
        [[ -z "$s" ]] && continue
        local sname sanon
        sname="${s%%|*}"
        sanon="$(printf '%s' "$s" | cut -d'|' -f2)"
        [[ "${sname^^}" == "IPC\$" || "${sname^^}" == "IPC" ]] && continue
        if printf '%s' "$sanon" | grep -qiE 'WRITE'; then
            anon_write=1
            problems+=("[CRITICAL] smb-share-anon-writable: share '${sname}' is WRITABLE over an anonymous session")
        elif printf '%s' "$sanon" | grep -qiE 'READ'; then
            anon_read=1
            problems+=("[HIGH] smb-share-anon-readable: share '${sname}' is READABLE over an anonymous session")
        fi
    done
    [[ $anon_write -eq 1 ]] && addck smb-share-anon-writable CRITICAL fail || addck smb-share-anon-writable CRITICAL pass
    [[ $anon_read  -eq 1 ]] && addck smb-share-anon-readable HIGH fail      || addck smb-share-anon-readable HIGH pass

    # EOL OS
    local eol
    if eol="$(eol_os "$OSV")"; then
        problems+=("[HIGH] smb-eol-os: end-of-life OS '${eol}' — unsupported, unpatched")
        addck smb-eol-os HIGH fail
    else
        addck smb-eol-os HIGH pass
    fi

    # RID / user enumeration
    if [[ ${#USERS[@]} -gt 0 && ( "$NULL_SESSION" == "yes" || "$GUEST_SESSION" == "yes" ) ]]; then
        problems+=("[MEDIUM] smb-rid-user-enum: ${#USERS[@]} user account(s) enumerable over MS-RPC (SAMR/LSA) without valid creds")
        addck smb-rid-user-enum MEDIUM fail
    else
        addck smb-rid-user-enum MEDIUM pass
    fi

    # OS / domain disclosure (informational; not a failure on its own)
    if [[ -n "$OSV" || -n "$DOMAIN" || -n "$WORKGROUP" || -n "$FQDN" ]]; then
        addck smb-os-domain-disclosure INFO info
    fi

    # vuln NSE (detection only)
    for v in "${VULNS[@]:-}"; do
        [[ -z "$v" ]] && continue
        local vid vids
        vid="${v%%|*}"; vids="$(printf '%s' "$v" | cut -d'|' -f3)"
        if [[ "$vid" == "ms17-010" ]]; then
            problems+=("[CRITICAL] smb-vuln-ms17-010: EternalBlue — host reports VULNERABLE (${vids})")
            addck smb-vuln-ms17-010 CRITICAL fail
        elif [[ "$vid" == "smbghost" ]]; then
            problems+=("[CRITICAL] smb-vuln-smbghost: SMBGhost — host reports VULNERABLE (${vids})")
            addck smb-vuln-smbghost CRITICAL fail
        fi
    done

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    # =============================== output ===============================
    if [[ $JSON -eq 1 ]]; then
        local pj="" dj="" sj="" uj="" cj="" first p d s u c n=0
        first=1; for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        first=1; for d in "${DIALECTS[@]:-}"; do [[ -z "$d" ]] && continue
            [[ $first -eq 0 ]] && dj+=","; dj+="\"$(jesc "$d")\""; first=0; done
        first=1; for s in "${SHARES[@]:-}"; do [[ -z "$s" ]] && continue
            local sn sa scc
            sn="${s%%|*}"; sa="$(printf '%s' "$s" | cut -d'|' -f2)"; scc="$(printf '%s' "$s" | cut -d'|' -f3)"
            [[ $first -eq 0 ]] && sj+=","
            sj+="{\"name\":\"$(jesc "$sn")\",\"anonymous\":\"$(jesc "$sa")\",\"current\":\"$(jesc "$scc")\"}"; first=0; done
        first=1; for u in "${USERS[@]:-}"; do [[ -z "$u" ]] && continue; [[ $n -ge 100 ]] && break
            local un ur
            un="${u%%|*}"; ur="$(printf '%s' "$u" | cut -d'|' -f2)"
            [[ $first -eq 0 ]] && uj+=","
            uj+="{\"name\":\"$(jesc "$un")\",\"rid\":\"$(jesc "$ur")\"}"; first=0; n=$((n+1)); done
        first=1; for c in "${checks[@]:-}"; do [[ -z "$c" ]] && continue
            local ci cs ct
            ci="${c%%|*}"; cs="$(printf '%s' "$c" | cut -d'|' -f2)"; ct="$(printf '%s' "$c" | cut -d'|' -f3)"
            [[ $first -eq 0 ]] && cj+=","
            cj+="{\"id\":\"$(jesc "$ci")\",\"severity\":\"$(jesc "$cs")\",\"status\":\"$(jesc "$ct")\"}"; first=0; done
        printf '{"tool":"smb-audit","host":"%s","port":"%s","reachable":true,' "$(jesc "$host")" "$(jesc "$port")"
        printf '"dialects":[%s],"smbv1":%s,"signing":"%s","null_session":%s,"guest_session":%s,' \
            "$dj" "$([[ "$SMBV1" == yes ]] && echo true || echo false)" "$(jesc "${SIGNING:-unknown}")" \
            "$([[ "$NULL_SESSION" == yes ]] && echo true || echo false)" \
            "$([[ "$GUEST_SESSION" == yes ]] && echo true || echo false)"
        printf '"os":"%s","os_cpe":"%s","computer":"%s","domain":"%s","forest":"%s","fqdn":"%s","workgroup":"%s","system_time":"%s",' \
            "$(jesc "$OSV")" "$(jesc "$OS_CPE")" "$(jesc "$COMPUTER")" "$(jesc "$DOMAIN")" "$(jesc "$FOREST")" "$(jesc "$FQDN")" "$(jesc "$WORKGROUP")" "$(jesc "$SYSTIME")"
        printf '"shares":[%s],"users":[%s],"checks":[%s],"problems":[%s]}\n' "$sj" "$uj" "$cj" "$pj"
        return
    fi

    section "${host}:${port}"
    field "Reachable"   "yes (SMB)"
    [[ ${#DIALECTS[@]} -gt 0 ]] && field "Dialects" "$(IFS=,; echo "${DIALECTS[*]}")"
    field "SMBv1"       "${SMBV1:-no}"
    field "Signing"     "${SIGNING:-unknown}${SIGNING_TEXT:+  ${C_DIM}(${SIGNING_TEXT})${C_RST}}"
    field "Null session" "${NULL_SESSION:-no}"
    field "Guest session" "${GUEST_SESSION:-no}"
    [[ -n "$OSV"       ]] && field "OS" "$OSV"
    [[ -n "$OS_CPE"    ]] && field "OS CPE" "$OS_CPE"
    [[ -n "$COMPUTER"  ]] && field "Computer" "$COMPUTER"
    [[ -n "$DOMAIN"    ]] && field "Domain" "$DOMAIN"
    [[ -n "$FQDN"      ]] && field "FQDN" "$FQDN"
    [[ -n "$WORKGROUP" ]] && field "Workgroup" "$WORKGROUP"
    [[ -n "$SYSTIME"   ]] && field "System time" "$SYSTIME"
    if [[ ${#SHARES[@]} -gt 0 ]]; then
        printf '    %s%s%s\n' "${C_DIM}" "Shares (name  anon/current):" "${C_RST}"
        for s in "${SHARES[@]}"; do
            [[ -z "$s" ]] && continue
            printf '      %-18s %s / %s\n' "$(printf '%s' "$s" | cut -d'|' -f1)" \
                "$(printf '%s' "$s" | cut -d'|' -f2)" "$(printf '%s' "$s" | cut -d'|' -f3)"
        done
    fi
    [[ ${#USERS[@]} -gt 0 ]] && field "Users (RPC)" "${#USERS[@]} enumerated"
    echo
    if [[ ${#problems[@]} -eq 0 ]]; then
        ok "no SMB weaknesses detected"
    else
        local p
        for p in "${problems[@]}"; do
            case "$p" in
                \[CRITICAL\]*) crit "$p" ;;
                \[HIGH\]*)     err  "$p" ;;
                \[MEDIUM\]*)   warn "$p" ;;
                *)             info "$p" ;;
            esac
        done
    fi

    return
}

# ---------------------------------------------------------------------- main --
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no hosts given"; usage; exit 2; }
if ! have nmap && ! have python3; then err "need nmap or python3"; exit 2; fi

# authorized-use banner (stderr so it never pollutes --json stdout)
printf '%s[*] smb-audit — authorized / lab use only. Read-only enumeration.%s\n' \
    "${C_DIM}" "${C_RST}" >&2
if [[ $JSON -eq 0 ]]; then
    MODE=""
    [[ $SAFE -eq 1 ]] && MODE+=" (safe)"
    [[ $VULN -eq 1 ]] && MODE+=" (+vuln)"
    info "smb-audit — ${#TARGETS[@]} target(s), backend=${BACKEND}, timeout ${TIMEOUT}s${MODE}"
fi

for t in "${TARGETS[@]}"; do audit_host "$t"; done
exit "${EXIT_CODE}"
