#!/usr/bin/env bash
#
# dns-audit.sh — DNS hygiene & mail-authentication analyser
# =============================================================================
#   Read-only DNS reconnaissance for one or more domains. Reports core records
#   and flags common problems:
#     * SPF   — missing, multiple, or overly-permissive (+all)
#     * DMARC — missing, or policy p=none (monitor-only)
#     * DKIM  — probes common selectors
#     * CAA   — missing (any CA may issue)
#     * DNSSEC— not enabled
#     * AXFR  — zone transfer allowed (misconfiguration / info leak)
#     * CNAME — dangling records pointing at unclaimed services (takeover risk)
#   Only performs ordinary DNS lookups. Assess domains you are authorized to.
# =============================================================================
#
#   Requires: dig (preferred) OR nslookup. Optional: python3 (resolver fallback).
#
#   Quick start:
#     ./dns-audit.sh example.com
#     ./dns-audit.sh -f domains.txt
#     ./dns-audit.sh --json example.com
#     ./dns-audit.sh --dkim-selectors "google,selector1,k1" example.com
#     ./dns-audit.sh --no-axfr example.com        # skip zone-transfer attempts
#
set -uo pipefail

TIMEOUT=5
JSON=0
DO_AXFR=1
DOMAINS=()
EXIT_CODE=0
DKIM_SELECTORS="default,google,selector1,selector2,k1,k2,mail,dkim,s1,s2,smtp,zoho,pm,protonmail,fm1,mandrill,mxvault,dkim1"
SUBS_FOR_CNAME="www,mail,blog,dev,staging,test,cdn,assets,api,shop,support,portal,autodiscover,m,app"

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
field()   { printf '    %s%-14s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }
jesc()    { local s="${1//$'\r'/}"; s="${s//$'\t'/ }"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            [[ -z "${2:-}" ]] && { err "missing FILE"; exit 2; }
            while IFS= read -r l; do l="${l%%#*}"; l="${l//[[:space:]]/}"; [[ -n "$l" ]] && DOMAINS+=("$l"); done < "$2"
            shift 2 ;;
        -t|--timeout)        TIMEOUT="${2:?}"; shift 2 ;;
        --dkim-selectors)    DKIM_SELECTORS="${2:?}"; shift 2 ;;
        --no-axfr)           DO_AXFR=0; shift ;;
        --json)              JSON=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        -*)                  err "unknown option: $1"; usage; exit 2 ;;
        *)                   DOMAINS+=("$1"); shift ;;
    esac
done
[[ ${#DOMAINS[@]} -eq 0 ]] && { err "no domains given"; usage; exit 2; }

# ---- query backend ----------------------------------------------------------
# Preference: dig (authoritative, full-featured on Kali/Linux) > python3
# (correct, cross-platform UDP resolver, embedded below) > nslookup (last resort).
BACKEND=""
if   have dig;      then BACKEND="dig"
elif have python3;  then BACKEND="python3"
elif have nslookup; then BACKEND="nslookup"
else err "need dig, python3, or nslookup"; exit 2; fi

# nameserver for the python3 backend: resolv.conf -> $ARSENAL_DNS -> 1.1.1.1
PY_NS="${ARSENAL_DNS:-}"
if [[ -z "$PY_NS" && -r /etc/resolv.conf ]]; then
    PY_NS="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
fi
[[ -z "$PY_NS" ]] && PY_NS="1.1.1.1"

# Compact stdlib DNS resolver used when dig is unavailable. Queries PY_NS over
# UDP and prints record values (one per line) for the given type.
read -r -d '' DNS_PY <<'PYEOF' || true
import sys, socket, struct, random
TYPES = {"A":1,"NS":2,"CNAME":5,"SOA":6,"MX":15,"TXT":16,"AAAA":28,"CAA":257}
qtype_s, name, server, timeout = sys.argv[1], sys.argv[2].rstrip("."), sys.argv[3], float(sys.argv[4])
qtype = TYPES.get(qtype_s)
if not qtype: sys.exit(0)
def enc(n):
    out = b""
    for part in n.split("."):
        if part: out += bytes([len(part)]) + part.encode()
    return out + b"\x00"
tid = random.randint(0, 65535)
pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + enc(name) + struct.pack(">HH", qtype, 1)
def over_tcp():
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM); t.settimeout(timeout)
    t.connect((server, 53)); t.sendall(struct.pack(">H", len(pkt)) + pkt)
    hdr = b""
    while len(hdr) < 2: hdr += t.recv(2 - len(hdr))
    ln = struct.unpack(">H", hdr)[0]; buf = b""
    while len(buf) < ln: buf += t.recv(ln - len(buf))
    t.close(); return buf
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(pkt, (server, 53)); data, _ = s.recvfrom(65535); s.close()
    if len(data) >= 4 and (struct.unpack(">H", data[2:4])[0] & 0x0200):  # TC: retry over TCP
        data = over_tcp()
except Exception:
    try:
        data = over_tcp()
    except Exception:
        sys.exit(0)
def rdname(data, off):
    labels = []; jumped = False; start = off
    while True:
        if off >= len(data): break
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off+2])[0] & 0x3FFF
            if not jumped: start = off + 2
            off = ptr; jumped = True; continue
        if ln == 0:
            off += 1;
            if not jumped: start = off
            break
        labels.append(data[off+1:off+1+ln].decode("latin1")); off += 1 + ln
    return ".".join(labels), (start if jumped else off)
try:
    qd = struct.unpack(">H", data[4:6])[0]; an = struct.unpack(">H", data[6:8])[0]
    off = 12
    for _ in range(qd):
        _, off = rdname(data, off); off += 4
    out = []
    for _ in range(an):
        _, off = rdname(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off+10]); off += 10
        rd = data[off:off+rdlen]
        if rtype == 1 and rdlen == 4: out.append(".".join(str(b) for b in rd))
        elif rtype == 28 and rdlen == 16: out.append(socket.inet_ntop(socket.AF_INET6, rd))
        elif rtype in (2, 5): out.append(rdname(data, off)[0] + ".")
        elif rtype == 6: out.append(rdname(data, off)[0] + ".")
        elif rtype == 15:
            pref = struct.unpack(">H", rd[:2])[0]; mx, _ = rdname(data, off+2); out.append(f"{pref} {mx}.")
        elif rtype == 16:
            i = 0; parts = []
            while i < rdlen:
                sl = rd[i]; parts.append(rd[i+1:i+1+sl].decode("latin1")); i += 1 + sl
            out.append("".join(parts))
        elif rtype == 257 and rdlen >= 2:
            fl = rd[0]; tl = rd[1]; tag = rd[2:2+tl].decode("latin1"); val = rd[2+tl:].decode("latin1")
            out.append(f'{fl} {tag} "{val}"')
        off += rdlen
    for v in out: print(v)
except Exception:
    sys.exit(0)
PYEOF

# dns_query <type> <name>   -> record values, one per line (best effort)
dns_query() {
    local type="$1" name="$2"
    # strip CR centrally so Windows-python / nslookup CRLF never leaks into
    # record values (would corrupt JSON and text output alike)
    {
    case "$BACKEND" in
        dig)
            dig +time="$TIMEOUT" +tries=1 +short "$type" "$name" 2>/dev/null ;;
        python3)
            python3 -c "$DNS_PY" "$type" "$name" "$PY_NS" "$TIMEOUT" 2>/dev/null ;;
        nslookup)
            case "$type" in
                A|AAAA)  nslookup -type="$type" "$name" 2>/dev/null | awk 'f&&/^(Address|Addresses): /{print $2} /^Name:/{f=1}' ;;
                MX)      nslookup -type=MX "$name" 2>/dev/null | sed -n 's/.*mail exchanger = //p' ;;
                NS)      nslookup -type=NS "$name" 2>/dev/null | sed -n 's/.*nameserver = //p' ;;
                TXT)     nslookup -type=TXT "$name" 2>/dev/null | grep -oE '"[^"]*"' | tr -d '"' ;;
                CNAME)   nslookup -type=CNAME "$name" 2>/dev/null | sed -n 's/.*canonical name = //p' ;;
                SOA)     nslookup -type=SOA "$name" 2>/dev/null | sed -n 's/.*origin = //p' ;;
                CAA)     : ;;
            esac ;;
    esac
    } | tr -d '\r'
}

resolves() { [[ -n "$(dns_query A "$1")" || -n "$(dns_query AAAA "$1")" ]]; }

# takeover-prone CNAME targets (non-exhaustive, DNS-only signal)
TAKEOVER_RE='github\.io|herokudns|herokuapp|s3.*amazonaws|azurewebsites|cloudfront\.net|ghost\.io|wpengine|fastly\.net|pantheonsite|readthedocs|surge\.sh|bitbucket\.io|zendesk|helpscout|unbounce|desk\.com|cargocollective|statuspage|launchrock|feedpress'

audit_domain() {
    local d="$1"
    local problems=()
    local a ns mx soa caa dnssec="no" spf="" dmarc="" dkim_found=()

    a="$(dns_query A "$d" | paste -sd, -)"
    ns="$(dns_query NS "$d" | sed 's/\.$//' | paste -sd, -)"
    mx="$(dns_query MX "$d" | sed 's/\.$//' | paste -sd, -)"
    soa="$(dns_query SOA "$d" | head -1)"

    # --- SPF -----------------------------------------------------------------
    local txt spf_count=0
    txt="$(dns_query TXT "$d")"
    while IFS= read -r line; do
        [[ "$line" == v=spf1* ]] && { spf="$line"; spf_count=$((spf_count+1)); }
    done <<<"$txt"
    if   [[ -z "$spf" ]];            then problems+=("SPF: no record (sender spoofing easier)")
    elif (( spf_count > 1 ));         then problems+=("SPF: multiple records (invalid per RFC 7208)")
    elif echo "$spf" | grep -qiE '(^| )\+?all'; then
        echo "$spf" | grep -qiE '[~-]all' || problems+=("SPF: ends in +all/all (permits any sender)")
    fi

    # --- DMARC ---------------------------------------------------------------
    local dmtxt
    dmtxt="$(dns_query TXT "_dmarc.$d" | grep -i 'v=DMARC1' | head -1)"
    dmarc="$dmtxt"
    if [[ -z "$dmtxt" ]]; then
        problems+=("DMARC: no record")
    else
        local pol; pol="$(echo "$dmtxt" | grep -oiE 'p=[a-z]+' | head -1 | cut -d= -f2)"
        [[ "${pol,,}" == "none" ]] && problems+=("DMARC: policy p=none (monitor only, not enforced)")
        echo "$dmtxt" | grep -qiE 'rua=' || problems+=("DMARC: no rua= aggregate reporting address")
    fi

    # --- DKIM (selector probe) ----------------------------------------------
    local sel
    IFS=',' read -ra sels <<<"$DKIM_SELECTORS"
    for sel in "${sels[@]}"; do
        [[ -z "$sel" ]] && continue
        local dk; dk="$(dns_query TXT "${sel}._domainkey.$d" | grep -iE 'v=DKIM1|k=|p=' | head -1)"
        [[ -n "$dk" ]] && dkim_found+=("$sel")
    done
    [[ ${#dkim_found[@]} -eq 0 ]] && problems+=("DKIM: no common selector found (checked ${#sels[@]})")

    # --- CAA -----------------------------------------------------------------
    caa="$(dns_query CAA "$d" | paste -sd, -)"
    if [[ "$BACKEND" != "nslookup" && -z "$caa" ]]; then
        problems+=("CAA: no record (any CA may issue certificates)")
    fi

    # --- DNSSEC --------------------------------------------------------------
    if [[ "$BACKEND" == "dig" ]]; then
        if dig +time="$TIMEOUT" +tries=1 +dnssec "$d" 2>/dev/null | grep -q 'RRSIG' \
           || [[ -n "$(dig +short DS "$d" 2>/dev/null)" ]]; then
            dnssec="yes"
        else
            dnssec="no"; problems+=("DNSSEC: not enabled")
        fi
    else
        dnssec="unknown"
    fi

    # --- AXFR zone transfer --------------------------------------------------
    local axfr_open=()
    if [[ ${DO_AXFR} -eq 1 && "$BACKEND" == "dig" && -n "$ns" ]]; then
        local nsrv nsarr
        IFS=',' read -ra nsarr <<<"$ns"
        for nsrv in "${nsarr[@]}"; do
            [[ -z "$nsrv" ]] && continue
            local xfr
            xfr="$(dig +time="$TIMEOUT" +tries=1 axfr "$d" "@${nsrv}" 2>/dev/null)"
            if echo "$xfr" | grep -qiE "^${d}\.?[[:space:]].*SOA" && \
               [[ "$(echo "$xfr" | grep -cvE '^(;|$)')" -gt 2 ]]; then
                axfr_open+=("$nsrv")
            fi
        done
        [[ ${#axfr_open[@]} -gt 0 ]] && problems+=("AXFR: zone transfer allowed from: ${axfr_open[*]}")
    fi

    # --- dangling CNAME / takeover hints -------------------------------------
    local dangling=()
    IFS=',' read -ra subs <<<"$SUBS_FOR_CNAME"
    local s
    for s in "${subs[@]}"; do
        [[ -z "$s" ]] && continue
        local cn; cn="$(dns_query CNAME "${s}.$d" | head -1 | sed 's/\.$//')"
        [[ -z "$cn" ]] && continue
        if echo "$cn" | grep -qiE "$TAKEOVER_RE"; then
            resolves "$cn" || dangling+=("${s}.$d -> ${cn} (unclaimed service?)")
        elif ! resolves "$cn"; then
            dangling+=("${s}.$d -> ${cn} (target does not resolve)")
        fi
    done
    [[ ${#dangling[@]} -gt 0 ]] && problems+=("dangling CNAME (takeover risk): ${dangling[*]}")

    [[ ${#problems[@]} -gt 0 ]] && EXIT_CODE=1

    # --- output --------------------------------------------------------------
    if [[ ${JSON} -eq 1 ]]; then
        local pj="" first=1 p
        for p in "${problems[@]:-}"; do [[ -z "$p" ]] && continue
            [[ $first -eq 0 ]] && pj+=","; pj+="\"$(jesc "$p")\""; first=0; done
        printf '{"tool":"dns-audit","host":"%s",' "$(jesc "$d")"
        printf '"a":"%s","ns":"%s","mx":"%s","spf":"%s","dmarc":"%s",' \
            "$(jesc "$a")" "$(jesc "$ns")" "$(jesc "$mx")" "$(jesc "$spf")" "$(jesc "$dmarc")"
        printf '"dkim_selectors":"%s","caa":"%s","dnssec":"%s","axfr_open":"%s","problems":[%s]}\n' \
            "$(jesc "$(IFS=,; echo "${dkim_found[*]:-}")")" "$(jesc "$caa")" "$dnssec" \
            "$(jesc "$(IFS=,; echo "${axfr_open[*]:-}")")" "$pj"
        return
    fi

    section "$d  (backend: $BACKEND)"
    field "A"       "${a:-none}"
    field "NS"      "${ns:-none}"
    field "MX"      "${mx:-none}"
    [[ -n "$soa" ]] && field "SOA" "$soa"
    field "SPF"     "${spf:-none}"
    field "DMARC"   "${dmarc:-none}"
    local dkim_disp="none"; [[ ${#dkim_found[@]} -gt 0 ]] && dkim_disp="$(IFS=,; echo "${dkim_found[*]}")"
    field "DKIM"    "$dkim_disp"
    field "CAA"     "${caa:-none}"
    field "DNSSEC"  "$dnssec"
    if [[ ${#problems[@]} -eq 0 ]]; then ok "no issues detected"
    else local p; for p in "${problems[@]}"; do warn "$p"; done; fi
}

[[ ${JSON} -eq 0 ]] && info "dns-audit — ${#DOMAINS[@]} domain(s), backend=${BACKEND}, timeout ${TIMEOUT}s"
for d in "${DOMAINS[@]}"; do audit_domain "$d"; done
exit "${EXIT_CODE}"
