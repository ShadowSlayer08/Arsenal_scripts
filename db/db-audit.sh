#!/usr/bin/env bash
#
# db-audit.sh — exposed-database posture analyser
# =============================================================================
#   Detects a database service + version on a port and SAFELY, read-only, tests
#   for the misconfigurations that make an exposed DB a breach:
#     * unauthenticated / no-auth access   (Redis, MongoDB, Elasticsearch, ...)
#     * blank / default credentials        (MySQL root, MSSQL sa, Postgres trust)
#     * TLS availability                   (is traffic forced in the clear?)
#     * dangerous defaults                 (Redis CONFIG enabled, SQL Browser, ...)
#
#   Supported engines: mysql | mariadb | mssql | postgres | mongodb | redis |
#                      elasticsearch
#
#   NOTHING here is destructive. No data is written, dropped or modified. The
#   RCE/write-proof probes (e.g. a Redis canary SET/DEL) are gated behind the
#   explicit --allow-destructive flag, which also enables nmap *-brute scripts.
#
#   Backend: nmap NSE when present (default/discovery/safe scripts) enriches the
#   result; a self-contained python3 raw-protocol engine is the universal
#   fallback and always runs. Native clients (redis-cli, mongosh, psql) are not
#   required. On a stock box only nmap, curl and python3 are assumed present.
# =============================================================================
#
#   Requires: python3 (universal engine). Optional: nmap (enrichment), curl.
#
#   Quick start:
#     ./db-audit.sh redis://10.0.0.5                 # scheme picks the engine
#     ./db-audit.sh --type redis 10.0.0.5            # same, explicit
#     ./db-audit.sh 10.0.0.5:6379                    # port 6379 -> redis
#     ./db-audit.sh --type postgres db.lab:5432
#     ./db-audit.sh --json --type mongodb 10.0.0.5 | ../lib/report.sh -
#     ./db-audit.sh --allow-destructive --type redis 10.0.0.5   # +canary write
#
#   Gate targets through ../engage/scope-guard.sh before running at scale.
#   Authorized / lab / CTF use only.
#
set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

PORT_OVERRIDE=""
FORCE_TYPE=""
TIMEOUT=6
JSON=0
NO_NMAP=0
ALLOW_DESTRUCTIVE=0
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
err()     { printf '%s[x]%s %s\n'  "${C_R}"   "${C_RST}" "$*" >&2; }
field()   { printf '    %s%-12s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME}${C_RST} — exposed-database posture analyser (safe / read-only)

USAGE:
    ${SCRIPT_NAME} [options] <target> [target ...]

    target forms:  host              host:port
                   scheme://host     scheme://host:port
    schemes:       mysql mariadb mssql postgres postgresql mongodb redis
                   elasticsearch (alias es)

OPTIONS:
    -T, --type TYPE          Force engine for targets without a scheme
    -p, --port PORT          Default port for targets without one
    -t, --timeout SEC        Per-probe timeout (default: ${TIMEOUT})
        --no-nmap            Skip nmap enrichment; use python3 engine only
        --allow-destructive  Opt in to destructive-ish probes: Redis canary
                             SET/DEL write-proof + nmap *-brute scripts.
                             (alias: --unsafe)
        --json               Emit JSON (one object per target) instead of text
    -h, --help               Show this help

EXIT STATUS:
    0  reachable services, no weakness found (or host simply down)
    1  at least one finding (unauth access / default creds / no TLS / risky)
    2  usage error

CHECKS (safe, read-only unless noted):
    redis          PING/INFO no-auth, requirepass/protected-mode/bind via
                   CONFIG GET, CONFIG-enabled warning, TLS. (--allow-destructive
                   adds a canary SET/DEL to prove write access, then deletes it.)
    mongodb        listDatabases unauthenticated (the real no-auth test;
                   buildInfo is NOT, it answers pre-auth), version, TLS.
    elasticsearch  GET / and /_cat/indices without creds, index/doc exposure,
                   cleartext-HTTP, version.
    postgres       SSLRequest TLS probe, StartupMessage trust-auth detection
                   (AuthenticationOk with no password), auth method.
    mysql/mariadb  handshake version, CLIENT_SSL (TLS) capability, old-password
                   hashing; blank/default-cred login only with --allow-destructive.
    mssql          UDP 1434 Browser exposure + version, TDS PRELOGIN encryption
                   (TLS) token; sa blank-password login only with --allow-destructive.

NOTES:
    Nothing is written or modified without --allow-destructive. Only probe
    services you own or are explicitly authorized to test.
EOF
}

# -------------------------------------------------------------- arg parsing --
while [[ $# -gt 0 ]]; do
    case "$1" in
        -T|--type)            FORCE_TYPE="${2:?}"; shift 2 ;;
        -p|--port)            PORT_OVERRIDE="${2:?}"; shift 2 ;;
        -t|--timeout)         TIMEOUT="${2:?}"; shift 2 ;;
        --no-nmap)            NO_NMAP=1; shift ;;
        --allow-destructive|--unsafe) ALLOW_DESTRUCTIVE=1; shift ;;
        --json)               JSON=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        --)                   shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
        -*)                   err "unknown option: $1"; usage; exit 2 ;;
        *)                    TARGETS+=("$1"); shift ;;
    esac
done

[[ ${#TARGETS[@]} -eq 0 ]] && { err "no targets given"; usage; exit 2; }
have python3 || { err "python3 is required (universal engine)"; exit 2; }

# normalise an engine name to the canonical token the engine understands
norm_type() {
    case "${1,,}" in
        mysql)                 echo mysql ;;
        mariadb)               echo mariadb ;;
        mssql|sqlserver|ms-sql)echo mssql ;;
        postgres|postgresql|pgsql|pg) echo postgres ;;
        mongodb|mongo)         echo mongodb ;;
        redis)                 echo redis ;;
        elasticsearch|elastic|es) echo elasticsearch ;;
        *)                     echo "" ;;
    esac
}

# default port per engine
default_port() {
    case "$1" in
        mysql|mariadb) echo 3306 ;;
        mssql)         echo 1433 ;;
        postgres)      echo 5432 ;;
        mongodb)       echo 27017 ;;
        redis)         echo 6379 ;;
        elasticsearch) echo 9200 ;;
        *)             echo "" ;;
    esac
}

# infer engine from a well-known port
type_from_port() {
    case "$1" in
        3306|3307) echo mysql ;;
        1433)      echo mssql ;;
        5432)      echo postgres ;;
        27017|27018|27019) echo mongodb ;;
        6379|6380) echo redis ;;
        9200|9201) echo elasticsearch ;;
        *)         echo "" ;;
    esac
}

# nmap NSE scripts to enrich a given engine (safe set; brute added when allowed)
nmap_scripts_for() {
    local t="$1" base=""
    # Default set is INFO-ONLY (read-only). Scripts that attempt a blank-password
    # login or authenticate+enumerate (empty-password, users, databases, brute)
    # are active credential guessing and only run with --allow-destructive.
    case "$t" in
        mysql|mariadb) base="mysql-info" ;;
        mssql)         base="ms-sql-info,ms-sql-ntlm-info" ;;
        mongodb)       base="mongodb-info,mongodb-databases" ;;
        redis)         base="redis-info" ;;
        postgres)      base="" ;;
        elasticsearch) base="" ;;
    esac
    if [[ $ALLOW_DESTRUCTIVE -eq 1 ]]; then
        case "$t" in
            mysql|mariadb) base="${base},mysql-empty-password,mysql-users,mysql-databases,mysql-brute" ;;
            mssql)         base="${base},ms-sql-empty-password,ms-sql-brute" ;;
            mongodb)       base="${base},mongodb-brute" ;;
            redis)         base="${base},redis-brute" ;;
            postgres)      base="pgsql-brute" ;;
        esac
    fi
    echo "${base#,}"
}

# ------------------------------------------------- nmap enrichment (optional) --
# Runs the mapped NSE scripts, returns a short note and whether a login/empty
# password was confirmed. Output: two lines -> NOTE then FINDING (may be empty).
run_nmap() {
    local host="$1" port="$2" dbtype="$3" scr args raw note="" finding=""
    scr="$(nmap_scripts_for "$dbtype")"
    args=(-Pn -n -p "$port" -sV)
    [[ -n "$scr" ]] && args+=(--script "$scr")
    [[ "$dbtype" == mssql ]] && args+=(--script-args "mssql.instance-port=${port}")
    if have timeout; then
        raw="$(timeout "$((TIMEOUT * 5))" nmap "${args[@]}" "$host" 2>/dev/null)"
    else
        raw="$(nmap "${args[@]}" "$host" 2>/dev/null)"
    fi
    note="$(printf '%s\n' "$raw" \
        | grep -iE 'empty password|login success|valid credentials|not authorized|requires authentication|no authentication|Databases \(|protocol|version' \
        | sed 's/^[[:space:]]*|*[_[:space:]]*//' | head -4 | tr '\n' ';')"
    printf '%s\n' "$raw" | grep -iqE 'empty password|Login Success|Valid credentials|Accounts:.*:.*:' \
        && finding="nmap NSE confirmed a blank/guessable login"
    printf '%s\n%s\n' "$note" "$finding"
}

# ------------------------------------------------------- python raw engine --
# Emits exactly one JSON object (the final tool schema) on stdout.
run_engine() {
    local host="$1" port="$2" dbtype="$3" nnote="$4" nfind="$5"
    HOST="$host" PORT="$port" DBTYPE="$dbtype" TMO="$TIMEOUT" \
    ALLOW_WRITE="$ALLOW_DESTRUCTIVE" NMAP_NOTE="$nnote" NMAP_FINDING="$nfind" \
    python3 - <<'PYBACKEND'
import os, sys, json, socket, struct, ssl, time, re

HOST = os.environ.get("HOST", "")
PORT = int(os.environ.get("PORT", "0") or "0")
DB   = os.environ.get("DBTYPE", "")
TMO  = float(os.environ.get("TMO", "6") or "6")
ALLOW_WRITE  = os.environ.get("ALLOW_WRITE", "0") == "1"
NMAP_NOTE    = os.environ.get("NMAP_NOTE", "").strip().strip(";")
NMAP_FINDING = os.environ.get("NMAP_FINDING", "").strip()

SEV = ["none", "info", "low", "medium", "high", "critical"]
state = {"version": None, "tls": "unknown", "reachable": False}
problems = []
facts = {}
sevmax = "none"


def add(sev, msg):
    global sevmax
    problems.append("[%s] %s" % (sev.upper(), msg))
    if SEV.index(sev) > SEV.index(sevmax):
        sevmax = sev


def connect(timeout=None):
    s = socket.create_connection((HOST, PORT), timeout or TMO)
    s.settimeout(timeout or TMO)
    state["reachable"] = True
    return s


def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            c = sock.recv(n - len(buf))
        except Exception:
            break
        if not c:
            break
        buf += c
    return buf


def tls_wrap(sock):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=HOST)


def best_effort_tls():
    """Best-effort direct TLS handshake (meaningful for separate TLS listeners)."""
    try:
        w = tls_wrap(connect())
        w.close()
        state["tls"] = "available"
    except Exception:
        if state["tls"] == "unknown":
            state["tls"] = "unavailable (plaintext)"


def eol_hint(service, version):
    if not version:
        return
    m = re.match(r"(\d+)(?:\.(\d+))?", str(version))
    if not m:
        return
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    thr = {"mysql": (5, 7), "mariadb": (10, 3), "redis": (6, 0),
           "postgres": (12, 0), "mongodb": (4, 4), "elasticsearch": (7, 0)}
    if service in thr:
        tmaj, tmin = thr[service]
        if major < tmaj or (major == tmaj and minor < tmin):
            add("medium", "%s: version %s looks end-of-life/old - confirm CVEs via cve-lookup" % (service, version))


# --------------------------------------------------------------- Redis (RESP)
def resp_read(f):
    line = f.readline()
    if not line:
        return None
    t = line[:1]
    body = line[1:].rstrip(b"\r\n")
    if t in (b"+", b"-", b":"):
        return (t.decode(), body.decode("utf-8", "replace"))
    if t == b"$":
        n = int(body or b"-1")
        if n < 0:
            return ("$", None)
        data = f.read(n)
        f.read(2)
        return ("$", data.decode("utf-8", "replace"))
    if t == b"*":
        n = int(body or b"-1")
        if n < 0:
            return ("*", None)
        return ("*", [resp_read(f) for _ in range(n)])
    return ("?", body.decode("utf-8", "replace"))


def redis_cmd(f, s, cmd):
    s.sendall((cmd + "\r\n").encode())
    return resp_read(f)


def audit_redis():
    s = connect()
    f = s.makefile("rb")
    r = redis_cmd(f, s, "PING")
    noauth = False
    if r and r[0] == "+" and r[1] == "PONG":
        noauth = True
    elif r and r[0] == "-":
        e = r[1]
        if "NOAUTH" in e:
            facts["auth"] = "required"
            add("info", "redis: authentication required (requirepass/ACL set)")
        elif "protected mode" in e.lower() or "DENIED" in e:
            add("medium", "redis: reachable; protected-mode is refusing remote commands")
            facts["auth"] = "protected-mode"
        else:
            facts["ping_error"] = e[:80]
    if noauth:
        facts["auth"] = "NONE"
        add("critical", "redis: NO AUTHENTICATION - any client can run commands")
        inf = redis_cmd(f, s, "INFO server")
        if inf and inf[0] == "$" and inf[1]:
            for ln in inf[1].splitlines():
                if ln.startswith("redis_version:"):
                    state["version"] = ln.split(":", 1)[1].strip()
                elif ln.startswith("os:"):
                    facts["os"] = ln.split(":", 1)[1].strip()
                elif ln.startswith("config_file:"):
                    facts["config_file"] = ln.split(":", 1)[1].strip()
                elif ln.startswith("executable:"):
                    facts["executable"] = ln.split(":", 1)[1].strip()
        for key in ("requirepass", "protected-mode", "bind", "dir"):
            cg = redis_cmd(f, s, "CONFIG GET %s" % key)
            if cg and cg[0] == "*" and isinstance(cg[1], list) and len(cg[1]) >= 2 and cg[1][1]:
                facts["config_" + key] = cg[1][1][1]
        if facts.get("config_requirepass", "") == "":
            add("critical", "redis: requirepass is empty")
        if facts.get("config_protected-mode", "") == "no":
            add("high", "redis: protected-mode disabled")
        b = facts.get("config_bind", "")
        if b == "" or "0.0.0.0" in b or "*" in b or "::" == b:
            add("high", "redis: listening on all interfaces (bind=%r)" % b)
        add("high", "redis: CONFIG command enabled -> CONFIG SET dir/dbfilename + SAVE "
                    "RCE chain possible; rename-command/ACL it")
        if ALLOW_WRITE:
            canary = "__dbaudit_%d__" % int(time.time())
            w = redis_cmd(f, s, "SET %s 1" % canary)
            if w and w[0] == "+" and w[1] == "OK":
                add("critical", "redis: WRITE access confirmed (canary key set) - data tamper / RCE risk")
                redis_cmd(f, s, "DEL %s" % canary)
                facts["canary"] = "set+deleted (cleaned up)"
    best_effort_tls()
    eol_hint("redis", state["version"])
    try:
        s.close()
    except Exception:
        pass


# ------------------------------------------------------- Elasticsearch (HTTP)
def http_get(scheme, path):
    import urllib.request
    import urllib.error
    url = "%s://%s:%d%s" % (scheme, HOST, PORT, path)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "db-audit"})
    try:
        r = urllib.request.urlopen(req, timeout=TMO, context=ctx)
        return r.getcode(), r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, str(e)


def audit_es():
    scheme = "http"
    code, body = http_get("http", "/")
    if code is None:
        code, body = http_get("https", "/")
        scheme = "https"
        if code is not None:
            state["tls"] = "available (https)"
            state["reachable"] = True
    else:
        state["tls"] = "unavailable (plaintext http)"
        state["reachable"] = True
    if code is None:
        facts["error"] = body[:100]
        return
    facts["scheme"] = scheme
    if code == 200:
        add("critical", "elasticsearch: OPEN - HTTP 200 without authentication")
        try:
            j = json.loads(body)
            state["version"] = (j.get("version") or {}).get("number")
            facts["cluster_name"] = j.get("cluster_name")
        except Exception:
            pass
        c2, b2 = http_get(scheme, "/_cat/indices?format=json")
        if c2 == 200:
            try:
                idx = json.loads(b2)
                docs = 0
                for i in idx:
                    dc = str(i.get("docs.count", "") or "")
                    if dc.isdigit():
                        docs += int(dc)
                facts["index_count"] = len(idx)
                facts["doc_count"] = docs
                add("critical", "elasticsearch: %d indices / %d docs readable unauthenticated" % (len(idx), docs))
            except Exception:
                pass
    elif code in (401, 403):
        facts["auth"] = "required"
        add("info", "elasticsearch: authentication required (HTTP %d)" % code)
    else:
        facts["http_code"] = code
    if scheme == "http":
        add("medium", "elasticsearch: served over cleartext HTTP (no TLS)")
    eol_hint("elasticsearch", state["version"])


# --------------------------------------------------------------- PostgreSQL
def audit_pg():
    # 1) SSLRequest  (len=8, code=80877103)  -> 'S' TLS, 'N' no TLS
    try:
        s = connect()
        s.sendall(struct.pack("!II", 8, 80877103))
        b = s.recv(1)
        if b == b"S":
            state["tls"] = "available"
        elif b == b"N":
            state["tls"] = "unavailable"
            add("medium", "postgresql: server does not offer TLS (SSLRequest -> N)")
        s.close()
    except Exception as e:
        facts["ssl_probe_error"] = str(e)[:80]

    # 2) StartupMessage trust test (fresh plaintext socket)
    for user in ("postgres",):
        try:
            s = connect()
            params = ("user\x00%s\x00database\x00%s\x00\x00" % (user, user)).encode()
            msg = struct.pack("!I", 8 + len(params)) + struct.pack("!I", 196608) + params
            s.sendall(msg)
            hdr = s.recv(1)
            if hdr == b"R":
                struct.unpack("!I", recvall(s, 4))[0]
                code = struct.unpack("!I", recvall(s, 4))[0]
                if code == 0:
                    add("critical", "postgresql: TRUST auth - user %r accepted with NO password" % user)
                    facts["auth"] = "trust"
                elif code == 3:
                    add("medium", "postgresql: cleartext-password auth for %r" % user)
                    facts["auth"] = "password(cleartext)"
                elif code == 5:
                    add("low", "postgresql: MD5 password auth (deprecated) for %r" % user)
                    facts["auth"] = "md5"
                elif code == 10:
                    facts["auth"] = "scram-sha-256"
                else:
                    facts["auth"] = "R:%d" % code
            elif hdr == b"E":
                ln = struct.unpack("!I", recvall(s, 4))[0]
                e = recvall(s, max(0, min(ln - 4, 2048))).decode("utf-8", "replace")
                e = e.replace("\x00", " ").strip()
                facts["startup_error"] = e[:120]
                if "no encryption" in e.lower() or "SSL" in e:
                    add("info", "postgresql: server requires TLS for this host (good)")
            try:
                s.sendall(b"X\x00\x00\x00\x04")
                s.close()
            except Exception:
                pass
        except Exception as e:
            facts.setdefault("startup_error", str(e)[:80])
    if state["tls"] == "unavailable" and str(facts.get("auth", "")).startswith("password"):
        add("high", "postgresql: cleartext password auth AND no TLS offered")
    eol_hint("postgres", state["version"])


# ----------------------------------------------------------------- MongoDB
def bson_cstr(s):
    return s.encode() + b"\x00"


def bson_str(v):
    b = v.encode() + b"\x00"
    return struct.pack("<i", len(b)) + b


def bson_doc(pairs):
    body = b""
    for t, n, v in pairs:
        body += bytes([t]) + bson_cstr(n) + v
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def parse_bson(data, off=0):
    size = struct.unpack_from("<i", data, off)[0]
    end = off + size
    off += 4
    d = {}
    while off < end - 1:
        t = data[off]
        off += 1
        ns = data.index(b"\x00", off)
        name = data[off:ns].decode("utf-8", "replace")
        off = ns + 1
        if t == 0x01:
            val = struct.unpack_from("<d", data, off)[0]; off += 8
        elif t == 0x02:
            ln = struct.unpack_from("<i", data, off)[0]; off += 4
            val = data[off:off + ln - 1].decode("utf-8", "replace"); off += ln
        elif t == 0x03:
            val, off = parse_bson(data, off)
        elif t == 0x04:
            arr, off = parse_bson(data, off)
            val = [arr[k] for k in arr]
        elif t == 0x05:
            ln = struct.unpack_from("<i", data, off)[0]; off += 4 + 1 + ln
            val = "<binary>"
        elif t == 0x07:
            val = data[off:off + 12].hex(); off += 12
        elif t == 0x08:
            val = bool(data[off]); off += 1
        elif t == 0x09:
            val = struct.unpack_from("<q", data, off)[0]; off += 8
        elif t == 0x0A:
            val = None
        elif t == 0x10:
            val = struct.unpack_from("<i", data, off)[0]; off += 4
        elif t == 0x11 or t == 0x12:
            val = struct.unpack_from("<q", data, off)[0]; off += 8
        else:
            raise ValueError("unhandled bson type 0x%02x" % t)
        d[name] = val
    return d, off


def mongo_cmd(sock, doc_bytes):
    flags = struct.pack("<I", 0)
    payload = flags + b"\x00" + doc_bytes          # OP_MSG, section kind 0
    header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)
    sock.sendall(header + payload)
    hdr = recvall(sock, 16)
    if len(hdr) < 16:
        return None
    mlen = struct.unpack("<i", hdr[:4])[0]
    rest = recvall(sock, mlen - 16)
    if len(rest) < 6:
        return None
    try:
        doc, _ = parse_bson(rest[5:])             # skip flags(4)+kind(1)
        return doc
    except Exception:
        return None


def audit_mongo():
    try:
        s = connect()
    except Exception as e:
        facts["error"] = str(e)[:80]
        return
    # buildInfo first (note: can answer even WITH auth -> only used for version)
    try:
        r = mongo_cmd(s, bson_doc([(0x10, "buildInfo", struct.pack("<i", 1)),
                                   (0x02, "$db", bson_str("admin"))]))
        if r and r.get("version"):
            state["version"] = r.get("version")
            facts["buildinfo"] = "answered"
    except Exception as e:
        facts["buildinfo_error"] = str(e)[:80]
    # listDatabases = authoritative no-auth test
    try:
        r = mongo_cmd(s, bson_doc([(0x10, "listDatabases", struct.pack("<i", 1)),
                                   (0x02, "$db", bson_str("admin"))]))
        if r is None:
            facts["listdb"] = "no/å unparseable response"
        elif r.get("ok") == 1.0 and "databases" in r:
            dbs = r["databases"]
            facts["auth"] = "NONE"
            facts["db_count"] = len(dbs) if isinstance(dbs, list) else "?"
            add("critical", "mongodb: NO AUTHENTICATION - listDatabases returned the database list unauthenticated")
        else:
            msg = str(r.get("errmsg") or "")
            if r.get("code") == 13 or "auth" in msg.lower() or "not authorized" in msg.lower():
                facts["auth"] = "required"
                add("info", "mongodb: authentication required (%s)" % (msg[:60] or "Unauthorized"))
            else:
                facts["listdb_resp"] = (msg or str(r))[:100]
    except Exception as e:
        facts["listdb_error"] = str(e)[:80]
    try:
        s.close()
    except Exception:
        pass
    best_effort_tls()
    eol_hint("mongodb", state["version"])


# ------------------------------------------------------------- MySQL/MariaDB
def read_packet(sock):
    h = recvall(sock, 4)
    if len(h) < 4:
        return None
    plen = h[0] | (h[1] << 8) | (h[2] << 16)
    return recvall(sock, plen)


def audit_mysql(service):
    try:
        s = connect()
    except Exception as e:
        facts["error"] = str(e)[:80]
        return
    payload = read_packet(s)
    try:
        s.close()
    except Exception:
        pass
    if not payload or len(payload) < 5:
        facts["error"] = "no/short handshake"
        return
    off = 0
    proto = payload[off]; off += 1
    if proto == 0xFF:
        txt = payload[3:].decode("latin1", "replace")
        facts["handshake"] = "error packet: %s" % txt[:80]
        m = re.search(r"\d+\.\d+\.\d+", txt)
        if m:
            state["version"] = m.group(0)
        eol_hint(service, state["version"])
        return
    end = payload.index(b"\x00", off)
    state["version"] = payload[off:end].decode("latin1", "replace")
    off = end + 1
    off += 4          # thread id
    off += 8          # auth-plugin-data-part-1
    off += 1          # filler
    caps = 0
    if off + 2 <= len(payload):
        caps = payload[off] | (payload[off + 1] << 8)
        off += 2
    if off + 5 <= len(payload):
        off += 1      # charset
        off += 2      # status
        caps |= (payload[off] | (payload[off + 1] << 8)) << 16
        off += 2
    facts["capabilities"] = "0x%08x" % caps
    if caps & 0x00000800:                       # CLIENT_SSL
        state["tls"] = "available"
    else:
        state["tls"] = "unavailable"
        add("medium", "%s: server does not advertise TLS (no CLIENT_SSL capability)" % service)
    low = payload.decode("latin1", "replace").lower()
    if "mysql_old_password" in low:
        add("medium", "%s: legacy pre-4.1 password hashing offered (mysql_old_password)" % service)
    facts["server_version"] = state["version"]
    eol_hint(service, state["version"])


# ------------------------------------------------------------------- MSSQL
def audit_mssql():
    # UDP 1434 SQL Server Browser (information disclosure)
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(min(TMO, 3))
        u.sendto(b"\x02", (HOST, 1434))
        d, _ = u.recvfrom(4096)
        u.close()
        if d and d[0] == 0x05:
            text = d[3:].decode("latin1", "replace")
            facts["browser"] = text[:200]
            add("low", "mssql: SQL Server Browser (UDP 1434) exposed - leaks instance/version")
            m = re.search(r"Version;([0-9.]+)", text)
            if m:
                state["version"] = m.group(1)
    except Exception:
        pass
    # TCP PRELOGIN -> ENCRYPTION + VERSION tokens
    try:
        s = connect()
        tokens = [(0, 6), (1, 1), (2, 1), (3, 4)]
        hdrlen = len(tokens) * 5 + 1
        tbl = b""
        dat = b""
        offset = hdrlen
        vals = {0: b"\x00" * 6, 1: b"\x00", 2: b"\x00", 3: b"\x00" * 4}
        for tk, ln in tokens:
            tbl += bytes([tk]) + struct.pack("!H", offset) + struct.pack("!H", ln)
            offset += ln
            dat += vals[tk]
        tbl += b"\xff"
        prelogin = tbl + dat
        pkt = struct.pack("!BBHHBB", 0x12, 0x01, 8 + len(prelogin), 0, 1, 0) + prelogin
        s.sendall(pkt)
        head = recvall(s, 4)
        if head and len(head) >= 4:
            rlen = struct.unpack("!H", head[2:4])[0]
            rest = recvall(s, max(0, rlen - 4))
            i = 0
            enc = None
            ver = None
            while i < len(rest) and rest[i] != 0xFF and i + 5 <= len(rest):
                tk = rest[i]
                po = struct.unpack("!H", rest[i + 1:i + 3])[0]
                pl = struct.unpack("!H", rest[i + 3:i + 5])[0]
                i += 5
                seg = rest[po:po + pl]
                if tk == 1 and pl >= 1:
                    enc = seg[0]
                if tk == 0 and pl >= 4:
                    ver = "%d.%d.%d" % (seg[0], seg[1], (seg[2] << 8) | seg[3])
            if ver:
                state["version"] = ver
            if enc is not None:
                facts["encryption_token"] = enc
                if enc == 0x02:
                    state["tls"] = "unavailable"
                    add("medium", "mssql: TLS not supported (PRELOGIN ENCRYPT_NOT_SUP)")
                elif enc == 0x00:
                    state["tls"] = "available (off by default)"
                elif enc == 0x01:
                    state["tls"] = "available"
                elif enc == 0x03:
                    state["tls"] = "required"
        s.close()
    except Exception as e:
        facts["prelogin_error"] = str(e)[:80]
    facts["sa_empty_test"] = "run nmap ms-sql-empty-password / sqlcmd for sa blank-password"
    eol_hint("mssql", state["version"])


# ------------------------------------------------------------------- dispatch
try:
    if DB in ("mysql", "mariadb"):
        audit_mysql(DB)
    elif DB == "mssql":
        audit_mssql()
    elif DB == "postgres":
        audit_pg()
    elif DB == "mongodb":
        audit_mongo()
    elif DB == "redis":
        audit_redis()
    elif DB == "elasticsearch":
        audit_es()
    else:
        print(json.dumps({"tool": "db-audit", "host": HOST, "port": PORT,
                          "problems": ["[CRITICAL] unknown engine %r" % DB]}))
        sys.exit(0)
except Exception as e:
    facts["fatal"] = str(e)[:120]

if NMAP_NOTE:
    facts["nmap"] = NMAP_NOTE[:300]
if NMAP_FINDING:
    add("critical", "%s: %s" % (DB, NMAP_FINDING))

if not state["reachable"]:
    problems = ["[INFO] %s: no response (host down, filtered, or not this service)" % DB]
    sevmax = "info"

finding = SEV.index(sevmax) >= SEV.index("low")
out = {
    "tool": "db-audit",
    "host": HOST,
    "port": PORT,
    "service": DB,
    "reachable": state["reachable"],
    "version": state["version"],
    "tls": state["tls"],
    "severity_max": sevmax,
    "finding": finding,
    "facts": facts,
    "problems": problems,
}
print(json.dumps(out))
PYBACKEND
}

# render one engine JSON blob as human text; also prints a FINDING\t<0|1> line
render_text() {
    RJSON="$1" python3 - <<'PYR'
import os, json
d = json.loads(os.environ["RJSON"])
print("FINDING\t%s" % ("1" if d.get("finding") else "0"))
print("VER\t%s" % (d.get("version") or "?"))
print("TLS\t%s" % (d.get("tls") or "?"))
f = d.get("facts") or {}
order = ["auth", "cluster_name", "index_count", "doc_count", "db_count",
         "server_version", "capabilities", "encryption_token", "browser",
         "config_requirepass", "config_protected-mode", "config_bind",
         "config_dir", "os", "startup_error", "nmap"]
for k in order:
    v = f.get(k)
    if v not in (None, ""):
        print("FACT\t%s = %s" % (k, v))
for p in d.get("problems") or []:
    print("PROB\t%s" % p)
if not (d.get("problems")):
    print("OK\tno issues detected")
PYR
}

# ----------------------------------------------------------- resolve a target --
# sets REPLY_HOST REPLY_PORT REPLY_TYPE ; returns 1 on resolve error
resolve_target() {
    local raw="$1" scheme="" hostport host port dbtype
    if [[ "$raw" == *"://"* ]]; then
        scheme="${raw%%://*}"
        hostport="${raw#*://}"
    else
        hostport="$raw"
    fi
    hostport="${hostport%/}"
    if [[ "$hostport" == *:* ]]; then
        host="${hostport%%:*}"
        port="${hostport##*:}"
    else
        host="$hostport"
        port=""
    fi

    # engine: scheme > --type > port map > nmap -sV guess
    if [[ -n "$scheme" ]]; then
        dbtype="$(norm_type "$scheme")"
    elif [[ -n "$FORCE_TYPE" ]]; then
        dbtype="$(norm_type "$FORCE_TYPE")"
    else
        dbtype=""
    fi
    [[ -z "$port" && -n "$PORT_OVERRIDE" ]] && port="$PORT_OVERRIDE"
    if [[ -z "$dbtype" && -n "$port" ]]; then
        dbtype="$(type_from_port "$port")"
    fi
    if [[ -z "$dbtype" && -n "$port" ]] && have nmap && [[ $NO_NMAP -eq 0 ]]; then
        local svc
        svc="$(nmap -Pn -n -p "$port" -sV "$host" 2>/dev/null | grep -iE "^${port}/tcp" | head -1)"
        case "$svc" in
            *mysql*)   dbtype=mysql ;;
            *ms-sql*|*mssql*) dbtype=mssql ;;
            *postgres*) dbtype=postgres ;;
            *mongod*)  dbtype=mongodb ;;
            *redis*)   dbtype=redis ;;
            *elasticsearch*|*http*) dbtype=elasticsearch ;;
        esac
    fi
    [[ -z "$dbtype" ]] && { err "cannot determine engine for '$raw' (use --type or a scheme)"; return 1; }
    [[ -z "$port" ]] && port="$(default_port "$dbtype")"
    [[ -z "$port" ]] && { err "no port for '$raw'"; return 1; }

    REPLY_HOST="$host"; REPLY_PORT="$port"; REPLY_TYPE="$dbtype"
    return 0
}

# ---------------------------------------------------------------------- main --
# Authorized-use banner to stderr (never pollutes stdout / --json).
printf '%s[db-audit]%s authorized / lab use only — read-only unless --allow-destructive\n' \
    "${C_DIM}" "${C_RST}" >&2

[[ ${JSON} -eq 0 ]] && info "db-audit — ${#TARGETS[@]} target(s), timeout ${TIMEOUT}s$( [[ $ALLOW_DESTRUCTIVE -eq 1 ]] && echo ' [DESTRUCTIVE PROBES ON]' )"

REPLY_HOST=""; REPLY_PORT=""; REPLY_TYPE=""
for raw in "${TARGETS[@]}"; do
    if ! resolve_target "$raw"; then
        [[ ${JSON} -eq 1 ]] && printf '{"tool":"db-audit","host":"%s","reachable":false,"problems":["could not identify DB engine/port (use --type or a scheme)"]}\n' "${raw//\"/}"
        EXIT_CODE=1; continue
    fi
    host="$REPLY_HOST"; port="$REPLY_PORT"; dbtype="$REPLY_TYPE"

    nnote=""; nfind=""
    if have nmap && [[ $NO_NMAP -eq 0 ]]; then
        { IFS= read -r nnote; IFS= read -r nfind; } < <(run_nmap "$host" "$port" "$dbtype")
    fi

    json="$(run_engine "$host" "$port" "$dbtype" "$nnote" "$nfind")"
    if [[ -z "$json" ]]; then
        err "engine produced no output for ${host}:${port}"
        [[ ${JSON} -eq 1 ]] && printf '{"tool":"db-audit","host":"%s","port":"%s","reachable":false,"problems":["engine produced no output"]}\n' "${host//\"/}" "${port//\"/}"
        EXIT_CODE=1; continue
    fi

    if [[ ${JSON} -eq 1 ]]; then
        printf '%s\n' "$json"
        printf '%s' "$json" | grep -q '"finding": *true' && EXIT_CODE=1
        continue
    fi

    rtext="$(render_text "$json")"
    section "${host}:${port}  ${C_DIM}(${dbtype})${C_RST}"
    printf '%s\n' "$rtext" | grep -q '^FINDING'$'\t''1' && EXIT_CODE=1
    while IFS=$'\t' read -r kind rest; do
        case "$kind" in
            VER)  field "Version" "$rest" ;;
            TLS)  field "TLS" "$rest" ;;
            FACT) field "·" "$rest" ;;
            PROB)
                case "$rest" in
                    "[CRITICAL]"*|"[HIGH]"*) err  "$rest" ;;
                    "[MEDIUM]"*|"[LOW]"*)    warn "$rest" ;;
                    *)                       info "$rest" ;;
                esac ;;
            OK)   ok "$rest" ;;
        esac
    done < <(printf '%s\n' "$rtext" | grep -v '^FINDING'$'\t')
done

exit "${EXIT_CODE}"
