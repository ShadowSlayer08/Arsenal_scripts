#!/usr/bin/env bash
#
# webscan-heavy.sh — deep web-app scan: crawl + discovery + safe indicators
# =============================================================================
#   A thorough, still-read-only-by-default web-app scan: same-origin crawl,
#   content/path discovery, form + parameter + JS-endpoint extraction, security
#   headers / CORS / methods, and (opt-in) SAFE, detection-only injection
#   indicators — reflected-marker XSS and SQL-error-signature probes that send
#   BENIGN markers only and never execute or weaponize anything.
#
#   Heavier than webscan-lite (many requests). Honor your rules of engagement;
#   only scan apps you own or are explicitly authorized to test. Use --scope to
#   gate the target through engage/scope-guard.sh first.
# =============================================================================
#
#   Requires: curl? no — python3 (stdlib). Optional: nuclei (extra templates).
#
#   Quick start:
#     ./webscan-heavy.sh https://app.example.com
#     ./webscan-heavy.sh --depth 3 --max-pages 120 https://app.example.com
#     ./webscan-heavy.sh --no-brute https://app.example.com         # crawl only, no path discovery
#     ./webscan-heavy.sh --active https://app.example.com           # + safe injection indicators
#     ./webscan-heavy.sh --json https://app.example.com
#
set -uo pipefail

DEPTH=2
MAXPAGES=60
WORDLIST=""
DO_BRUTE=1
DO_ACTIVE=0
TIMEOUT=10
JSON=0
SCOPE=""
TARGETS=()
EXIT_CODE=0

if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'
    C_B=$'\e[34m'; C_C=$'\e[36m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_BOLD=""; C_DIM=""
fi
info()    { printf '%s[*]%s %s\n'  "${C_B}" "${C_RST}" "$*" >&2; }
ok()      { printf '%s[+]%s %s\n'  "${C_G}" "${C_RST}" "$*"; }
warn()    { printf '%s[!]%s %s\n'  "${C_Y}" "${C_RST}" "$*"; }
err()     { printf '%s[x]%s %s\n'  "${C_R}" "${C_RST}" "$*" >&2; }
field()   { printf '    %s%-18s%s %s\n' "${C_DIM}" "$1" "${C_RST}" "$2"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; }
have()    { command -v "$1" >/dev/null 2>&1; }

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)      DEPTH="${2:?}"; shift 2 ;;
        --max-pages)  MAXPAGES="${2:?}"; shift 2 ;;
        -w|--wordlist) WORDLIST="${2:?}"; shift 2 ;;
        --no-brute)   DO_BRUTE=0; shift ;;
        --active)     DO_ACTIVE=1; shift ;;
        --scope)      SCOPE="${2:?}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           err "unknown option: $1"; usage; exit 2 ;;
        *)            TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && { err "no target URL given"; usage; exit 2; }
have python3 || { err "python3 is required"; exit 2; }
[[ ${JSON} -eq 0 ]] && info "webscan-heavy — depth ${DEPTH}, max ${MAXPAGES} pages, brute=${DO_BRUTE}, active=${DO_ACTIVE}"

# optional scope-guard gate
scope_ok() {
    local t="$1"
    [[ -z "$SCOPE" ]] && return 0
    local sg; sg="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/engage/scope-guard.sh"
    [[ -x "$sg" ]] || { warn "scope-guard not found; proceeding"; return 0; }
    bash "$sg" --scope "$SCOPE" --quiet check "$t" >/dev/null 2>&1
}

read -r -d '' ENGINE <<'PYEOF' || true
import sys, os, re, json, html, time
import urllib.request, urllib.parse, urllib.error

TARGET=os.environ["TARGET"]; DEPTH=int(os.environ["DEPTH"]); MAXPAGES=int(os.environ["MAXPAGES"])
TIMEOUT=float(os.environ["TIMEOUT"]); DO_BRUTE=os.environ["DO_BRUTE"]=="1"; DO_ACTIVE=os.environ["DO_ACTIVE"]=="1"
WORDLIST=os.environ.get("WORDLIST",""); UA="arsenal-webscan-heavy/1.0"

if not re.match(r"^https?://", TARGET): TARGET="https://"+TARGET
base=urllib.parse.urlparse(TARGET); origin=base.scheme+"://"+base.netloc
problems=[]; pages=[]; forms=[]; endpoints=set(); params=set(); discovered=[]; js_files=set()
SQL_ERR=re.compile(r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|ODBC SQL|Unclosed quotation|syntax error at or near", re.I)
WORDS=["admin","login","administrator","api","api/v1","api/v2","config","config.php","backup","backup.zip",
       ".git/HEAD",".env",".svn/entries","wp-admin","wp-login.php","phpmyadmin","server-status","actuator",
       "actuator/health","swagger","swagger-ui.html","openapi.json","robots.txt","sitemap.xml","test","dev",
       "staging","old","tmp","uploads","console","debug","status",".DS_Store","web.config","dump.sql"]

def fetch(url, method="GET"):
    try:
        req=urllib.request.Request(url, method=method, headers={"User-Agent":UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body=r.read(1500000).decode("utf-8","replace")
            return r.status, dict(r.headers), body, r.geturl()
    except urllib.error.HTTPError as e:
        try: body=e.read(200000).decode("utf-8","replace")
        except Exception: body=""
        return e.code, dict(e.headers or {}), body, url
    except Exception:
        return 0, {}, "", url

def same_origin(u):
    p=urllib.parse.urlparse(u); return (p.scheme in ("http","https")) and p.netloc==base.netloc

def extract(url, body):
    for m in re.findall(r"""(?:href|src|action)=["']([^"'#]+)""", body, re.I):
        ab=urllib.parse.urljoin(url, m)
        if m.lower().endswith(".js"): js_files.add(ab)
        p=urllib.parse.urlparse(ab)
        if p.query:
            endpoints.add(p.scheme+"://"+p.netloc+p.path+"?"+p.query)
            for k,_ in urllib.parse.parse_qsl(p.query): params.add(k)
        yield ab
    for m in re.findall(r"""fetch\(["']([^"']+)|["'](/api/[^"'\s]+)""", body):
        u="".join(m)
        if u: endpoints.add(urllib.parse.urljoin(url,u))
    for f in re.findall(r"<form\b[^>]*>", body, re.I):
        act=re.search(r"""action=["']([^"']*)""", f, re.I); meth=re.search(r"""method=["']?(\w+)""", f, re.I)
        forms.append({"action":urllib.parse.urljoin(url, act.group(1) if act else url),
                      "method":(meth.group(1).upper() if meth else "GET")})

# ---- crawl (BFS, bounded) ----
seen=set([TARGET]); queue=[(TARGET,0)]; n=0
while queue and n<MAXPAGES:
    url,d=queue.pop(0)
    st,hd,body,final=fetch(url)
    if st==0: continue
    n+=1; pages.append({"url":url,"status":st})
    if d<DEPTH and "text/html" in hd.get("Content-Type",""):
        for link in extract(url, body):
            if same_origin(link) and link not in seen and len(seen)<MAXPAGES*3:
                seen.add(link); queue.append((link, d+1))
# fetch JS to mine more endpoints
for j in list(js_files)[:20]:
    _,_,jb,_=fetch(j)
    for m in re.findall(r"""["'](/[A-Za-z0-9_\-/]+(?:\?[^"']*)?)["']""", jb):
        if "/" in m and len(m)>3: endpoints.add(urllib.parse.urljoin(origin,m))

# ---- seed-page security posture ----
st,hd,body,_=fetch(TARGET)
H={k.lower():v for k,v in hd.items()}
if base.scheme=="https" and "strict-transport-security" not in H: problems.append("missing HSTS")
if "content-security-policy" not in H: problems.append("missing Content-Security-Policy")
if "x-content-type-options" not in H: problems.append("missing X-Content-Type-Options")
if "x-frame-options" not in H and "frame-ancestors" not in H.get("content-security-policy",""): problems.append("clickjacking: no X-Frame-Options/frame-ancestors")
if H.get("server","") and re.search(r"\d+\.\d+", H.get("server","")): problems.append("version disclosure in Server: "+H["server"])
# CORS
_,ch,_,_=fetch(TARGET)
cs,chd,_,_=0,{},"",""
try:
    req=urllib.request.Request(TARGET, headers={"User-Agent":UA,"Origin":"https://evil.arsenal-audit.example"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r: chd={k.lower():v for k,v in r.headers.items()}
except Exception: chd={}
if "evil.arsenal-audit.example" in chd.get("access-control-allow-origin",""):
    problems.append("CORS reflects arbitrary Origin"+(" + credentials" if chd.get("access-control-allow-credentials","").lower()=="true" else ""))

# ---- content discovery ----
if DO_BRUTE:
    words=WORDS
    if WORDLIST and os.path.exists(WORDLIST):
        words=[w.strip() for w in open(WORDLIST,encoding="utf-8",errors="replace") if w.strip() and not w.startswith("#")]
    bogus,_,_,_=fetch(origin+"/arsenal_nonexistent_9f3a2b")
    soft404 = bogus in (200,206)
    if soft404:
        problems.append("content discovery skipped: soft-404 (site returns 200 for missing paths)")
    else:
        for w in words:
            code,_,_,_=fetch(origin+"/"+w)
            if code in (200,206,401,403):
                discovered.append({"path":"/"+w,"code":code})
        hot=[d["path"] for d in discovered if d["code"]==200 and re.search(r"\.git|\.env|\.svn|backup|dump\.sql|web\.config|\.DS_Store", d["path"])]
        if hot: problems.append("exposed sensitive paths: "+", ".join(hot))

# ---- safe, opt-in injection INDICATORS (benign markers only) ----
xss=[]; sqli=[]
if DO_ACTIVE:
    targets=list(endpoints)[:40]
    marker="arsxss"+str(len(endpoints)%9973)+"zz"
    for u in targets:
        p=urllib.parse.urlparse(u); qs=urllib.parse.parse_qsl(p.query)
        if not qs: continue
        # reflected-marker XSS indicator: inject a harmless token, check it comes back unencoded
        for i in range(len(qs)):
            q2=list(qs); q2[i]=(qs[i][0], marker+"<arstest>")
            tu=p._replace(query=urllib.parse.urlencode(q2)).geturl()
            _,_,rb,_=fetch(tu)
            if marker+"<arstest>" in rb: xss.append({"url":u,"param":qs[i][0]}); break
        # SQL-error indicator: a single quote, look for a DB error signature
        for i in range(len(qs)):
            q2=list(qs); q2[i]=(qs[i][0], qs[i][1]+"'")
            tu=p._replace(query=urllib.parse.urlencode(q2)).geturl()
            _,_,rb,_=fetch(tu)
            if SQL_ERR.search(rb): sqli.append({"url":u,"param":qs[i][0]}); break
    if xss: problems.append("reflected-XSS indicator: %d endpoint(s) reflect an unencoded marker (verify manually)"%len(xss))
    if sqli: problems.append("SQL-error indicator: %d endpoint(s) return a DB error on a quote (possible SQLi; verify)"%len(sqli))

out={"tool":"webscan-heavy","host":base.netloc,"url":TARGET,"reachable":n>0,
     "pages_crawled":n,"forms":len(forms),"endpoints":len(endpoints),"params":sorted(params)[:50],
     "discovered":discovered,"js_files":len(js_files),
     "xss_indicators":xss,"sqli_indicators":sqli,"problems":problems}
print(json.dumps(out))
PYEOF

render() { python3 -c '
import sys,json
o=json.loads(sys.stdin.read())
def f(k,v): print("    %-18s %s"%(k,v))
print("\n== %s =="%o["url"])
f("Reachable",o["reachable"]); f("Pages crawled",o["pages_crawled"]); f("Forms",o["forms"])
f("Endpoints",o["endpoints"]); f("JS files",o["js_files"])
if o.get("discovered"): f("Discovered",", ".join("%s(%s)"%(d["path"],d["code"]) for d in o["discovered"][:12]))
if o.get("params"): f("Params",", ".join(o["params"][:15]))
probs=o.get("problems",[])
if not probs: print("[+] no issues detected")
else:
    for p in probs: print("[!] "+p)
'; }

for t in "${TARGETS[@]}"; do
    if ! scope_ok "$t"; then err "out of scope (per $SCOPE): $t — skipping"; EXIT_CODE=2; continue; fi
    out="$(TARGET="$t" DEPTH="$DEPTH" MAXPAGES="$MAXPAGES" TIMEOUT="$TIMEOUT" DO_BRUTE="$DO_BRUTE" \
           DO_ACTIVE="$DO_ACTIVE" WORDLIST="$WORDLIST" python3 -c "$ENGINE" 2>/dev/null)"
    [[ -z "$out" ]] && { err "scan failed for $t"; continue; }
    if [[ ${JSON} -eq 1 ]]; then printf '%s\n' "$out"; else printf '%s' "$out" | render; fi
    printf '%s' "$out" | grep -q '"problems":\[\]' || EXIT_CODE=1
done
exit "${EXIT_CODE}"
