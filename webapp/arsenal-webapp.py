#!/usr/bin/env python3
"""arsenal-webapp.py — a tiny local console (micro web GUI) for the Arsenal toolkit.

A small indie app: python3 stdlib only, binds to 127.0.0.1, runs the arsenal
analysers against a target you enter, collects their JSON findings, and can build
a report or export an engagement bundle to Mimir and Crucible.

Safety: localhost-only; targets are validated; tools run via argv subprocess
(never a shell); only a curated allowlist of tools + boolean flags can run (no
free-form arguments). Authorized-use only — scan what you own or may test.

  python3 webapp/arsenal-webapp.py            # http://127.0.0.1:8733
  ARSENAL_MIMIR_URL=http://host/ingest ARSENAL_CRUCIBLE_URL=... python3 webapp/arsenal-webapp.py
"""
import json, os, re, subprocess, sys, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARSENAL = os.path.join(ROOT, "bin", "arsenal")
EXCHANGE = os.path.join(ROOT, "webapp", "exchange")
HOST, PORT = "127.0.0.1", int(os.environ.get("ARSENAL_WEBAPP_PORT", "8733"))
MIMIR_URL = os.environ.get("ARSENAL_MIMIR_URL", "")
CRUCIBLE_URL = os.environ.get("ARSENAL_CRUCIBLE_URL", "")

# tool -> (how many positional target args, {gui_option: safe_flag})
TOOLS = {
    "ssl":          (1, {"vuln": "--vuln"}),
    "ssh":          (1, {}),
    "dns":          (1, {"brute": "--brute", "passive": "--passive"}),
    "http":         (1, {"methods": "--methods"}),
    "smb":          (1, {"vuln": "--vuln"}),
    "ldap":         (1, {}),
    "smtp":         (1, {}),
    "snmp":         (1, {}),
    "ftp":          (1, {}),
    "db":           (1, {}),
    "webscan-lite": (1, {}),
    "webscan-heavy":(1, {"active": "--active", "no-brute": "--no-brute"}),
    "vulndb":       (2, {}),   # target = "product version"
}
# reject anything with a shell metachar / control char — argv already prevents
# shell injection, this just keeps inputs to a sane host/url/product shape.
BAD = re.compile(r"""[;|&`$<>\\'"\n\r\t]""")
FINDINGS = []   # in-memory session of result objects


def valid_target(tool, target):
    target = (target or "").strip()
    if not target or len(target) > 200 or BAD.search(target):
        return None
    if tool != "vulndb" and " " in target:
        return None
    return target


def run_tool(tool, target, opts):
    spec = TOOLS.get(tool)
    if not spec:
        return {"error": "unknown tool"}
    npos, flagmap = spec
    target = valid_target(tool, target)
    if not target:
        return {"error": "invalid target"}
    argv = ["bash", ARSENAL, tool]
    for key, on in (opts or {}).items():
        if on and key in flagmap:
            argv.append(flagmap[key])
    argv.append("--json")
    argv += target.split(" ", 1) if npos == 2 else [target]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=180, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return {"error": "tool timed out"}
    except Exception as e:
        return {"error": str(e)[:200]}
    objs = []
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try: objs.append(json.loads(line))
            except Exception: pass
    if not objs:
        return {"error": "no JSON output", "stderr": (p.stderr or "")[:300]}
    for o in objs:
        FINDINGS.append(o)
    return {"ok": True, "results": objs}


def build_report(fmt="md"):
    rep = os.path.join(ROOT, "lib", "report.sh")
    data = "\n".join(json.dumps(o) for o in FINDINGS)
    try:
        p = subprocess.run(["bash", rep, "--format", fmt], input=data, text=True,
                           capture_output=True, timeout=60, cwd=ROOT)
        return p.stdout
    except Exception as e:
        return "report error: %s" % e


def export_bundle():
    os.makedirs(EXCHANGE, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    findings_path = os.path.join(EXCHANGE, "findings.jsonl")
    with open(findings_path, "w", encoding="utf-8", newline="\n") as f:
        for o in FINDINGS:
            f.write(json.dumps(o) + "\n")
    # build the red-ribbon graph from the findings (+ vuln DB if present)
    gout = os.path.join(EXCHANGE, "graph")
    gb = os.path.join(ROOT, "graph", "graph-build.sh")
    try:
        subprocess.run(["bash", gb, "--out", gout], input="\n".join(json.dumps(o) for o in FINDINGS),
                       text=True, capture_output=True, timeout=120, cwd=ROOT)
    except Exception:
        pass
    manifest = {"schema": "arsenal-exchange/1.0", "generated": ts,
                "findings": len(FINDINGS), "files": {"findings": "findings.jsonl", "graph": "graph/graph.json"},
                "consumers": {"mimir": "ingest findings.jsonl + graph.json", "crucible": "infra-recon layer"}}
    with open(os.path.join(EXCHANGE, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
    pushed = {}
    for name, url in (("mimir", MIMIR_URL), ("crucible", CRUCIBLE_URL)):
        if not url:
            pushed[name] = "not configured (set ARSENAL_%s_URL)" % name.upper()
            continue
        try:
            body = json.dumps({"manifest": manifest, "findings": FINDINGS}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                pushed[name] = "HTTP %s" % r.status
        except Exception as e:
            pushed[name] = "push failed: %s" % str(e)[:120]
    return {"ok": True, "exchange": EXCHANGE, "manifest": manifest, "pushed": pushed}


PAGE = """<!doctype html><html><head><meta charset=utf-8><title>Arsenal Console</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1017;--fg:#c9d1d9;--mut:#8b949e;--acc:#d9a441;--red:#ff6b6b;--grn:#3fd07d;--card:#161b22;--br:#222a35}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
header{padding:14px 18px;border-bottom:1px solid var(--br);display:flex;gap:10px;align-items:baseline}
h1{font-size:17px;margin:0;color:var(--acc)}.sub{color:var(--mut);font-size:12px}
.wrap{max-width:980px;margin:0 auto;padding:18px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
select,input,button{background:var(--card);color:var(--fg);border:1px solid var(--br);border-radius:6px;padding:8px 10px;font:inherit}
input{flex:1;min-width:220px}button{cursor:pointer;color:var(--acc);border-color:var(--acc)}
button.sec{color:var(--fg);border-color:var(--br)}
.opts label{margin-right:12px;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--br);border-radius:8px;padding:10px 12px;margin:10px 0}
.card h3{margin:0 0 6px;font-size:13px;color:var(--acc)}
.p{color:var(--red)}.ok{color:var(--grn)}.mut{color:var(--mut)}
.banner{color:var(--acc);background:#1c1206;border:1px solid #3a2a0a;border-radius:6px;padding:8px 10px;font-size:12px;margin:10px 0}
pre{white-space:pre-wrap;word-break:break-word;margin:6px 0 0;color:var(--mut);font-size:12px}
</style></head><body>
<header><h1>⚒ Arsenal Console</h1><span class=sub>protégé of Mimir &amp; Crucible · local recon console</span></header>
<div class=wrap>
<div class=banner>⚠ Authorized use only. Runs on 127.0.0.1. Scan only systems you own or are written-authorized to test.</div>
<div class=row>
  <select id=tool></select>
  <input id=target placeholder="example.com  |  https://app/  |  (vulndb: openssh 9.2)">
  <button onclick=run()>Run</button>
</div>
<div class="row opts" id=opts></div>
<div class=row>
  <button class=sec onclick=report()>Build report</button>
  <button class=sec onclick=exp()>Export → Mimir &amp; Crucible</button>
  <span class=mut id=count>0 findings</span>
</div>
<div id=out></div>
</div>
<script>
const TOOLS=__TOOLS__;
const tsel=document.getElementById('tool'),opts=document.getElementById('opts'),out=document.getElementById('out');
for(const t in TOOLS){const o=document.createElement('option');o.value=t;o.textContent=t;tsel.appendChild(o);}
function drawOpts(){opts.innerHTML='';const f=TOOLS[tsel.value]||[];for(const k of f){const id='opt_'+k;opts.insertAdjacentHTML('beforeend',`<label><input type=checkbox id=${id}> ${k}</label>`);}}
tsel.onchange=drawOpts;drawOpts();
function card(h,html,cls){const d=document.createElement('div');d.className='card';d.innerHTML=`<h3 class='${cls||""}'>${h}</h3>${html}`;out.prepend(d);}
async function run(){const tool=tsel.value,target=document.getElementById('target').value;
 const o={};for(const k of (TOOLS[tool]||[])){o[k]=document.getElementById('opt_'+k).checked;}
 card(tool+' '+target,'<span class=mut>running…</span>');
 const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,target,opts:o})});
 const j=await r.json();out.firstChild.remove();
 if(j.error){card(tool+' '+target,'<span class=p>error: '+j.error+'</span>'+(j.stderr?'<pre>'+j.stderr+'</pre>':''));return;}
 for(const res of j.results){const probs=(res.problems||[]);
  const body=(probs.length?probs.map(p=>'<div class=p>• '+p+'</div>').join(''):'<div class=ok>no issues</div>')+'<pre>'+JSON.stringify(res).slice(0,600)+'</pre>';
  card((res.tool||tool)+' — '+(res.host||res.url||target),body);}
 count();}
async function report(){const r=await fetch('/api/report?format=md');const t=await r.text();card('Report (markdown)','<pre>'+t.replace(/</g,'&lt;')+'</pre>');}
async function exp(){const r=await fetch('/api/export',{method:'POST'});const j=await r.json();
 card('Export','<div class=ok>wrote '+j.manifest.findings+' findings to exchange/</div><pre>'+JSON.stringify(j.pushed,null,1)+'</pre>');}
async function count(){const r=await fetch('/api/findings');const j=await r.json();document.getElementById('count').textContent=j.length+' findings';}
count();
</script></body></html>"""


class App(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _json(self, obj, code=200): self._send(code, json.dumps(obj))

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE.replace("__TOOLS__", json.dumps({k: list(v[1].keys()) for k, v in TOOLS.items()})), "text/html; charset=utf-8")
        elif self.path == "/api/tools":
            self._json({k: list(v[1].keys()) for k, v in TOOLS.items()})
        elif self.path == "/api/findings":
            self._json(FINDINGS)
        elif self.path.startswith("/api/report"):
            fmt = "md"
            if "format=" in self.path: fmt = self.path.split("format=", 1)[1].split("&")[0]
            if fmt not in ("md", "csv", "txt", "json"): fmt = "md"
            self._send(200, build_report(fmt), "text/plain; charset=utf-8")
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(n) if n else b"{}"
        try: req = json.loads(raw or b"{}")
        except Exception: req = {}
        if self.path == "/api/scan":
            self._json(run_tool(req.get("tool", ""), req.get("target", ""), req.get("opts", {})))
        elif self.path == "/api/export":
            self._json(export_bundle())
        else:
            self._json({"error": "not found"}, 404)


def main():
    sys.stderr.write("⚒ Arsenal Console (protégé of Mimir & Crucible) on http://%s:%d\n" % (HOST, PORT))
    sys.stderr.write("   authorized use only · localhost only · Ctrl-C to stop\n")
    sys.stderr.write("   Mimir=%s  Crucible=%s\n" % (MIMIR_URL or "(unset)", CRUCIBLE_URL or "(unset)"))
    ThreadingHTTPServer((HOST, PORT), App).serve_forever()


if __name__ == "__main__":
    main()
