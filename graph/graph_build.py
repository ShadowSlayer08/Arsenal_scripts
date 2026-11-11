#!/usr/bin/env python3
"""graph_build.py — weave analyser --json (+ the vuln DB) into a knowledge graph.

The "red ribbon": every tool's JSON finding becomes a node, tied to the Service
it was seen on, the Protocol that service speaks, and — through CVE references —
to the public Exploits and CWEs in the shared vuln DB. The output is ingestible
by graphify, Mimir, and Crucible.

Emits (into --out dir):
  nodes.jsonl   one node per line  {id,type,label,props,source,confidence}
  edges.jsonl   one edge per line  {id,source,target,relation,props,confidence}
  graph.json    {schema,generated,nodes:[...],edges:[...],hyperedges:[]}  (graphify input)
  manifest.json counts + producers
Optionally bloodhound.json (--format bloodhound).

Input: analyser JSON objects (one per line) on stdin or from files — ssl/ssh/
dns/http/smb/ldap/kerberos/smtp/snmp/ftp/db audits and vulndb/cve-lookup.

  { ssl-audit --json ...; vulndb-lookup --json ...; } | graph_build.py --out ./graph-out
  graph_build.py --out ./g --vulndb vulndb.sqlite results.jsonl   # enrich CVEs from the DB

stdlib only; opens the vuln DB read-only.
"""
import argparse, json, os, re, sqlite3, sys, time

SCHEMA = "arsenal-redribbon/1.0"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# tool -> (protocol, l4). db/vulndb/cve are special-cased.
TOOL_PROTO = {
    "ssl-audit": ("tls", "tcp"), "ssh-audit": ("ssh", "tcp"),
    "dns-audit": ("dns", "udp"), "http-audit": ("http", "tcp"),
    "smb-audit": ("smb", "tcp"), "ldap-audit": ("ldap", "tcp"),
    "kerb-audit": ("kerberos", "tcp"), "mail-audit": ("smtp", "tcp"),
    "snmp-audit": ("snmp", "udp"), "ftp-audit": ("ftp", "tcp"),
}


def sev_of(text):
    m = re.match(r"\s*\[?\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", text, re.I)
    if m:
        return m.group(1).lower()
    t = text.lower()
    if any(k in t for k in ("expired", "no auth", "no-auth", "anonymous", "unauth",
                            "null session", "open relay", "default cred", "writable",
                            "backdoor", "critical", "eternalblue")):
        return "high"
    if any(k in t for k in ("weak", "deprecated", "self-signed", "missing", "not required",
                            "not set", "disclosure", "sweet32", "signing")):
        return "medium"
    return "low"


class Graph:
    def __init__(self, run_id, ts):
        self.nodes = {}
        self.edges = {}
        self.run_id = run_id
        self.ts = ts

    def node(self, nid, ntype, label=None, props=None, tool=None, confidence="EXTRACTED"):
        n = self.nodes.get(nid)
        if not n:
            n = {"id": nid, "type": ntype, "label": label or nid,
                 "props": {}, "source": {"tool": tool, "run_id": self.run_id, "ts": self.ts},
                 "confidence": confidence}
            self.nodes[nid] = n
        if props:
            for k, v in props.items():
                if v not in (None, "", []) and k not in n["props"]:
                    n["props"][k] = v
        if label and (n["label"] == nid):
            n["label"] = label
        return nid

    def edge(self, src, rel, dst, props=None, confidence="EXTRACTED"):
        eid = "%s|%s|%s" % (src, rel, dst)
        if eid not in self.edges:
            self.edges[eid] = {"id": eid, "source": src, "target": dst, "relation": rel,
                               "props": props or {}, "confidence": confidence}
        return eid


def add_cve(g, cve_id, src_tool, props=None, confidence="INFERRED"):
    cid = cve_id.upper()
    nid = "cve:" + cid
    g.node(nid, "CVE", cid, props or {}, tool=src_tool, confidence="EXTRACTED")
    return nid


def enrich_from_db(g, conn, cve_nid):
    cid = cve_nid.split("cve:", 1)[1]
    row = conn.execute(
        "SELECT cvss_base,cvss_severity,epss,kev,cwe,description FROM cve WHERE cve_id=?",
        (cid,)).fetchone()
    if row:
        g.nodes[cve_nid]["props"].update({
            "cvss": row[0], "severity": row[1], "epss": row[2],
            "kev": bool(row[3]), "summary": " ".join((row[5] or "").split())[:200]})
        if row[4]:
            cwe = "cwe:" + row[4]
            g.node(cwe, "CWE", row[4], tool="vulndb")
            g.edge(cve_nid, "EXPLOITS_WEAKNESS", cwe, confidence="EXTRACTED")
    for e in conn.execute(
            "SELECT kind,ext_id,title,url,source,rank,verified FROM v_exploit_for_cve WHERE cve_id=?",
            (cid,)):
        exid = "exploit:%s:%s" % (e[0], e[1])
        g.node(exid, "Exploit", (e[2] or e[1])[:80],
               {"source": e[4], "url": e[3], "kind": e[0], "rank": e[5], "verified": bool(e[6])},
               tool="vulndb")
        g.edge(cve_nid, "HAS_EXPLOIT", exid,
               confidence="EXTRACTED" if e[0] in ("edb", "msf") else "INFERRED")


def ingest(g, obj, conn):
    tool = obj.get("tool")
    if not tool:
        return
    host = str(obj.get("host", obj.get("target", obj.get("query", "?"))))
    port = obj.get("port")
    proto, l4 = TOOL_PROTO.get(tool, (None, "tcp"))
    if tool == "db-audit":
        proto = obj.get("engine") or obj.get("type") or "database"
    tnode = g.node("tool:" + tool, "Tool", tool, {"where": "arsenal"}, tool=tool)

    snode = None
    if host and host != "?":
        hnode = g.node("host:" + host, "Host", host, {"hostname": host}, tool=tool)
        if port:
            sid = "svc:%s:%s/%s" % (host, port, l4)
            snode = g.node(sid, "Service", "%s:%s" % (host, port),
                           {"host": host, "port": port, "l4": l4,
                            "product": obj.get("product"), "version": obj.get("version"),
                            "banner": obj.get("banner")}, tool=tool)
            g.edge(sid, "ON_HOST", hnode)
            if proto:
                pid = g.node("proto:" + proto, "Protocol", proto, tool=tool)
                g.edge(sid, "SPEAKS", pid)
        elif proto:
            pid = g.node("proto:" + proto, "Protocol", proto, tool=tool)
            g.edge(hnode, "SPEAKS", pid)

    anchor = snode or ("host:" + host if host and host != "?" else tnode)

    # findings from problems[]
    for i, prob in enumerate(obj.get("problems", []) or []):
        prob = str(prob)
        fid = "finding:%s:%s:%s:%s:%d" % (g.run_id, tool, host, port or "-", i)
        g.node(fid, "Finding", prob[:80],
               {"evidence": prob, "severity": sev_of(prob), "host": host, "port": port},
               tool=tool)
        g.edge(fid, "FOUND_BY", tnode)
        if anchor != tnode:
            g.edge(fid, "OBSERVED_ON", anchor)
        for cid in CVE_RE.findall(prob):
            cve = add_cve(g, cid, tool)
            g.edge(fid, "MAPS_TO", cve, confidence="INFERRED")

    # structured cves[] from vulndb-lookup / cve-lookup
    for c in obj.get("cves", []) or []:
        cid = (c.get("cve") or "").upper()
        if not cid:
            continue
        cve = add_cve(g, cid, tool, {
            "cvss": c.get("cvss"), "severity": c.get("severity"),
            "epss": c.get("epss"), "kev": bool(c.get("kev")),
            "summary": " ".join((c.get("description") or "").split())[:200]})
        if snode:
            g.edge(snode, "AFFECTED_BY", cve, confidence="INFERRED")
        for ex in c.get("exploits", []) or []:
            exid = "exploit:%s:%s" % (ex.get("kind", "poc"), ex.get("ext_id", "?"))
            g.node(exid, "Exploit", (ex.get("title") or ex.get("ext_id") or "")[:80],
                   {"source": ex.get("source"), "url": ex.get("url"), "kind": ex.get("kind"),
                    "verified": bool(ex.get("verified"))}, tool=tool)
            g.edge(cve, "HAS_EXPLOIT", exid,
                   confidence="EXTRACTED" if ex.get("kind") in ("edb", "msf") else "INFERRED")

    # enrich every CVE node from the shared vuln DB — adds CVSS/EPSS/KEV where
    # missing and, crucially, the public exploits + CWE that tie the ribbon
    # together (the lookup's cves[] may already carry CVSS but not exploits/CWE)
    if conn:
        for nid in [n for n in g.nodes if n.startswith("cve:")]:
            enrich_from_db(g, conn, nid)


def to_bloodhound(g):
    nodes = [{"id": n["id"], "kinds": [n["type"]],
              "properties": dict(n["props"], label=n["label"], confidence=n["confidence"])}
             for n in g.nodes.values()]
    edges = [{"kind": e["relation"], "start": {"value": e["source"], "match_by": "id"},
              "end": {"value": e["target"], "match_by": "id"}, "properties": e["props"]}
             for e in g.edges.values()]
    return {"graph": {"nodes": nodes, "edges": edges}}


def main():
    ap = argparse.ArgumentParser(description="Weave analyser --json into a knowledge graph.")
    ap.add_argument("files", nargs="*", help="JSONL files (default: stdin)")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--vulndb", help="vuln DB to enrich CVE nodes (read-only)")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--engagement", default=os.environ.get("ARSENAL_ENGAGEMENT", ""))
    ap.add_argument("--format", choices=["graphify", "bloodhound", "both"], default="graphify")
    args = ap.parse_args()

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    run_id = args.run_id or ("run-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
    g = Graph(run_id, ts)

    conn = None
    if args.vulndb:
        if not os.path.exists(args.vulndb):
            sys.stderr.write("[!] --vulndb not found, skipping enrichment: %s\n" % args.vulndb)
        else:
            conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % os.path.abspath(args.vulndb), uri=True)

    # read input
    streams = [open(f, encoding="utf-8") for f in args.files] if args.files else [sys.stdin]
    n_in = 0
    for st in streams:
        for line in st:
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            ingest(g, obj, conn)
            n_in += 1

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "nodes.jsonl"), "w", encoding="utf-8") as f:
        for n in g.nodes.values():
            f.write(json.dumps(n) + "\n")
    with open(os.path.join(args.out, "edges.jsonl"), "w", encoding="utf-8") as f:
        for e in g.edges.values():
            f.write(json.dumps(e) + "\n")
    bundle = {"schema": SCHEMA, "generated": ts, "engagement": args.engagement,
              "nodes": list(g.nodes.values()), "edges": list(g.edges.values()), "hyperedges": []}
    with open(os.path.join(args.out, "graph.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    if args.format in ("bloodhound", "both"):
        with open(os.path.join(args.out, "bloodhound.json"), "w", encoding="utf-8") as f:
            json.dump(to_bloodhound(g), f, indent=2)

    counts = {"nodes": len(g.nodes), "edges": len(g.edges),
              "findings": sum(1 for n in g.nodes.values() if n["type"] == "Finding"),
              "cves": sum(1 for n in g.nodes.values() if n["type"] == "CVE"),
              "exploits": sum(1 for n in g.nodes.values() if n["type"] == "Exploit")}
    manifest = {"schema": SCHEMA, "generated": ts, "engagement": args.engagement,
                "run_id": run_id, "inputs": n_in,
                "producers": sorted({n["source"]["tool"] for n in g.nodes.values() if n["source"]["tool"]}),
                "files": {"nodes": "nodes.jsonl", "edges": "edges.jsonl", "graphify": "graph.json"},
                "counts": counts}
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    if conn:
        conn.close()
    sys.stderr.write("[+] graph: %d nodes, %d edges (%d findings, %d CVEs, %d exploits) from %d inputs -> %s\n"
                     % (counts["nodes"], counts["edges"], counts["findings"], counts["cves"],
                        counts["exploits"], n_in, args.out))


if __name__ == "__main__":
    main()
