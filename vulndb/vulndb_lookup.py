#!/usr/bin/env python3
"""vulndb_lookup.py — offline lookup against the vuln+exploit DB.

Map a software product + version to CVEs (version-range aware) and their public
exploits, enriched with CVSS / EPSS / CISA-KEV. stdlib only; opens the DB
read-only so Mimir/Crucible can read concurrently.

  vulndb_lookup.py --db vulndb.sqlite openssh 9.2
  vulndb_lookup.py --db vulndb.sqlite --json "apache http_server" 2.4.49
  vulndb_lookup.py --db vulndb.sqlite --cve CVE-2024-6387
  nmap -sV -oG - host | vulndb_lookup.py --db vulndb.sqlite --from-nmap --json

Exit: 0 nothing found / 1 vulnerabilities found / 2 error.
"""
import argparse, json, os, re, sqlite3, sys

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
PRE = {"alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1, "pre": -1, "dev": -4, "snapshot": -4}


# ----------------------------------------------------------- version compare
def ver_key(v):
    out = []
    for tok in re.findall(r"\d+|[a-zA-Z]+", str(v).lower()):
        if tok.isdigit():
            out.append((1, int(tok), ""))
        elif tok in PRE:
            out.append((0, PRE[tok], tok))      # pre-release: sorts below release
        else:
            out.append((2, 0, tok))             # letter/patch suffix: post-release
    return out


def vcmp(a, b):
    ka, kb = ver_key(a), ver_key(b)
    pad = (1, 0, "")                            # release sentinel (> pre, < post)
    n = max(len(ka), len(kb))
    ka += [pad] * (n - len(ka))
    kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def in_range(t, exact, vstart, startop, vend, endop):
    if exact:
        return vcmp(t, exact) == 0
    if not vstart and not vend:
        return True                              # criteria version '*' = all versions
    if vstart:
        c = vcmp(t, vstart)
        if startop == "excluding" and not c > 0:
            return False
        if startop != "excluding" and c < 0:     # including (default)
            return False
    if vend:
        c = vcmp(t, vend)
        if endop == "excluding" and not c < 0:
            return False
        if endop != "excluding" and c > 0:        # including (default)
            return False
    return True


# ----------------------------------------------------------- db
def open_ro(db):
    uri = "file:%s?mode=ro&immutable=1" % os.path.abspath(db).replace("?", "")
    return sqlite3.connect(uri, uri=True)


def resolve_products(conn, phrase):
    """phrase -> [product_id]. Try alias, exact product, then LIKE on last token."""
    phrase = phrase.strip().lower()
    ids = []
    for q, a in (("SELECT product_id FROM product_alias WHERE lower(alias)=?", phrase),
                 ("SELECT id FROM product WHERE lower(product)=?", phrase.replace(" ", "_"))):
        ids += [r[0] for r in conn.execute(q, (a,))]
    if not ids:
        tok = phrase.split()[-1] if phrase.split() else phrase
        tok = tok.replace(" ", "_")
        ids += [r[0] for r in conn.execute(
            "SELECT id FROM product WHERE product=? OR product LIKE ?", (tok, "%" + tok + "%"))]
    return sorted(set(ids))


def cves_for(conn, phrase, version):
    pids = resolve_products(conn, phrase)
    if not pids:
        return [], pids
    hits = set()
    qmarks = ",".join("?" * len(pids))
    rows = conn.execute(
        "SELECT cve_id,version_exact,version_start,start_op,version_end,end_op "
        "FROM cve_cpe_match WHERE vulnerable=1 AND product_id IN (%s)" % qmarks, pids)
    for cve_id, exact, vs, so, ve, eo in rows:
        if version is None or in_range(version, exact, vs, so, ve, eo):
            hits.add(cve_id)
    return sorted(hits), pids


def enrich(conn, cve_id):
    row = conn.execute(
        "SELECT cve_id,cvss_base,cvss_severity,epss,epss_percentile,kev,kev_ransomware,cwe,description "
        "FROM cve WHERE cve_id=?", (cve_id,)).fetchone()
    if not row:
        return None
    d = dict(zip(("cve", "cvss", "severity", "epss", "epss_pct", "kev", "kev_ransomware", "cwe", "description"), row))
    d["exploits"] = [dict(zip(("kind", "ext_id", "title", "url", "local_path", "source", "rank", "verified"), e))
                     for e in conn.execute(
                         "SELECT kind,ext_id,title,url,local_path,source,rank,verified "
                         "FROM v_exploit_for_cve WHERE cve_id=? ORDER BY kind", (cve_id,))]
    return d


def sort_key(d):
    return (1 if d.get("kev") else 0, d.get("cvss") or -1, d.get("epss") or -1)


def main():
    ap = argparse.ArgumentParser(description="Offline CVE+exploit lookup by product+version.")
    ap.add_argument("--db", required=True)
    ap.add_argument("query", nargs="*", help='e.g. openssh 9.2  |  "apache http_server" 2.4.49')
    ap.add_argument("--cve", help="look up a single CVE id directly")
    ap.add_argument("--from-nmap", action="store_true", help="parse `nmap -sV` lines from stdin")
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--min-epss", type=float, default=0.0)
    ap.add_argument("--kev-only", action="store_true")
    ap.add_argument("--exploitable-only", action="store_true", help="only CVEs with a known exploit")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.stderr.write("[x] vuln DB not found: %s (build it with vulndb-build.sh)\n" % args.db)
        sys.exit(2)
    conn = open_ro(args.db)

    # assemble (label, product, version) work items
    items = []
    if args.cve:
        items.append((args.cve.upper(), None, None))
    elif args.from_nmap:
        for line in sys.stdin:
            if "open" not in line.lower():
                continue
            m = re.sub(r"^.*?/\w+\s+open\s+\S+\s+", "", line.strip())
            mm = re.match(r"([A-Za-z][\w .-]*?)\s+(\d[\w.]*)", m)
            if mm:
                items.append((mm.group(0).strip(), mm.group(1).strip().replace(" ", "_"), mm.group(2)))
    else:
        if not args.query:
            sys.stderr.write("[x] give a product and version, or --cve, or --from-nmap\n")
            sys.exit(2)
        version = args.query[-1] if len(args.query) > 1 and re.match(r"^v?\d", args.query[-1]) else None
        product = " ".join(args.query[:-1]) if version else " ".join(args.query)
        items.append((" ".join(args.query), product, version))

    out_objs, found_any = [], False
    for label, product, version in items:
        if product is None and args.cve:
            cids = [args.cve.upper()]
        else:
            cids, _ = cves_for(conn, product, version)
        rows = [enrich(conn, c) for c in cids]
        rows = [r for r in rows if r]
        rows = [r for r in rows if (r["cvss"] or 0) >= args.min_score and (r["epss"] or 0) >= args.min_epss]
        if args.kev_only:
            rows = [r for r in rows if r["kev"]]
        if args.exploitable_only:
            rows = [r for r in rows if r["exploits"]]
        rows.sort(key=sort_key, reverse=True)
        rows = rows[:args.limit]
        if rows:
            found_any = True

        problems = []
        for r in rows:
            tags = []
            if r["kev"]:
                tags.append("KEV")
            if r["exploits"]:
                tags.append("%d exploit%s" % (len(r["exploits"]), "" if len(r["exploits"]) == 1 else "s"))
            tag = (" [" + ", ".join(tags) + "]") if tags else ""
            problems.append("%s (CVSS %s %s, EPSS %s)%s: %s" % (
                r["cve"], r["cvss"] if r["cvss"] is not None else "?", r["severity"] or "?",
                ("%.2f" % r["epss"]) if r["epss"] is not None else "?", tag,
                " ".join((r["description"] or "").split())[:120]))

        if args.json:
            out_objs.append({"tool": "vulndb-lookup", "host": label, "query": label,
                             "version": version, "count": len(rows), "problems": problems, "cves": rows})
        else:
            print("\n== %s ==" % label)
            if not rows:
                print("   (no CVEs matched)")
            for r in rows:
                flags = ("KEV " if r["kev"] else "") + ("EXPLOIT " if r["exploits"] else "")
                print("  %4s  %-16s %-9s EPSS %-5s %s%s" % (
                    r["cvss"] if r["cvss"] is not None else "?", r["cve"], r["severity"] or "?",
                    ("%.2f" % r["epss"]) if r["epss"] is not None else "-", flags,
                    " ".join((r["description"] or "").split())[:80]))
                for e in r["exploits"][:6]:
                    print("          -> %-9s %s  %s" % (e["kind"], e["ext_id"], (e["title"] or e["url"] or "")[:70]))

    if args.json:
        for o in out_objs:
            print(json.dumps(o))
    conn.close()
    sys.exit(1 if found_any else 0)


if __name__ == "__main__":
    main()
