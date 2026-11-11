#!/usr/bin/env python3
"""vulndb_build.py — build the offline CVE+exploit knowledge base (SQLite).

stdlib only (sqlite3, urllib, json, csv, gzip, lzma, zipfile) so it runs
anywhere python3 is present — the target has no sqlite3 CLI and no pip.

Sources (all curl/urllib-fetchable; see README for licenses):
  nvd        NVD API 2.0  -> CVE + CVSS + CWE + CPE version ranges (the version map)
  kev        CISA KEV     -> known-exploited flag
  epss       FIRST EPSS   -> exploit-probability score (update-only by default)
  nuclei     nuclei-templates cves.json -> CVE -> detection template
  exploitdb  Exploit-DB files_exploits.csv -> CVE -> public exploit
  metasploit modules_metadata_base.json  -> CVE -> Metasploit module

Typical use:
  # fast exploit/KEV/EPSS/nuclei layer (no NVD):
  vulndb_build.py --db vulndb.sqlite --only kev,epss,nuclei,exploitdb,metasploit
  # add the version->CVE map for your target's software (targeted, quick):
  vulndb_build.py --db vulndb.sqlite --nvd-keyword openssh
  # full NVD import (large; paced; use an NVD_API_KEY):
  vulndb_build.py --db vulndb.sqlite --nvd-full
"""
import argparse, csv, gzip, io, json, lzma, os, re, sqlite3, sys, time, urllib.request, zipfile

BUILDER_VERSION = "1"
UA = "arsenal-vulndb-build/1.0 (+https://github.com/ShadowSlayer08/Arsenal_scripts)"
SRC_BIT = {"nvd": 1, "osv": 2, "ghsa": 4, "exploitdb": 8, "metasploit": 16,
           "nuclei": 32, "kev": 64, "epss": 128}

NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL  = "https://epss.cyentia.com/epss_scores-current.csv.gz"
NUCLEI_URL= "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
EDB_URL   = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
MSF_URL   = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def log(msg):
    sys.stderr.write(msg + "\n"); sys.stderr.flush()


# --------------------------------------------------------------------------- http
def _opener(insecure):
    import ssl
    ctx = ssl._create_unverified_context() if insecure else None
    h = urllib.request.HTTPSHandler(context=ctx) if ctx else urllib.request.HTTPSHandler()
    op = urllib.request.build_opener(h)
    op.addheaders = [("User-Agent", UA)]
    return op


def http_get(url, timeout, insecure=False, headers=None):
    op = _opener(insecure)
    req = urllib.request.Request(url, headers=headers or {})
    with op.open(req, timeout=timeout) as r:
        return r.read()


def cached_get(url, cache_dir, timeout, insecure=False, force=False):
    """Fetch url, caching the raw bytes under cache_dir by a safe filename."""
    os.makedirs(cache_dir, exist_ok=True)
    fn = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-180:]
    path = os.path.join(cache_dir, fn)
    if os.path.exists(path) and not force:
        with open(path, "rb") as f:
            return f.read()
    data = http_get(url, timeout, insecure)
    with open(path, "wb") as f:
        f.write(data)
    return data


# --------------------------------------------------------------------------- db
def connect(db_path, schema_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    with open(schema_path, encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version','1')")
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('builder_version',?)",
                 (BUILDER_VERSION,))
    conn.commit()
    return conn


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def note_source(conn, name, url, license, count):
    conn.execute(
        "INSERT INTO source(name,url,license,last_sync,record_count) VALUES(?,?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET url=excluded.url, license=excluded.license, "
        "last_sync=excluded.last_sync, record_count=excluded.record_count",
        (name, url, license, now_iso(), count))


def set_mask(conn, cve_id, bit):
    conn.execute("UPDATE cve SET source_mask = source_mask | ? WHERE cve_id=?", (bit, cve_id))


def ensure_cve(conn, cve_id):
    conn.execute("INSERT OR IGNORE INTO cve(cve_id) VALUES(?)", (cve_id,))


def product_id(conn, part, vendor, product):
    cur = conn.execute("SELECT id FROM product WHERE part=? AND vendor=? AND product=?",
                       (part, vendor, product))
    row = cur.fetchone()
    if row:
        return row[0]
    cur = conn.execute("INSERT INTO product(part,vendor,product) VALUES(?,?,?)",
                       (part, vendor, product))
    pid = cur.lastrowid
    conn.execute("INSERT OR IGNORE INTO product_alias(alias,product_id) VALUES(?,?)",
                 (product.replace("_", " "), pid))
    return pid


def parse_cpe23(cpe):
    # cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:...
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


def link_exploit(conn, cve_ids, kind, ext_id, **kw):
    conn.execute(
        "INSERT OR IGNORE INTO exploit(kind,ext_id,title,url,local_path,source,platform,type,rank,verified,date_published) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (kind, ext_id, kw.get("title"), kw.get("url"), kw.get("local_path"),
         kw.get("source", kind), kw.get("platform"), kw.get("type"), kw.get("rank"),
         int(kw.get("verified", 0)), kw.get("date_published")))
    eid = conn.execute("SELECT id FROM exploit WHERE kind=? AND ext_id=?", (kind, ext_id)).fetchone()[0]
    for cid in cve_ids:
        cid = cid.upper()
        ensure_cve(conn, cid)
        conn.execute("INSERT OR IGNORE INTO cve_exploit(cve_id,exploit_id,source,confidence) VALUES(?,?,?,?)",
                     (cid, eid, kw.get("source", kind), kw.get("confidence", "high")))
        set_mask(conn, cid, SRC_BIT.get(kind if kind in SRC_BIT else kw.get("source", ""), 0))
    return eid


# --------------------------------------------------------------------------- NVD
def ingest_nvd(conn, mode, value, api_key, timeout, insecure, max_pages):
    headers = {"apiKey": api_key} if api_key else {}
    pace = 0.6 if api_key else 6.0
    per_page = 2000
    start = 0
    total = None
    n_cve = 0
    page = 0
    while True:
        params = ["resultsPerPage=%d" % per_page, "startIndex=%d" % start]
        if mode == "keyword":
            params.append("keywordSearch=" + urllib.request.quote(value))
        elif mode == "cpe":
            params.append("virtualMatchString=" + urllib.request.quote(value))
        url = NVD_URL + "?" + "&".join(params)
        try:
            raw = http_get(url, timeout, insecure, headers)
        except Exception as e:
            log("  nvd: request failed (%s)" % e)
            break
        doc = json.loads(raw)
        if total is None:
            total = doc.get("totalResults", 0)
            log("  nvd: %d results for mode=%s value=%r" % (total, mode, value))
        for v in doc.get("vulnerabilities", []):
            _nvd_one(conn, v.get("cve", {}))
            n_cve += 1
        conn.commit()
        start += per_page
        page += 1
        if start >= (total or 0) or (max_pages and page >= max_pages):
            break
        time.sleep(pace)
    note_source(conn, "nvd", NVD_URL,
                "U.S. Government work / CVE Program terms — redistributable", n_cve)
    return n_cve


def _nvd_one(conn, cve):
    cid = cve.get("id")
    if not cid:
        return
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", ""); break
    base = sev = vec = cvss_ver = None
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            cd = m[key][0].get("cvssData", {})
            base = cd.get("baseScore")
            sev = m[key][0].get("baseSeverity") or cd.get("baseSeverity")
            vec = cd.get("vectorString")
            cvss_ver = cd.get("version")
            break
    cwe = None
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe = d["value"]; break
        if cwe:
            break
    conn.execute(
        "INSERT INTO cve(cve_id,published,last_modified,description,cvss_version,cvss_base,"
        "cvss_severity,cvss_vector,cwe,source_mask) VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(cve_id) DO UPDATE SET published=excluded.published,"
        "last_modified=excluded.last_modified,description=excluded.description,"
        "cvss_version=excluded.cvss_version,cvss_base=excluded.cvss_base,"
        "cvss_severity=excluded.cvss_severity,cvss_vector=excluded.cvss_vector,"
        "cwe=excluded.cwe,source_mask=cve.source_mask|?",
        (cid, cve.get("published"), cve.get("lastModified"), desc, cvss_ver, base, sev, vec,
         cwe, SRC_BIT["nvd"], SRC_BIT["nvd"]))
    # references
    for r in cve.get("references", []):
        tags = ",".join(r.get("tags", [])) or None
        conn.execute("INSERT INTO cve_reference(cve_id,url,ref_type,source) VALUES(?,?,?,?)",
                     (cid, r.get("url"), tags, "nvd"))
    # configurations -> cpeMatch version ranges
    for node_cfg in cve.get("configurations", []):
        for node in node_cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                crit = cm.get("criteria", "")
                p = parse_cpe23(crit)
                if not p:
                    continue
                pid = product_id(conn, p["part"], p["vendor"], p["product"])
                ver_exact = p["version"] if p["version"] not in ("*", "-", "") else None
                conn.execute(
                    "INSERT INTO cve_cpe_match(cve_id,product_id,cpe23,version_exact,"
                    "version_start,start_op,version_end,end_op,vulnerable) VALUES(?,?,?,?,?,?,?,?,?)",
                    (cid, pid, crit, ver_exact,
                     cm.get("versionStartIncluding") or cm.get("versionStartExcluding"),
                     "including" if cm.get("versionStartIncluding") else
                     ("excluding" if cm.get("versionStartExcluding") else None),
                     cm.get("versionEndIncluding") or cm.get("versionEndExcluding"),
                     "including" if cm.get("versionEndIncluding") else
                     ("excluding" if cm.get("versionEndExcluding") else None),
                     int(cm.get("vulnerable", True))))


# --------------------------------------------------------------------------- KEV
def ingest_kev(conn, cache, timeout, insecure, force):
    raw = cached_get(KEV_URL, cache, timeout, insecure, force)
    doc = json.loads(raw)
    n = 0
    for v in doc.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        ensure_cve(conn, cid)
        conn.execute(
            "UPDATE cve SET kev=1, kev_date_added=?, kev_due_date=?, kev_ransomware=?, "
            "source_mask=source_mask|? WHERE cve_id=?",
            (v.get("dateAdded"), v.get("dueDate"),
             1 if (v.get("knownRansomwareCampaignUse", "").lower() == "known") else 0,
             SRC_BIT["kev"], cid))
        n += 1
    conn.commit()
    note_source(conn, "kev", KEV_URL, "CISA / U.S. Government — free to redistribute", n)
    return n


# --------------------------------------------------------------------------- EPSS
def ingest_epss(conn, cache, timeout, insecure, force, insert_all):
    raw = cached_get(EPSS_URL, cache, timeout, insecure, force)
    text = gzip.decompress(raw).decode("utf-8", "replace")
    n = 0
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        if len(row) < 3:
            continue
        cid, epss, pct = row[0], row[1], row[2]
        try:
            epss = float(epss); pct = float(pct)
        except ValueError:
            continue
        if insert_all:
            ensure_cve(conn, cid)
        cur = conn.execute(
            "UPDATE cve SET epss=?, epss_percentile=?, source_mask=source_mask|? WHERE cve_id=?",
            (epss, pct, SRC_BIT["epss"], cid))
        if cur.rowcount:
            n += 1
    conn.commit()
    note_source(conn, "epss", EPSS_URL, "FIRST EPSS — free to use (cite FIRST.org)", n)
    return n


# --------------------------------------------------------------------------- nuclei
def ingest_nuclei(conn, cache, timeout, insecure, force):
    raw = cached_get(NUCLEI_URL, cache, timeout, insecure, force).decode("utf-8", "replace")
    n = 0
    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            t = json.loads(line)
        except Exception:
            continue
        tid = t.get("ID") or t.get("id")
        if not tid:
            continue
        info = t.get("Info", t.get("info", {}))
        sev = (info.get("severity") if isinstance(info, dict) else None)
        name = (info.get("name") if isinstance(info, dict) else None)
        path = t.get("file_path") or t.get("path")
        cids = CVE_RE.findall(tid)
        if not cids:
            continue
        link_exploit(conn, cids, "nuclei", tid, title=name, source="nuclei",
                     url="https://github.com/projectdiscovery/nuclei-templates/blob/main/" + (path or ""),
                     local_path=path, rank=sev, confidence="high")
        n += 1
    conn.commit()
    note_source(conn, "nuclei", NUCLEI_URL, "MIT (ProjectDiscovery)", n)
    return n


# --------------------------------------------------------------------------- ExploitDB
def ingest_exploitdb(conn, cache, timeout, insecure, force):
    raw = cached_get(EDB_URL, cache, timeout, insecure, force).decode("utf-8", "replace")
    n = 0
    rdr = csv.DictReader(io.StringIO(raw))
    for row in rdr:
        eid = row.get("id")
        codes = row.get("codes", "") or ""
        cids = CVE_RE.findall(codes)
        if not eid or not cids:
            continue
        link_exploit(conn, cids, "edb", eid, title=row.get("description"),
                     url="https://www.exploit-db.com/exploits/" + eid,
                     local_path=row.get("file"), source="exploitdb",
                     platform=row.get("platform"), type=row.get("type"),
                     verified=1 if row.get("verified") in ("1", "true", "True") else 0,
                     date_published=row.get("date_published"), confidence="high")
        n += 1
    conn.commit()
    note_source(conn, "exploitdb", EDB_URL, "GPL-2.0-or-later (Offensive Security)", n)
    return n


# --------------------------------------------------------------------------- Metasploit
def ingest_metasploit(conn, cache, timeout, insecure, force):
    raw = cached_get(MSF_URL, cache, timeout, insecure, force).decode("utf-8", "replace")
    doc = json.loads(raw)
    n = 0
    for fullname, mod in doc.items():
        refs = mod.get("references", []) or []
        cids = []
        for r in refs:
            if isinstance(r, str):
                cids += CVE_RE.findall(r)
            elif isinstance(r, dict):
                cids += CVE_RE.findall(json.dumps(r))
        cids = sorted(set(c.upper() for c in cids))
        if not cids:
            continue
        link_exploit(conn, cids, "msf", fullname, title=mod.get("name"),
                     url="https://github.com/rapid7/metasploit-framework",
                     local_path="modules/" + fullname + ".rb", source="metasploit",
                     type=mod.get("type"), rank=str(mod.get("rank", "")),
                     date_published=mod.get("disclosure_date"), confidence="high")
        n += 1
    conn.commit()
    note_source(conn, "metasploit", MSF_URL, "BSD-style (Rapid7) — metadata index", n)
    return n


# --------------------------------------------------------------------------- main
DEFAULT_ONLY = "kev,epss,nuclei,exploitdb,metasploit"


def main():
    ap = argparse.ArgumentParser(description="Build the offline CVE+exploit vuln DB (SQLite).")
    ap.add_argument("--db", required=True)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--schema", default=os.path.join(here, "schema.sql"))
    ap.add_argument("--cache", default=None, help="cache dir (default: <db>.cache)")
    ap.add_argument("--only", default=None,
                    help="comma list of: nvd,kev,epss,nuclei,exploitdb,metasploit (default: %s)" % DEFAULT_ONLY)
    ap.add_argument("--nvd-keyword", help="import NVD CVEs matching this keyword (targeted, quick)")
    ap.add_argument("--nvd-cpe", help="import NVD CVEs for this CPE match string")
    ap.add_argument("--nvd-full", action="store_true", help="import the full NVD (large, paced)")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--max-nvd-pages", type=int, default=0, help="cap NVD pages (0=all)")
    ap.add_argument("--epss-all", action="store_true", help="insert EPSS rows even for unknown CVEs")
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification for feeds")
    ap.add_argument("--refresh", action="store_true", help="ignore cache, re-fetch")
    args = ap.parse_args()

    cache = args.cache or (args.db + ".cache")
    conn = connect(args.db, args.schema)

    only = set((args.only or DEFAULT_ONLY).split(","))
    nvd_requested = args.nvd_keyword or args.nvd_cpe or args.nvd_full or ("nvd" in (args.only or "").split(","))

    try:
        if nvd_requested:
            mode, val = ("keyword", args.nvd_keyword) if args.nvd_keyword else \
                        ("cpe", args.nvd_cpe) if args.nvd_cpe else ("full", None)
            log("[*] NVD (%s)…" % mode)
            n = ingest_nvd(conn, mode, val, args.nvd_api_key, args.timeout, args.insecure, args.max_nvd_pages)
            log("    nvd: %d CVEs" % n)
        if "kev" in only:
            log("[*] CISA KEV…"); log("    kev: %d" % ingest_kev(conn, cache, args.timeout, args.insecure, args.refresh))
        if "epss" in only:
            log("[*] EPSS…"); log("    epss: %d updated" % ingest_epss(conn, cache, args.timeout, args.insecure, args.refresh, args.epss_all))
        if "nuclei" in only:
            log("[*] nuclei-templates…"); log("    nuclei: %d" % ingest_nuclei(conn, cache, args.timeout, args.insecure, args.refresh))
        if "exploitdb" in only:
            log("[*] Exploit-DB…"); log("    exploitdb: %d" % ingest_exploitdb(conn, cache, args.timeout, args.insecure, args.refresh))
        if "metasploit" in only:
            log("[*] Metasploit…"); log("    metasploit: %d" % ingest_metasploit(conn, cache, args.timeout, args.insecure, args.refresh))
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('built_at',?)", (now_iso(),))
        conn.commit()
    finally:
        # counts
        for tbl in ("cve", "exploit", "cve_exploit", "cve_cpe_match", "product"):
            try:
                c = conn.execute("SELECT COUNT(*) FROM %s" % tbl).fetchone()[0]
                log("    [db] %s: %d" % (tbl, c))
            except Exception:
                pass
        conn.close()


if __name__ == "__main__":
    main()
