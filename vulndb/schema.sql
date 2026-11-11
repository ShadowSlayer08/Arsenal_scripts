-- vulndb schema v1 — OFFLINE vuln+exploit knowledge base for Arsenal / Mimir / Crucible.
-- Built and queried with python3 stdlib sqlite3 (target has NO sqlite3 CLI).
-- Build with PRAGMA journal_mode=WAL; readers (Mimir/Crucible) open mode=ro / immutable=1.
PRAGMA foreign_keys = ON;

-- ---- provenance / incremental-update bookkeeping -------------------------
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);  -- ('schema_version','1'), ('built_at',ISO8601), ('builder_version',...)

CREATE TABLE IF NOT EXISTS source (
    name         TEXT PRIMARY KEY,  -- nvd|osv|ghsa|exploitdb|metasploit|nuclei|kev|epss
    url          TEXT,
    license      TEXT,
    last_sync    TEXT,              -- ISO8601 UTC of last successful import
    cursor       TEXT,              -- incremental cursor: NVD lastModEndDate / archive SHA / ETag
    record_count INTEGER DEFAULT 0
);

-- ---- product / CPE identity ---------------------------------------------
CREATE TABLE IF NOT EXISTS product (
    id      INTEGER PRIMARY KEY,
    part    TEXT NOT NULL DEFAULT 'a',  -- a|o|h  (application/os/hardware)
    vendor  TEXT NOT NULL,
    product TEXT NOT NULL,
    UNIQUE(part, vendor, product)
);
CREATE INDEX IF NOT EXISTS ix_product_product ON product(product);

CREATE TABLE IF NOT EXISTS cpe (
    id         INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE,
    cpe23      TEXT NOT NULL UNIQUE,   -- cpe:2.3:a:vendor:product:version:...
    version    TEXT
);
CREATE INDEX IF NOT EXISTS ix_cpe_product ON cpe(product_id);

-- ---- central CVE table (cvss + epss + kev inline for fast sort/filter) ---
-- source_mask bits: 1 nvd, 2 osv, 4 ghsa, 8 exploitdb, 16 metasploit, 32 nuclei, 64 kev, 128 epss
CREATE TABLE IF NOT EXISTS cve (
    cve_id          TEXT PRIMARY KEY,           -- CVE-YYYY-NNNNN
    published       TEXT,
    last_modified   TEXT,
    description     TEXT,
    cvss_version    TEXT,                        -- '3.1'|'3.0'|'2.0'|'4.0'
    cvss_base       REAL,                        -- 0.0-10.0 (NULL if none)
    cvss_severity   TEXT,                        -- LOW|MEDIUM|HIGH|CRITICAL
    cvss_vector     TEXT,
    cwe             TEXT,
    epss            REAL,                         -- 0.0-1.0 (FIRST EPSS)
    epss_percentile REAL,
    kev             INTEGER NOT NULL DEFAULT 0,   -- 1 if in CISA KEV
    kev_date_added  TEXT,
    kev_due_date    TEXT,
    kev_ransomware  INTEGER NOT NULL DEFAULT 0,
    source_mask     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_cve_cvss ON cve(cvss_base);
CREATE INDEX IF NOT EXISTS ix_cve_epss ON cve(epss);
CREATE INDEX IF NOT EXISTS ix_cve_kev  ON cve(kev);

-- ---- NVD applicability: CVE -> product + version-range (CPE match) -------
CREATE TABLE IF NOT EXISTS cve_cpe_match (
    id            INTEGER PRIMARY KEY,
    cve_id        TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    product_id    INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE,
    cpe23         TEXT,                   -- criteria string (version may be * or -)
    version_exact TEXT,                   -- set when criteria pins one version
    version_start TEXT,
    start_op      TEXT,                   -- 'including'|'excluding'|NULL
    version_end   TEXT,
    end_op        TEXT,                   -- 'including'|'excluding'|NULL
    vulnerable    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_match_product ON cve_cpe_match(product_id);
CREATE INDEX IF NOT EXISTS ix_match_cve     ON cve_cpe_match(cve_id);

-- ---- OSV / GHSA applicability: CVE -> ecosystem package + range ----------
CREATE TABLE IF NOT EXISTS osv_range (
    id            INTEGER PRIMARY KEY,
    cve_id        TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,          -- PyPI|npm|Go|Debian:12|Alpine:v3.19|...
    package       TEXT NOT NULL,
    range_type    TEXT,                   -- SEMVER|ECOSYSTEM|GIT
    introduced    TEXT,
    fixed         TEXT,
    last_affected TEXT
);
CREATE INDEX IF NOT EXISTS ix_osv_pkg ON osv_range(ecosystem, package);
CREATE INDEX IF NOT EXISTS ix_osv_cve ON osv_range(cve_id);

-- ---- references ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_reference (
    id       INTEGER PRIMARY KEY,
    cve_id   TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    url      TEXT NOT NULL,
    ref_type TEXT,                         -- ADVISORY|FIX|WEB|EXPLOIT|REPORT
    source   TEXT
);
CREATE INDEX IF NOT EXISTS ix_ref_cve ON cve_reference(cve_id);

-- ---- exploits / detections ----------------------------------------------
CREATE TABLE IF NOT EXISTS exploit (
    id             INTEGER PRIMARY KEY,
    kind           TEXT NOT NULL,          -- edb|msf|nuclei|poc|packetstorm
    ext_id         TEXT NOT NULL,          -- EDB id | msf fullname | nuclei template id | GHSA
    title          TEXT,
    url            TEXT,                   -- canonical web url
    local_path     TEXT,                   -- path inside offline clone (open without network)
    source         TEXT NOT NULL,          -- exploitdb|metasploit|nuclei|...
    platform       TEXT,
    type           TEXT,                   -- remote|local|webapps|dos|exploit|auxiliary...
    rank           TEXT,                   -- msf rank / nuclei severity (confidence)
    verified       INTEGER NOT NULL DEFAULT 0,
    date_published TEXT,
    UNIQUE(kind, ext_id)
);
CREATE INDEX IF NOT EXISTS ix_exploit_kind ON exploit(kind, ext_id);

-- ---- CVE <-> exploit mapping (many-to-many) ------------------------------
CREATE TABLE IF NOT EXISTS cve_exploit (
    cve_id     TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    exploit_id INTEGER NOT NULL REFERENCES exploit(id) ON DELETE CASCADE,
    source     TEXT,                       -- feed that asserted the link
    confidence TEXT,                       -- 'high' (direct CVE ref) | 'medium' (heuristic)
    PRIMARY KEY (cve_id, exploit_id)
);
CREATE INDEX IF NOT EXISTS ix_ce_cve     ON cve_exploit(cve_id);
CREATE INDEX IF NOT EXISTS ix_ce_exploit ON cve_exploit(exploit_id);

-- ---- id aliases (CVE <-> GHSA <-> OSV <-> BID ...) -----------------------
CREATE TABLE IF NOT EXISTS alias (
    cve_id   TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    alias_id TEXT NOT NULL,                -- GHSA-xxxx | OSV id | BID | MSB | ...
    scheme   TEXT,                         -- ghsa|osv|bid|msb|edb
    PRIMARY KEY (cve_id, alias_id)
);
CREATE INDEX IF NOT EXISTS ix_alias_alias ON alias(alias_id);

-- ---- product name aliases (recon string -> canonical product) ------------
CREATE TABLE IF NOT EXISTS product_alias (
    alias      TEXT PRIMARY KEY,           -- 'openssh','apache httpd','nginx','iis'
    product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE
);

-- ---- convenience views for Mimir / Crucible ------------------------------
CREATE VIEW IF NOT EXISTS v_cve_enriched AS
SELECT c.cve_id, c.cvss_base, c.cvss_severity, c.epss, c.epss_percentile,
       c.kev, c.kev_ransomware,
       (SELECT COUNT(*) FROM cve_exploit x WHERE x.cve_id = c.cve_id) AS exploit_count,
       c.description
FROM cve c;

CREATE VIEW IF NOT EXISTS v_product_cve AS
SELECT p.id AS product_id, p.part, p.vendor, p.product,
       m.cve_id, m.version_exact, m.version_start, m.start_op,
       m.version_end, m.end_op, m.vulnerable
FROM product p JOIN cve_cpe_match m ON m.product_id = p.id;

CREATE VIEW IF NOT EXISTS v_exploit_for_cve AS
SELECT ce.cve_id, e.kind, e.ext_id, e.title, e.url, e.local_path,
       e.source, e.rank, e.verified
FROM cve_exploit ce JOIN exploit e ON e.id = ce.exploit_id;
