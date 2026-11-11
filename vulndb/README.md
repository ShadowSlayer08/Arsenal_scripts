# vulndb — offline CVE + public-exploit knowledge base

A single SQLite file that maps **software product + version → CVEs → public
exploits**, enriched with CVSS, FIRST EPSS, and the CISA KEV flag. Built and
queried entirely with **python3 stdlib `sqlite3`** (no `sqlite3` CLI, no pip),
so it runs anywhere python3 does and then works **fully offline**.

It is the shared knowledge layer for Arsenal's lookups and for **Mimir** and
**Crucible**: build once, then any number of readers open the same file.

```
vulndb/
├── schema.sql          # the DB schema (v1) — canonical, readable by any consumer
├── vulndb_build.py     # builder (fetch + ingest feeds -> vulndb.sqlite)
├── vulndb_lookup.py    # lookup (product+version -> CVEs -> exploits), version-range aware
├── vulndb-build.sh     # thin wrapper over the builder
└── vulndb-lookup.sh    # thin wrapper over the lookup (Arsenal --json contract)
```
`vulndb.sqlite` and the `*.cache/` download dir are **gitignored** — rebuild them, never commit bulk data.

## Build

```bash
# fast layer: exploits + KEV + EPSS + nuclei (no NVD), -> ./vulndb.sqlite
arsenal vulndb-build --only kev,epss,nuclei,exploitdb,metasploit

# add the version->CVE map for specific software (targeted, quick):
arsenal vulndb-build --nvd-keyword openssh

# full NVD version map (large; paced — set NVD_API_KEY to go faster):
NVD_API_KEY=xxxx arsenal vulndb-build --nvd-full
```
Incremental/again: re-run; `--refresh` ignores the local cache and re-fetches.

## Look up

```bash
arsenal vulndb openssh 9.2                       # version-range matched CVEs + exploits
arsenal vulndb --json --min-score 7 nginx 1.18   # machine-readable (feeds report.sh)
arsenal vulndb --cve CVE-2024-6387               # one CVE's enrichment + exploits
arsenal vulndb --exploitable-only --kev-only redis 6.0
nmap -sV -oG - host | arsenal vulndb --from-nmap --json
```
Exit `0` nothing found / `1` vulnerabilities found / `2` error. Output JSON uses
the Arsenal contract (`{tool,host,...,problems[]}`) so it drops into `arsenal report`.

> Version comparison is done in python (dotted numerics plus suffixes like
> OpenSSH `9.2p1`, OpenSSL `1.0.2k`, `rc`/`beta`), **not** in SQL. Matches are
> **leads to verify**, not proof a target is vulnerable.

## Sources & licenses

Pulled from single curl-fetchable index files; all redistributable under the
terms below (preserve attribution when you redistribute the built DB).

| Source | Gives | Offline | License |
| ------ | ----- | ------- | ------- |
| NVD API 2.0 | CVE, CVSS, CWE, **CPE version ranges** | bootstrap, then yes | U.S. Gov work / CVE Program terms |
| CISA KEV | known-exploited flag + ransomware flag | yes (small JSON) | U.S. Gov — free |
| FIRST EPSS | exploit-probability score | yes (daily CSV.gz) | FIRST EPSS terms (cite FIRST.org) |
| Exploit-DB | CVE → public exploit (EDB id + local path) | yes (`files_exploits.csv`) | GPL-2.0-or-later |
| Metasploit | CVE → module | yes (`modules_metadata_base.json`) | BSD-style (metadata) |
| nuclei-templates | CVE → detection template | yes (`cves.json`) | MIT |

Not ingested: **Vulners** (proprietary, online-only). OSV/GHSA (ecosystem package
ranges) have schema tables (`osv_range`, `alias`) reserved for a future ingester.

Prior art this builds on: [`scipag/vulscan`](https://github.com/scipag/vulscan)
(offline nmap NSE matching `-sV` against flat CSVs) and the online
`nmap-vulners` — this upgrades that idea to an indexed, version-range-aware
SQLite with EPSS/KEV and multi-source exploit links.

## How Mimir / Crucible consume it

Open the same file **read-only** (many concurrent readers; the builder uses WAL):

```python
import sqlite3
c = sqlite3.connect("file:vulndb.sqlite?mode=ro&immutable=1", uri=True)
c.execute("SELECT * FROM v_exploit_for_cve WHERE cve_id=?", ("CVE-2024-6387",))
```
Stable read surface = the three views: `v_cve_enriched`, `v_product_cve`,
`v_exploit_for_cve`. Or shell out to `vulndb-lookup.sh --json`. Either way the
same DB is the single source of truth, so a finding in Arsenal, Mimir, or
Crucible resolves to the same CVE and the same exploit.
