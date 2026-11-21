# Integration — how Arsenal feeds Mimir & Crucible

Arsenal is the protégé: it does the field recon and hands the results to its two
mentors. The handoff is **data, through four stable, documented surfaces** — no
tight coupling, no shared process. Mimir and Crucible consume whichever they want.

```
   analysers --json ─┐
   webscan-lite/heavy ├─► 1. findings (shared JSON schema)
   vulndb lookups ────┘   2. vuln DB (SQLite, read-only)
                          3. red-ribbon graph (nodes/edges/graph.json)
                          4. exchange bundle (findings + graph + manifest, + webhook)
```

## 1. The shared finding schema

Every analyser emits one JSON object per target on stdout with `--json`:

```json
{"tool":"webscan-lite","host":"app.example.com","port":"443","problems":["missing HSTS","..."]}
```

Always present: `tool`, `host`, `problems[]` (`port` when applicable). Tools add
their own fields (`cves[]`, `vulns{}`, `cve_refs[]`, `endpoints`, …). This is the
unit of exchange — collect a run's objects into a `findings.jsonl` (one per line).

## 2. The vuln DB (shared, read-only)

[`vulndb/vulndb.sqlite`](../vulndb/) maps `product+version → CVE → public exploit`
with CVSS/EPSS/KEV. **Open it read-only; many readers are safe** (built WAL):

```python
import sqlite3
c = sqlite3.connect("file:vulndb/vulndb.sqlite?mode=ro&immutable=1", uri=True)
c.execute("SELECT * FROM v_exploit_for_cve WHERE cve_id=?", ("CVE-2024-6387",))
```

Stable read surface = the three views: `v_cve_enriched`, `v_product_cve`,
`v_exploit_for_cve`. Same file for Arsenal, Mimir and Crucible → a finding in any
of them resolves to the same CVE and the same exploit.

## 3. The red-ribbon graph

[`graph/graph-build.sh`](../graph/) turns the findings (+ vuln DB) into
`nodes.jsonl` / `edges.jsonl` / `graph.json`:
`Tool → Finding → Service → Protocol`, `Finding → CVE → Exploit → CWE`, every edge
tagged `EXTRACTED` vs `INFERRED`. `graph.json` is graphify's `build_from_json`
input and a clean ingest for Mimir/Crucible. A `--format bloodhound` export is
available too.

## 4. The exchange bundle (what the console ships)

`arsenal webapp` → **Export** writes `webapp/exchange/`:

```
exchange/
├── findings.jsonl        all session findings (schema #1)
├── graph/graph.json      the red ribbon (schema #3)
└── manifest.json         {schema:"arsenal-exchange/1.0", findings, files, consumers}
```

If `ARSENAL_MIMIR_URL` / `ARSENAL_CRUCIBLE_URL` are set, it also **POSTs** the
bundle to each:

```
POST <url>   Content-Type: application/json
{ "manifest": { … }, "findings": [ {schema #1}, … ] }
```

```bash
ARSENAL_MIMIR_URL=http://mimir.local/ingest \
ARSENAL_CRUCIBLE_URL=http://crucible.local/recon \
  arsenal webapp
```

## What each mentor does with it

### ᛗ Mimir — orchestration
Mimir stages `scope → scan → correlate → attack-path → runbook`. Arsenal supplies
the **scan/assess** inputs:
- `findings.jsonl` → service/finding correlation (its "25 findings · 11 CVEs" stage).
- the vuln DB → CVE enrichment + EPSS/KEV prioritisation for ranking.
- `graph.json` → attack-path edges and the ATT&CK/CWE hooks its engine maps.

Mimir stays the strategist (it fires no exploits); Arsenal is its eyes and hands
in the field.

### ⚔️ Crucible — trial by fire for AI
Crucible red-teams an LLM/agent and **recons the infrastructure around the model**.
Arsenal *is* that infra-recon layer: point `webscan-lite/heavy`, `ssl`, `http`,
`dns` and the vuln DB at the model's endpoint/host, and the bundle gives Crucible
the exposed-services / TLS / CVE picture that surrounds the AI it's testing.

## Note on coupling

Arsenal never imports Mimir or Crucible and never calls their internals. The
contract is these four artifacts. If the other side changes, nothing in Arsenal
breaks — it keeps producing the same findings, DB, graph and bundle.
