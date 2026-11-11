# graph — the "red ribbon" knowledge graph

Weaves the `--json` output of every Arsenal analyser (plus `vulndb`/`cve-lookup`)
into one connected knowledge graph, and auto-enriches CVE nodes from the shared
[vuln DB](../vulndb/) with CVSS/EPSS/KEV, public exploits, and CWEs. The result
is ingestible by **graphify**, **Mimir**, and **Crucible** — one finding in any
tool resolves to the same CVE and the same exploit as everywhere else.

```
{ arsenal ssl --json host; arsenal http --json host; } | arsenal graph --out ./g
arsenal vulndb --json openssh 9.2 | arsenal graph --out ./g
arsenal graph --out ./g --vulndb ../vulndb/vulndb.sqlite results.jsonl
arsenal graph --out ./g --format bloodhound results.jsonl
```

## Output (`--out` dir)

| File | What |
| ---- | ---- |
| `nodes.jsonl` | one node per line: `{id,type,label,props,source,confidence}` |
| `edges.jsonl` | one edge per line: `{id,source,target,relation,props,confidence}` |
| `graph.json` | `{schema,generated,nodes,edges,hyperedges}` — graphify's `build_from_json` input |
| `manifest.json` | counts + producers + run id |
| `bloodhound.json` | (with `--format bloodhound`) OpenGraph-shaped export |

## Model (`arsenal-redribbon/1.0`)

Node types: `Tool, Protocol, Service, Host, Finding, CVE, Exploit, CWE` (and
`Technique`/`CPE` reserved). IDs are type-prefixed and stable (`cve:CVE-2024-6387`,
`svc:host:443/tcp`, `exploit:edb:40888`).

Relations: `SPEAKS` (Service→Protocol), `ON_HOST` (Service→Host), `FOUND_BY`
(Finding→Tool), `OBSERVED_ON` (Finding→Service), `MAPS_TO` (Finding→CVE),
`AFFECTED_BY` (Service→CVE), `HAS_EXPLOIT` (CVE→Exploit), `EXPLOITS_WEAKNESS`
(CVE→CWE).

Each node/edge carries a `confidence` of `EXTRACTED` (directly observed / curated
source) or `INFERRED` (a lead to verify — e.g. a keyword CVE match or an
unvetted PoC), so consumers can weight the ribbon.

The canonical path that closes the loop:

```
Tool -DETECTS/FOUND_BY-> Finding -OBSERVED_ON-> Service -SPEAKS-> Protocol
Finding -MAPS_TO-> CVE -HAS_EXPLOIT-> Exploit
                   CVE -EXPLOITS_WEAKNESS-> CWE
```

## Consuming it

- **graphify**: feed `graph.json` straight into `build_from_json` — `node.id`
  dedup, `edge.source/target` health check, and `confidence` audit trail already
  match its contract; Louvain communities surface clusters (TLS hygiene, mail
  auth, web exposure) and god-nodes surface hubs (a shared CWE, a KEV CVE).
- **Mimir / Crucible**: read `nodes.jsonl` + `edges.jsonl`, or `graph.json`.
- **BloodHound**: `--format bloodhound` emits OpenGraph `{graph:{nodes,edges}}`
  with `UPPER_SNAKE` relation kinds.

> Not yet implemented: the `Check`/`Technique` catalog layer (`checks.json` with
> per-check ATT&CK mappings) — findings currently anchor directly to tools and
> CVEs. Tracked in [../docs/roadmap.md](../docs/roadmap.md).
