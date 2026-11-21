<h1 align="center">⚒ Arsenal</h1>

<p align="center"><b><i>The forge. Where the field tools are made and wielded.</i></b></p>

<p align="center">
Hand-run scripts for manual pentesting, VAPT, red teaming and config review —
the reconnaissance and analysis muscle that does the work in the field and
carries what it learns back to its mentors, <b>Mimir</b> and <b>Crucible</b>.
</p>

<p align="center">
  <img alt="shellcheck" src="https://img.shields.io/badge/shellcheck-clean-3fd07d?style=flat-square">
  <img alt="authorized use only" src="https://img.shields.io/badge/authorized%20use%20only-ffa53b?style=flat-square">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-8b91a3?style=flat-square">
</p>

> ⚠️ **Authorized use only.** For your own systems, lab/CTF environments, or
> engagements where you have **explicit written permission**. The analysers make
> ordinary, read-only connections; intrusive checks are opt-in; the installer
> stages offensive tooling. You are responsible for how you use them.

---

## The trinity — Arsenal, the protégé

Three tools, one craft. Arsenal is the **protégé** of two heroes, and it knows its place:

- ᛗ **[Mimir](https://github.com/ShadowSlayer08/Mimir)** — the keeper of the well of
  knowledge. A pentest **orchestration engine**: it stages an engagement end-to-end
  (scope → scan → correlate → attack-path → runbook) and hands the operator a plan.
- ⚔️ **[Crucible](https://github.com/ShadowSlayer08/Crucible)** — trial by fire for AI.
  Black-box **offensive testing of LLMs/agents**, mapped to ATLAS / OWASP-LLM / NIST.

**Arsenal is neither.** It doesn't orchestrate and it doesn't judge models — it is
the hands at the anvil: each script does one job, run by hand, and emits a shared
`--json` finding. Those findings become **the knowledge Arsenal carries up the
mountain** — through the [vuln DB](vulndb/), the [red-ribbon graph](graph/), and the
web console's [exchange bundle](docs/integration.md):

```
   analysers --json ─┐
   webscan-lite/heavy ├─► vuln DB (CVE→exploit)  ─┐
   vulndb lookups ────┘   red-ribbon graph.json  ─┼─► Mimir   (scan/correlate/stage)
                          exchange bundle ─────────┴─► Crucible (infra-recon around an AI)
```

How that handoff works: **[docs/integration.md](docs/integration.md)**.

---

## The scripts

### Service & config analysers (read-only)
| Script | Does |
| ------ | ---- |
| [`ssl/ssl-audit.sh`](ssl/ssl-audit.sh) | TLS posture + cert analysis; `--vuln` adds safe Heartbleed/CCS/POODLE/Logjam/SWEET32/ROBOT/ROCA probes → CVE refs. |
| [`ssh/ssh-audit.sh`](ssh/ssh-audit.sh) | SSH probe (banner, host-key fingerprints, weak KEX/cipher/MAC) + local `sshd_config` hardening review. |
| [`dns/dns-audit.sh`](dns/dns-audit.sh) | SPF/DKIM/DMARC/CAA/DNSSEC, AXFR, takeover hints; `--brute`/`--passive` subdomain discovery. |
| [`http/http-audit.sh`](http/http-audit.sh) | Security headers, cookies, http→https, WAF/CSP/CORS, `--methods`. |
| [`smb/smb-audit.sh`](smb/smb-audit.sh) | SMBv1, signing, null/guest, anon shares, OS/domain, RID/user enum. |
| [`ldap/ldap-audit.sh`](ldap/ldap-audit.sh) | Anon bind, rootDSE/naming contexts, LDAPS; signing probe is opt-in. |
| [`kerberos/kerb-audit.sh`](kerberos/kerb-audit.sh) | AS-REP roast, SPN discovery, pre-auth (user/cred checks opt-in). |
| [`smtp/mail-audit.sh`](smtp/mail-audit.sh) | STARTTLS, safe open-relay, VRFY/EXPN; user-enum opt-in. |
| [`snmp/snmp-audit.sh`](snmp/snmp-audit.sh) | v1/v2c/v3, sysDescr; community guessing opt-in (`--guess`). |
| [`ftp/ftp-audit.sh`](ftp/ftp-audit.sh) | Anon login, FTPS/AUTH TLS, bounce; backdoor checks opt-in. |
| [`db/db-audit.sh`](db/db-audit.sh) | Exposed DBs (Redis/Mongo/ES/MSSQL/MySQL/PG): no-auth / default-cred / TLS. |

### Appsec — web application scanners
| Script | Does |
| ------ | ---- |
| [`appsec/webscan-lite.sh`](appsec/webscan-lite.sh) | **Lite:** fast, passive posture scan — headers, cookies, CORS, tech fingerprint, page/login/forms, mixed content, a few well-known paths. A handful of requests. |
| [`appsec/webscan-heavy.sh`](appsec/webscan-heavy.sh) | **Heavy:** same-origin crawl + form/parameter/JS-endpoint extraction + content discovery, and opt-in (`--active`) **safe** injection *indicators* (reflected-marker XSS, SQL-error signature) — detection only, never exploitation. |

### Knowledge & intel
| Script | Does |
| ------ | ---- |
| [`vuln/cve-lookup.sh`](vuln/cve-lookup.sh) | Online NVD lookup: service `product+version` (or `nmap -sV`) → CVEs, CVSS-sorted. |
| [`vulndb/`](vulndb/) | **Offline CVE + public-exploit DB** (SQLite): `product+version → CVE → exploit`, version-range aware, EPSS/KEV. Shared read-only by Mimir & Crucible. See [vulndb/README.md](vulndb/README.md). |
| [`graph/graph-build.sh`](graph/graph-build.sh) | The **red ribbon**: analyser `--json` + vuln DB → one knowledge graph (Finding→CVE→Exploit→CWE). See [graph/README.md](graph/README.md). |
| [`installers/kali-arsenal.sh`](installers/kali-arsenal.sh) | Red-team tooling installer (`/opt/tools` + `~/tools`), profiles, `--list`/`--health`/`--dry-run`. |

### The console & glue (optional)
| Script | Does |
| ------ | ---- |
| [`webapp/`](webapp/) | **Arsenal Console** — a tiny local web GUI (`arsenal webapp`): run the analysers from a browser, collate findings, build a report, and export the engagement bundle to Mimir & Crucible. Localhost-only; argv-sandboxed. |
| [`bin/arsenal`](bin/arsenal) | Launcher: `arsenal <tool> …`, `arsenal list`, `arsenal help <tool>`. |
| [`engage/scope-guard.sh`](engage/scope-guard.sh) | Target allowlist — `check` / `filter` so a stray host never gets hit. |
| [`lib/report.sh`](lib/report.sh) | Collate `--json` output into one Markdown / CSV / text report. |

Every analyser prints readable output or `--json`, and exits `0` clean / `1` finding(s) / `2` usage error.

---

## Quick reference

```bash
arsenal list                                   # every tool
arsenal webapp                                 # the local console at http://127.0.0.1:8733
arsenal ssl   --vuln example.com               # TLS posture + safe vuln probes
arsenal webscan-lite  https://app.example.com  # fast appsec posture
arsenal webscan-heavy --active https://app.example.com   # deep crawl + safe injection indicators
arsenal vulndb openssh 9.2                     # offline CVE + public exploits
{ arsenal ssl --json h; arsenal webscan-lite --json https://h; } | arsenal graph --out ./g
```

Run any script with `--help` (or `arsenal help <tool>`) for its full options.

## Requirements

`bash` 4+ and coreutils everywhere; then per tool: `openssl` (ssl), `openssh-client`
(ssh), `curl`+`python3` (http/appsec/cve/vulndb/graph/webapp), `dig` preferred for
dns, `nmap` as the default backend for smb/ldap/kerberos/smtp/snmp/ftp/db. Optional
`NVD_API_KEY` for a reliable full vuln-DB build.

## CI

Every push runs `shellcheck -S warning` and `bash -n` on all `*.sh`
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Roadmap in
[`docs/roadmap.md`](docs/roadmap.md).

## License

[MIT](LICENSE).
