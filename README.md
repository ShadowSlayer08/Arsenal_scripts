# Arsenal_scripts

A grab-bag of **standalone shell scripts** that help with **manual** pentesting,
VAPT, red teaming, and configuration review. Each one does a single job, runs by
hand, and is useful on its own — copy one onto a box and run it.

> ⚠️ **Authorized use only.** For your own systems, lab/CTF environments, or
> engagements where you have **explicit written permission**. The installer
> stages offensive tooling; the analysers make ordinary, read-only connections.
> You are responsible for how you use them.

> **Scope.** These are hand-run helpers, not a platform. Engagement
> orchestration, methodology and staging are intentionally **out of scope** —
> that's what [Mimir](https://github.com/ShadowSlayer08/Mimir) is for. Reach for
> these when you want a quick, focused answer during manual testing.

---

## The scripts

| Script | Does |
| ------ | ---- |
| [`ssl/ssl-audit.sh`](ssl/ssl-audit.sh) | TLS posture + certificate analysis: chain, SANs, expiry, key (RSA/EC aware), protocols SSLv3–TLS1.3, STARTTLS. |
| [`ssh/ssh-audit.sh`](ssh/ssh-audit.sh) | SSH server probe (banner, host-key fingerprints, offered KEX/cipher/MAC/host-key algos) and local `sshd_config` hardening review. |
| [`dns/dns-audit.sh`](dns/dns-audit.sh) | DNS hygiene: SPF/DKIM/DMARC/CAA/DNSSEC, AXFR zone-transfer test, dangling-CNAME / takeover hints. |
| [`http/http-audit.sh`](http/http-audit.sh) | HTTP security headers, cookie flags, http→https enforcement, version disclosure, sensitive-path checks. |
| [`smb/smb-audit.sh`](smb/smb-audit.sh) | SMB/NetBIOS/RPC: dialects + SMBv1, signing (relay risk), null/guest sessions, anon-readable/writable shares, OS/domain, RID/user enum. |
| [`ldap/ldap-audit.sh`](ldap/ldap-audit.sh) | LDAP anonymous bind, rootDSE / naming contexts, domain functional level, anon user/group enum, LDAPS/StartTLS. |
| [`kerberos/kerb-audit.sh`](kerberos/kerb-audit.sh) | Kerberos: AS-REP-roastable users, SPN discovery, pre-auth status (user/cred checks are opt-in). |
| [`smtp/mail-audit.sh`](smtp/mail-audit.sh) | SMTP banner/version, STARTTLS + cert, **safe** non-delivering open-relay probe, VRFY/EXPN; user-enum is opt-in. |
| [`snmp/snmp-audit.sh`](snmp/snmp-audit.sh) | SNMP community guessing (small default list), v1/v2c/v3, sysDescr; writable-community test is opt-in. |
| [`ftp/ftp-audit.sh`](ftp/ftp-audit.sh) | FTP banner, anonymous login, FTPS/AUTH TLS, bounce (FXP); backdoor checks are opt-in. |
| [`db/db-audit.sh`](db/db-audit.sh) | Exposed databases (Redis/MongoDB/Elasticsearch/MSSQL/MySQL/Postgres): no-auth / default-cred / TLS, read-only (writes need `--unsafe`). |
| [`vuln/cve-lookup.sh`](vuln/cve-lookup.sh) | Look up CVEs for a service `product + version` (or `nmap -sV` output) via NVD, CVSS-sorted (online). |
| [`vulndb/`](vulndb/) | **Offline CVE + public-exploit knowledge base** (SQLite). `vulndb-build` ingests NVD/KEV/EPSS/Exploit-DB/Metasploit/nuclei; `vulndb` maps `product+version → CVE → exploit`, version-range aware. Shared read-only by **Mimir & Crucible**. See [vulndb/README.md](vulndb/README.md). |
| [`installers/kali-arsenal.sh`](installers/kali-arsenal.sh) | Idempotent red-team tooling installer (`/opt/tools` + `~/tools`), engagement profiles, `--list`/`--health`/`--dry-run`. |

Small conveniences, entirely optional — ignore them and the scripts above still
work standalone:

| Script | Does |
| ------ | ---- |
| [`bin/arsenal`](bin/arsenal) | Launcher so you can type `arsenal ssl …` instead of the full path. `arsenal list`, `arsenal help <tool>`. |
| [`engage/scope-guard.sh`](engage/scope-guard.sh) | A target allowlist you can check a host against before you touch it (`check` / `filter`), so a stray host in a list doesn't get hit. |
| [`lib/report.sh`](lib/report.sh) | Collate the `--json` output of the analysers into one Markdown / CSV / text table when you're writing up. |
| [`graph/graph-build.sh`](graph/graph-build.sh) | Weave analyser `--json` + the vuln DB into one knowledge graph (Finding→CVE→Exploit→CWE), enriched from the shared DB and ingestible by graphify / Mimir / Crucible. See [graph/README.md](graph/README.md). |

Each analyser prints readable output or `--json` (for your own notes or
scripting), and exits `0` clean / `1` finding(s) / `2` usage error.

---

## Requirements

- **Common:** `bash` 4+, coreutils.
- **ssl:** `openssl` (optional `nmap` for `--ciphers`).
- **ssh:** `openssh-client` (optional `nmap`).
- **dns:** `dig` preferred; falls back to `python3` (built-in resolver) or `nslookup`.
- **http:** `curl`.
- **cve:** `curl` + `python3`; optional `NVD_API_KEY` env var raises the rate limit.
- **report:** `python3`.
- **installer:** a Debian/Kali box with `apt`.

---

## Quick reference

```bash
ssl/ssl-audit.sh   example.com[:443] | -f hosts.txt | --json | --starttls smtp host:25
ssh/ssh-audit.sh   host[:22]         | --local [--config FILE] | --json
dns/dns-audit.sh   example.com       | -f domains.txt | --json | --no-axfr
http/http-audit.sh https://host/path | -f urls.txt | --json | --no-probe
vuln/cve-lookup.sh openssh 9.2       | --cpe "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*" | --from-nmap
```

Run any script with `--help` (or `arsenal help <tool>`) for its full options.

Example config review during an engagement:

```bash
ssh/ssh-audit.sh --local                      # review this box's sshd_config
ssl/ssl-audit.sh --json internal.example > tls.json   # keep the raw result for your notes
```

---

## Roadmap

Ideas for more helper scripts live in [`docs/roadmap.md`](docs/roadmap.md).

## Contributing / CI

Every push runs `shellcheck -S warning` and `bash -n` on all `*.sh`
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Keep scripts
shellcheck-clean and self-contained.

## License

[MIT](LICENSE).
