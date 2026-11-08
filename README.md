# Arsenal_scripts

A toolkit of self-contained shell scripts for VAPT / red-team work: a tooling
installer, read-only service analysers, an engagement scope gatekeeper, a CVE
mapper, and a unified reporter — all speaking one `--json` schema so they chain
into one deliverable.

> ⚠️ **Authorized use only.** For your own systems, lab/CTF environments, or
> engagements where you have **explicit written permission**. The installer
> stages offensive tooling; the analysers make ordinary, read-only connections;
> `scope-guard` exists to keep automation inside the agreed targets. You are
> responsible for how you use them.

---

## What's here

| Tool | Type | What it does |
| ---- | ---- | ------------ |
| [`bin/arsenal`](bin/arsenal) | dispatcher | Front-end: `arsenal <tool> [args]`, `arsenal list`, `arsenal help <tool>`. |
| [`engage/scope-guard.sh`](engage/scope-guard.sh) | gatekeeper | Engagement scope allowlist (CIDR/domain/host + exclusions). `check`/`filter` targets so automation can't stray off-scope. Fail-closed. |
| [`ssl/ssl-audit.sh`](ssl/ssl-audit.sh) | analyser | TLS posture + certificate analysis: chain, SANs, expiry, key (RSA/EC aware), protocols SSLv3–TLS1.3, STARTTLS. |
| [`ssh/ssh-audit.sh`](ssh/ssh-audit.sh) | analyser | SSH remote probe (banner, host-key fingerprints, offered KEX/cipher/MAC/host-key algos) + local `sshd_config` hardening audit. |
| [`dns/dns-audit.sh`](dns/dns-audit.sh) | analyser | DNS hygiene: SPF/DKIM/DMARC/CAA/DNSSEC, AXFR zone-transfer test, dangling-CNAME/takeover hints. `dig`→`python3`→`nslookup` backends. |
| [`http/http-audit.sh`](http/http-audit.sh) | analyser | HTTP security headers, cookie flags, http→https enforcement, version disclosure, sensitive-path exposure (with soft-404 baseline). |
| [`vuln/cve-lookup.sh`](vuln/cve-lookup.sh) | orchestrator | Map a service `product+version` (or `nmap -sV`) to CVEs via NVD, CVSS-sorted, using CPE version matching. |
| [`lib/report.sh`](lib/report.sh) | reporter | Ingest any analyser's `--json` and render a consolidated Markdown / CSV / text / JSON report. |
| [`installers/kali-arsenal.sh`](installers/kali-arsenal.sh) | installer | Idempotent red-team tooling installer (`/opt/tools` + `~/tools`), engagement profiles, `--list`/`--health`/`--dry-run`. |

Each analyser is standalone (no shared library to source), prints human output
or `--json`, and exits `0` healthy / `1` finding(s) / `2` usage error — so they
drop straight into pipelines, cron, and CI.

---

## The workflow it's built for

```bash
# 1. define the engagement scope once
arsenal scope init                        # writes ./.arsenal-scope; edit it
arsenal scope add example.com

# 2. only assess in-scope hosts, collect every tool's JSON
printf 'example.com\nsub.example.com\nevil.com\n' | arsenal scope filter > targets.txt

{
  while read -r t; do arsenal ssl  --json "$t"; done < targets.txt
  arsenal dns  --json -f targets.txt
  while read -r t; do arsenal http --json "$t"; done < targets.txt
} > findings.jsonl

# 3. map discovered service versions to CVEs (e.g. from nmap -sV)
nmap -sV -oG - example.com | arsenal cve --from-nmap --json >> findings.jsonl

# 4. render one report
arsenal report --title "example.com assessment" --format md findings.jsonl > report.md
```

---

## Requirements

- **Common:** `bash` 4+, coreutils.
- **ssl:** `openssl` (optional `nmap` for `--ciphers`).
- **ssh:** `openssh-client` (optional `nmap`).
- **dns:** `dig` preferred; falls back to `python3` (built-in UDP/TCP resolver) or `nslookup`.
- **http:** `curl`.
- **cve:** `curl` + `python3`; optional `NVD_API_KEY` env var raises the rate limit.
- **report:** `python3`.
- **installer:** a Debian/Kali box with `apt`.

---

## Per-tool quick reference

```bash
arsenal ssl    example.com[:443] | -f hosts.txt | --json | --starttls smtp host:25
arsenal ssh    host[:22]         | --local [--config FILE] | --json
arsenal dns    example.com       | -f domains.txt | --json | --no-axfr | --dkim-selectors a,b
arsenal http   https://host/path | -f urls.txt | --json | --no-probe
arsenal cve    openssh 9.2       | --cpe "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*" | --from-nmap | --min-score 7
arsenal scope  init|add|list|check <target>|filter
arsenal report [--format md|csv|txt|json] [--title T] [--only-findings] [files...]
```

Run `arsenal help <tool>` (or `<script> --help`) for full options.

---

## Roadmap

Further script ideas and sequencing live in [`docs/roadmap.md`](docs/roadmap.md).

## Contributing / CI

Every push runs `shellcheck -S warning` and `bash -n` on all `*.sh`
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Keep scripts
shellcheck-clean and self-contained.

## License

[MIT](LICENSE).
