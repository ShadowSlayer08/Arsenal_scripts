# Roadmap

Ideas for more **standalone, hand-run** helper scripts. Orchestration,
methodology and staging stay out of scope (that's Mimir) — everything here is a
point-tool a tester runs directly.

Conventions for every script: self-contained, read-only unless clearly an
installer, authorized-use only, human + `--json` output, exit `0`/`1`/`2`.

## Shipped
- `bin/arsenal` — dispatcher.
- `engage/scope-guard.sh` — scope allowlist & target gatekeeper.
- `lib/report.sh` — unified MD/CSV/TXT/JSON report builder.
- `ssl/ssl-audit.sh`, `ssh/ssh-audit.sh` — TLS & SSH analysers.
- `dns/dns-audit.sh` — SPF/DKIM/DMARC/CAA/DNSSEC/AXFR/takeover.
- `http/http-audit.sh` — security headers, cookies, exposure probes.
- `vuln/cve-lookup.sh` — service version → CVEs (NVD, CPE matching).

## Next — analysers (read-only)
- **`smtp/mail-audit.sh`** — MX reachability, STARTTLS, open-relay test, banner/PTR.
- **`tls/cert-expiry-monitor.sh`** — fan `ssl-audit --json` over a host list, emit only soon-to-expire/weak certs (cron + alert).
- **extend `http-audit`** — follow + report full redirect chain, CORS misconfig, `.well-known` inventory.

## Next — optional glue / post-processing
Each still runs by hand and stands alone; they just make results easier to reuse.
- **`recon/subdomain-sweep.sh`** — passive sources (crt.sh/CT) → resolve → liveness → a host list you can feed the analysers.
- **`recon/port-sweep.sh`** — wrap nmap/rustscan/masscan and print tidy `--json`.
- **`vuln/scan-normalize.sh`** — turn Nuclei/Nikto/testssl output into the same `--json` the analysers emit.
- **`engage/evidence-logger.sh`** — timestamped, hashed command/output logging for your notes and write-up.

## Next — active (needs scope-guard + evidence-logger first)
- **`creds/spray-wrapper.sh`** — password-spray wrapper with built-in lockout-safety caps and scope allowlist enforcement.
- **`creds/hash-triage.sh`** — identify hash types, drive Hashcat/John, report cracked ratio.
- **`postex/loot-parser.sh`** — normalize BloodHound/secretsdump/PEAS output into findings.
- **`postex/pivot-setup.sh`** — one-command ligolo-ng / sshuttle / chisel tunnels.

## Next — defensive
- **`installers/defensive-arsenal.sh`** — blue-team counterpart: Zeek, Suricata, tshark, Volatility, YARA, Sigma, osquery.

## Housekeeping
- **`kali-nova`** (local `kali-nova.tar.gz`) is a standalone desktop-theming
  project; it should get its **own repository**, not live here. It is gitignored.
