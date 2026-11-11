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
- `smb/smb-audit.sh` — dialects/SMBv1, signing, null/guest, shares, RID/user enum.
- `ldap/ldap-audit.sh` — anon bind, rootDSE/naming contexts, LDAPS.
- `kerberos/kerb-audit.sh` — AS-REP roast, SPN discovery, pre-auth (opt-in).
- `smtp/mail-audit.sh` — banner/STARTTLS, safe open-relay, VRFY/EXPN.
- `snmp/snmp-audit.sh` — community guessing, v1/v2c/v3, sysDescr.
- `ftp/ftp-audit.sh` — anon login, FTPS/AUTH TLS, bounce.
- `db/db-audit.sh` — exposed DB no-auth/default-cred/TLS (read-only).
- `vuln/cve-lookup.sh` — service version → CVEs (NVD, CPE matching).
- `vulndb/` — offline CVE+exploit knowledge base (shared with Mimir/Crucible).

## Next — analysers (read-only)
- **`tls/cert-expiry-monitor.sh`** — fan `ssl-audit --json` over a host list, emit only soon-to-expire/weak certs (cron + alert).
- **extend `http-audit`** — follow + report full redirect chain, CORS misconfig, `.well-known` inventory.
- **field-validate** the SMB/LDAP/Kerberos/SNMP/DB analysers against real services (they are built on nmap NSE + python fallbacks and verified for safety/syntax, but not yet live-fired against those services from this workstation).

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
