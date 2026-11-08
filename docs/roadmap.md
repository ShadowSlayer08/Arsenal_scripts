# Roadmap — suggested scripts

Candidate additions for the arsenal, grouped by theme. These keep the repo's
rule: self-contained, read-only unless clearly an installer, authorized-use
only, text + `--json` output, meaningful exit codes.

## Service / posture analysers (read-only)
- **`dns/dns-audit.sh`** — zone hygiene: SPF/DKIM/DMARC presence & syntax,
  CAA records, DNSSEC chain, open resolver / zone-transfer (`AXFR`) check,
  dangling CNAME (subdomain-takeover) hints.
- **`http/http-audit.sh`** — security headers (HSTS, CSP, X-Frame-Options,
  referrer/permissions policy), cookie flags (`Secure`/`HttpOnly`/`SameSite`),
  redirect chain, server/version disclosure, TLS redirect enforcement.
- **`smtp/mail-audit.sh`** — MX reachability, STARTTLS support, open-relay
  test, banner/version, reverse-DNS/PTR consistency.
- **`tls/cert-expiry-monitor.sh`** — thin wrapper over `ssl-audit --json` that
  fans out over a host list and emits only soon-to-expire certs (cron-friendly).

## Workstation setup / installers
- **`installers/defensive-arsenal.sh`** — blue-team counterpart: Zeek, Suricata,
  Wireshark/tshark, Volatility, YARA, Sigma, osquery.
- **`installers/common-base.sh`** — shell/editor/tmux/zsh baseline + QoL (the
  `kali-nova` theming project is a natural home for this; see note below).

## Reporting / glue
- **`lib/report.sh`** — shared Markdown/CSV emitter so analysers can produce a
  single engagement report. (Would be the one place scripts `source`.)
- **`bin/arsenal`** — a tiny dispatcher (`arsenal ssl …`, `arsenal ssh …`).

## Housekeeping notes
- **`kali-nova`** (currently the local `kali-nova.tar.gz`) is a full
  standalone desktop-theming/setup project with its own README/LICENSE/CI.
  It's gitignored here and should live in its **own repository**, linked from
  this README, rather than vendored into a security-scripts collection.
