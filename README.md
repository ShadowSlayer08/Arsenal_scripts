# Arsenal_scripts

A collection of self-contained shell scripts for building out and assessing a
security testing workstation — tool installers plus read-only analysers for
common network services.

> ⚠️ **Authorized use only.** These scripts are for your own systems, lab/CTF
> environments, or engagements where you have **explicit written permission**.
> The installer stages offensive/red-team tooling; the analysers make ordinary,
> read-only connections. You are responsible for how you use them.

---

## What's here

| Script | What it does |
| ------ | ------------ |
| [`installers/kali-arsenal.sh`](installers/kali-arsenal.sh) | Idempotent installer that stages red-team / pentest tooling into `/opt/tools` and portable transfer binaries into `~/tools`, with apt-first installs and release/git fallbacks. Engagement profiles (`recon`/`web`/`ad`/`full`), `--list`, `--health`, `--dry-run`. |
| [`ssl/ssl-audit.sh`](ssl/ssl-audit.sh) | TLS/SSL posture checker. Reports the certificate chain, SANs, validity window and days-to-expiry, key size, signature algorithm, hostname match, and which protocols (SSLv3–TLS 1.3) respond — flagging expired/self-signed certs, weak keys/sigs, and deprecated protocols. Text or `--json`. |
| [`ssh/ssh-audit.sh`](ssh/ssh-audit.sh) | SSH assessor with two modes: **remote** probe (banner, host-key fingerprints, offered KEX/host-key/cipher/MAC algorithms, flagging weak ones) and **local** `sshd_config` hardening audit against a baseline. Text or `--json`. |

Every script is standalone — no shared library to source — so you can copy or
`curl` a single file onto a box and run it.

---

## Requirements

- **Common:** `bash` 4+, coreutils.
- **ssl-audit:** `openssl`. Optional `nmap` for `--ciphers`.
- **ssh-audit:** `openssh-client` (`ssh`, `ssh-keyscan`, `ssh-keygen`). Optional `nmap` for authoritative algorithm lists.
- **kali-arsenal:** a Debian/Kali-family box with `apt`; run as your normal user (it uses `sudo` internally only for `apt` and `/opt`).

---

## Usage

### TLS / certificate audit
```bash
ssl/ssl-audit.sh example.com                 # defaults to :443
ssl/ssl-audit.sh example.com:8443
ssl/ssl-audit.sh -f hosts.txt                # one host[:port] per line
ssl/ssl-audit.sh --json example.com          # machine-readable
ssl/ssl-audit.sh --starttls smtp mail.example.com:25
```

### SSH audit
```bash
ssh/ssh-audit.sh host.example.com            # remote probe, port 22
ssh/ssh-audit.sh host.example.com:2222
ssh/ssh-audit.sh --local                     # audit /etc/ssh/sshd_config
ssh/ssh-audit.sh --local --config ./sshd_config
ssh/ssh-audit.sh --json host.example.com
```

Both analysers exit `0` when healthy, `1` when a problem/weakness is found, and
`2` on usage errors — handy in CI or cron monitoring.

### Tooling installer
```bash
installers/kali-arsenal.sh --list            # see the catalog, install nothing
installers/kali-arsenal.sh --health          # check what's already present
installers/kali-arsenal.sh --dry-run --all   # show what --all would do
installers/kali-arsenal.sh --profile recon   # recon|web|ad|full
```

---

## Roadmap

Planned additions are tracked in [`docs/roadmap.md`](docs/roadmap.md).

## Contributing / CI

Every push runs `shellcheck` and `bash -n` on all `*.sh` files
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Keep scripts
shellcheck-clean (`-S warning`) and self-contained.

## License

[MIT](LICENSE).
