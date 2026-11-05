#!/usr/bin/env bash
# Kali/Parrot dependency installer. Run as your normal user: ./install.sh
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

log() { printf '\n[WebRaptor] %s\n' "$*"; }
die() { printf '\n[WebRaptor] ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: ./install.sh
Installs WebRaptor dependencies on Kali Linux or Parrot OS, installs Nuclei
templates, then runs --check-tools for all eight modules without scanning.
APT operations use sudo when needed. Python packages and upstream fallback
binaries are installed in this project's .venv/.tools directories.
After installation: source .venv/bin/activate
HELP
}
apt_install() { "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"; }
package_available() {
    apt-cache policy "$1" | awk '/Candidate:/ {found=1; if ($2 != "(none)") available=1} END {exit !(found && available)}'
}
install_distro_tool() {
    local executable="$1" package
    shift
    for package in "$@"; do
        if package_available "$package"; then
            log "Installing distro package: $package"
            apt_install "$package"
            return
        fi
    done
    # Preserve a working upstream installation if the distro lacks its package.
    if command -v "$executable" >/dev/null; then
        log "Using existing $executable: $(command -v "$executable")"
        return
    fi
    if [[ "$executable" == testssl ]] && command -v testssl.sh >/dev/null; then return; fi
    die "No package or executable found for $executable. Check your official Kali/Parrot apt sources."
}

wrap_distro_dirsearch() {
    # Kali's /usr/bin/dirsearch is a shell launcher using bare python3.
    # Keep its distro Python dependencies separate from WebRaptor's venv.
    local system_path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    local distro_dirsearch
    distro_dirsearch="$(PATH="$system_path" command -v dirsearch)" || die 'Distro Dirsearch executable is missing.'
    printf '#!/usr/bin/env bash\nexport PATH=%q\nexec %q "$@"\n' "$system_path" "$distro_dirsearch" > "$SCRIPT_DIR/.venv/bin/dirsearch"
    chmod +x "$SCRIPT_DIR/.venv/bin/dirsearch"
}

install_fixed_testssl() {
    # Upstream stable-branch fix for the TLS 1.3 post-handshake ticket race (#3188).
    local revision='216827365345f8abdb97c177636809a10e64fbe5'
    local checkout="$SCRIPT_DIR/.tools/testssl"
    log 'Installing pinned upstream testssl with the TLS 1.3 session-ticket fix'
    if [[ ! -d "$checkout/.git" ]]; then
        [[ ! -e "$checkout" ]] || die 'Unmanaged .tools/testssl exists; move it aside before installing.'
        mkdir -p "$SCRIPT_DIR/.tools"
        git clone --no-checkout --depth 1 --single-branch --branch 3.2 https://github.com/testssl/testssl.sh.git "$checkout"
    fi
    if ! git -C "$checkout" cat-file -e "$revision^{commit}" 2>/dev/null; then
        git -C "$checkout" fetch --depth 1 https://github.com/testssl/testssl.sh.git "$revision"
    fi
    git -C "$checkout" checkout --detach "$revision"
    [[ "$(git -C "$checkout" rev-parse HEAD)" == "$revision" ]] || die 'testssl revision verification failed.'
    [[ -x "$checkout/testssl.sh" ]] || die 'Pinned testssl executable is missing.'
    printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$checkout/testssl.sh" > "$SCRIPT_DIR/.venv/bin/testssl"
    chmod +x "$SCRIPT_DIR/.venv/bin/testssl"
}

go_compatible() {
    command -v go >/dev/null && "$PYTHON" -c '
import re,subprocess,sys
version=subprocess.check_output(["go","env","GOVERSION"],text=True).strip()
match=re.match(r"go(\d+)\.(\d+)",version)
sys.exit(0 if match and tuple(map(int,match.groups())) >= (1,21) else 1)
'
}
ensure_go() {
    if go_compatible; then return; fi
    if package_available golang-go; then
        log 'Installing the distro Go toolchain'
        apt_install golang-go
        hash -r
        if go_compatible; then return; fi
    fi
    log 'Installing the current stable Go toolchain from go.dev (SHA256 verified)'
    # Download metadata and the matching official Linux archive without executing
    # remote shell scripts, and never replace a system Go installation.
    "$PYTHON" - "$SCRIPT_DIR/.tools" <<'PY'
import hashlib,json,os,platform,re,sys,tarfile,tempfile,urllib.request
from pathlib import Path
root=Path(sys.argv[1]); root.mkdir(parents=True,exist_ok=True)
arch={'x86_64':'amd64','aarch64':'arm64','arm64':'arm64','i386':'386','i686':'386',
      'armv7l':'armv6l','armv6l':'armv6l','ppc64le':'ppc64le','s390x':'s390x','riscv64':'riscv64'}.get(platform.machine())
if not arch: raise SystemExit('Unsupported Go architecture: '+platform.machine())
with urllib.request.urlopen('https://go.dev/dl/?mode=json',timeout=60) as response:
    releases=json.load(response)
release=next(r for r in releases if r.get('stable'))
version=release['version']
if not re.fullmatch(r'go\d+\.\d+(?:\.\d+)?',version): raise SystemExit('Unexpected Go release version')
asset=next((f for f in release['files'] if f['os']=='linux' and f['arch']==arch and f['kind']=='archive'),None)
if asset is None: raise SystemExit('No official Go Linux archive for '+arch)
filename=asset['filename']
if not re.fullmatch(r'go[\w.\-]+\.tar\.gz',filename): raise SystemExit('Unexpected Go archive name')
parent=root/'go'/version
stamp=parent/'archive.sha256'
cached=(parent/'go/bin/go').is_file() and stamp.is_file() and stamp.read_text().strip()==asset['sha256']
if not cached:
    parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='webraptor-go-') as temp:
        archive=Path(temp)/filename
        with urllib.request.urlopen('https://go.dev/dl/'+filename,timeout=120) as response, archive.open('wb') as output:
            while True:
                block=response.read(1024*1024)
                if not block: break
                output.write(block)
        digest=hashlib.sha256()
        with archive.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''): digest.update(block)
        if digest.hexdigest()!=asset['sha256']: raise SystemExit('Go archive SHA256 mismatch')
        with tarfile.open(archive) as bundle:
            for member in bundle.getmembers():
                parts=Path(member.name).parts
                if not parts or parts[0]!='go' or '..' in parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise SystemExit('Unsafe Go archive member')
            bundle.extractall(parent)
        stamp.write_text(asset['sha256']+'\n')
(root/'go-path').write_text(str(parent/'go/bin')+'\n')
print('Installed '+version+' for Linux '+arch)
PY
    export PATH="$(cat "$SCRIPT_DIR/.tools/go-path"):$PATH"
}
install_go_tool() {
    local executable="$1" module="$2"
    if package_available "$executable"; then apt_install "$executable"; return; fi
    if command -v "$executable" >/dev/null; then
        log "Using existing $executable: $(command -v "$executable")"
        return
    fi
    ensure_go
    log "Building $executable from its official Go module"
    GOBIN="$SCRIPT_DIR/.venv/bin" GOTOOLCHAIN=auto go install "$module"
}
finish_install() {
log 'Installing/updating Nuclei templates (no target scan)'
nuclei -update-templates
log 'Checking all eight scanner versions and required CLI flags'
if ! "$PYTHON" "$SCRIPT_DIR/webraptor.py" --check-tools --modules curl,whatweb,nikto,waybackurls,dirsearch,nuclei,testssl,sslscan; then
    die 'One or more scanner checks failed. Review the version/flag diagnostics above; installation is not verified.'
fi
log 'All eight modules passed --check-tools.'
printf 'Next steps:\n  source %q\n  python %q --help\n' "$SCRIPT_DIR/.venv/bin/activate" "$SCRIPT_DIR/webraptor.py"

}

main() {
export LC_ALL=C
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then usage; exit 0; fi
[[ $# == 0 ]] || die 'Unknown argument; use --help.'
[[ "$(uname -s)" == Linux ]] || die 'This installer supports Kali Linux and Parrot OS, not macOS. No changes made.'
[[ -r /etc/os-release ]] || die '/etc/os-release is unavailable.'
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in kali|parrot) ;; *) die "Unsupported distribution: ${ID:-unknown}. Use Kali or Parrot." ;; esac
command -v apt-get >/dev/null || die 'apt-get is required.'
[[ -f "$SCRIPT_DIR/webraptor.py" && -f "$SCRIPT_DIR/requirements.txt" ]] || die 'Keep install.sh beside webraptor.py and requirements.txt.'

# Avoid leaving a normal user's checkout and environment owned by root when
# they invoke sudo ./install.sh. Only package installation needs elevation.
if [[ $EUID == 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    exec sudo -H -u "$SUDO_USER" -- bash "$SCRIPT_DIR/install.sh"
fi
SUDO=()
if [[ $EUID != 0 ]]; then
    command -v sudo >/dev/null || die 'Install sudo or run this script as root.'
    SUDO=(sudo)
    sudo -v
fi
trap 'printf "\n[WebRaptor] Installation stopped at line %s (exit %s). Fix the reported error and rerun ./install.sh.\n" "$LINENO" "$?" >&2' ERR
export PATH="$SCRIPT_DIR/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

log "Installing dependencies on ${PRETTY_NAME:-$ID}"
"${SUDO[@]}" apt-get update
apt_install ca-certificates python3 python3-venv python3-pip curl git \
    ruby \
    perl libnet-ssleay-perl libio-socket-ssl-perl libjson-perl \
    bash openssl dnsutils bsdextrautils procps build-essential pkg-config
python3 -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9 or later is required"'
if [[ -e "$SCRIPT_DIR/.venv" && ! -f "$SCRIPT_DIR/.venv/pyvenv.cfg" ]]; then
    die '.venv already exists but is not a Python virtual environment; move it aside and rerun.'
fi
python3 -m venv "$SCRIPT_DIR/.venv"
PYTHON="$SCRIPT_DIR/.venv/bin/python"
"$PYTHON" -c 'import sys; assert sys.platform == "linux", "Existing .venv is not a Linux environment; recreate it on this host"'
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt"

install_distro_tool whatweb whatweb
install_distro_tool nikto nikto
install_distro_tool testssl testssl.sh testssl
install_fixed_testssl
install_distro_tool sslscan sslscan
if package_available dirsearch; then
    apt_install dirsearch
    wrap_distro_dirsearch
elif ! command -v dirsearch >/dev/null; then
    log 'Installing Dirsearch in its own isolated Python environment'
    python3 -m venv "$SCRIPT_DIR/.tools/dirsearch"
    "$SCRIPT_DIR/.tools/dirsearch/bin/python" -m pip install --upgrade pip
    "$SCRIPT_DIR/.tools/dirsearch/bin/python" -m pip install 'dirsearch>=0.4.3,<1'
    ln -s "$SCRIPT_DIR/.tools/dirsearch/bin/dirsearch" "$SCRIPT_DIR/.venv/bin/dirsearch"
fi

install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
hash -r
finish_install

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
