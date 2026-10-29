"""Installer control-flow tests; never install packages or contact the network."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'install.sh'


class InstallerTests(unittest.TestCase):
    def shell(self, code, *arguments):
        return subprocess.run(['bash', '-c', 'source "$1"\n' + code, 'test-installer', str(INSTALLER), *arguments],
                              capture_output=True, text=True, timeout=10)

    def test_syntax_and_sourcing_do_not_install(self):
        subprocess.run(['bash', '-n', str(INSTALLER)], check=True)
        run = self.shell('printf "sourced\\n"')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, 'sourced\n')

    def test_help_can_run_on_non_linux_hosts(self):
        run = subprocess.run(['bash', str(INSTALLER), '--help'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertIn('--check-tools', run.stdout)
        self.assertIn('without scanning', run.stdout)

    def test_unsupported_platform_exits_before_package_mutations(self):
        run = self.shell('uname() { printf "Darwin\\n"; }; apt-get() { echo SHOULD_NOT_RUN; }; main')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('No changes made', run.stderr)
        self.assertNotIn('SHOULD_NOT_RUN', run.stdout)

    def test_unknown_arguments_rejected(self):
        run = subprocess.run(['bash', str(INSTALLER), '--unknown'], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('Unknown argument', run.stderr)

    def test_apt_candidate_none_is_not_treated_as_available(self):
        run = self.shell('apt-cache() { printf "tool:\\n  Candidate: (none)\\n"; }; if package_available tool; then exit 99; fi')
        self.assertEqual(run.returncode, 0, run.stderr)
        run = self.shell('apt-cache() { printf "tool:\\n  Candidate: 1.2.3\\n"; }; package_available tool')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_testssl_package_alias_fallback(self):
        run = self.shell('''
package_available() { [[ "$1" == testssl ]]; }
apt_install() { printf 'INSTALL=%s\\n' "$*"; }
install_distro_tool testssl testssl.sh testssl
''')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('INSTALL=testssl\n', run.stdout)

    def test_go_fallback_uses_project_bin_and_official_module(self):
        with tempfile.TemporaryDirectory(prefix='installer path ') as temp:
            run = self.shell('''
SCRIPT_DIR="$2"
package_available() { return 1; }
command() { if [[ "$1" == -v && "$2" == waybackurls ]]; then return 1; fi; builtin command "$@"; }
ensure_go() { printf 'GO_READY\\n'; }
go() { printf 'GO_ARGS=%s\\nBIN=%s\\nTOOLCHAIN=%s\\n' "$*" "$GOBIN" "$GOTOOLCHAIN"; }
install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
''', temp)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('GO_ARGS=install github.com/tomnomnom/waybackurls@latest', run.stdout)
        self.assertIn('BIN=' + temp + '/.venv/bin', run.stdout)
        self.assertIn('TOOLCHAIN=auto', run.stdout)

    def test_available_go_package_skips_upstream_build(self):
        run = self.shell('''
package_available() { return 0; }
apt_install() { printf 'APT=%s\\n' "$*"; }
ensure_go() { exit 99; }
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
''')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('APT=nuclei', run.stdout)

    def test_failed_go_build_is_not_ignored(self):
        run = self.shell('''
package_available() { return 1; }
command() { if [[ "$1" == -v && "$2" == waybackurls ]]; then return 1; fi; builtin command "$@"; }
ensure_go() { :; }
go() { return 42; }
install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
printf SHOULD_NOT_RUN
''')
        self.assertEqual(run.returncode, 42)
        self.assertNotIn('SHOULD_NOT_RUN', run.stdout)

    def test_final_step_updates_templates_and_checks_all_eight_without_target(self):
        run = self.shell('''
nuclei() { printf 'NUCLEI=%s\\n' "$*"; }
check_python() { printf 'CHECK=%s\\n' "$*"; }
PYTHON=check_python
finish_install
''')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('NUCLEI=-update-templates', run.stdout)
        self.assertIn('--check-tools --modules curl,whatweb,nikto,waybackurls,dirsearch,nuclei,testssl,sslscan', run.stdout)
        self.assertIn('All eight modules passed', run.stdout)

    def test_final_check_failure_cannot_report_installation_verified(self):
        run = self.shell('''
nuclei() { :; }
check_python() { return 1; }
PYTHON=check_python
finish_install
''')
        self.assertEqual(run.returncode, 1)
        self.assertIn('installation is not verified', run.stderr)
        self.assertNotIn('All eight modules passed', run.stdout)

    def bootstrap(self, root, *, wrong_hash=False, unsafe_path=False):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as bundle:
            member = tarfile.TarInfo('../escaped' if unsafe_path else 'go/bin/go')
            data = b'fixture executable, never executed'
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
        archive = buffer.getvalue()
        digest = '0' * 64 if wrong_hash else hashlib.sha256(archive).hexdigest()
        metadata = [dict(version='go1.99.0', stable=True, files=[dict(
            filename='go1.99.0.linux-amd64.tar.gz', os='linux', arch='amd64', kind='archive', sha256=digest)])]
        source = INSTALLER.read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        def download(url, **unused):
            return io.BytesIO(json.dumps(metadata).encode() if '?mode=json' in url else archive)
        with patch('urllib.request.urlopen', side_effect=download), patch('platform.machine', return_value='x86_64'), patch('sys.argv', ['bootstrap', str(root)]):
            exec(compile(source, 'installer-go-bootstrap', 'exec'), {})

    def test_official_archive_checksum_is_verified_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'tools'
            with self.assertRaisesRegex(SystemExit, 'SHA256 mismatch'):
                self.bootstrap(root, wrong_hash=True)
            self.assertFalse((root / 'go/go1.99.0/go/bin/go').exists())
            self.assertFalse((root / 'go/go1.99.0/archive.sha256').exists())

    def test_archive_paths_cannot_escape_install_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(SystemExit, 'Unsafe Go archive'):
                self.bootstrap(Path(temp) / 'tools', unsafe_path=True)
            self.assertFalse(any(Path(temp).rglob('escaped')))

    def test_verified_archive_is_cached_locally(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'tools'
            self.bootstrap(root)
            self.assertTrue((root / 'go/go1.99.0/archive.sha256').is_file())
            self.assertEqual((root / 'go-path').read_text().strip(), str(root / 'go/go1.99.0/go/bin'))
