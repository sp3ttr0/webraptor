import contextlib
import hashlib
import ast
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import httpx

REAL_CURL = shutil.which('curl')
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('webraptor', ROOT / 'webraptor.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class UnitTests(unittest.TestCase):
    def test_original_banner_is_unchanged(self):
        source = (ROOT / 'webraptor.py').read_text()
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'print_banner')
        self.assertEqual(hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest(), 'a6cf74a7ec99af7f79834720753b9e095814fc8cbeafc53dbcb6e19cae391227')

    def test_exclude_default_and_explicit_selection(self):
        args = w.parse_args(['example.com', '--exclude', 'nikto, dirsearch', '--exclude', 'nikto'])
        self.assertEqual(args.modules, [m for m in w.MODULES if m not in ('nikto', 'dirsearch')])
        args = w.parse_args(['example.com', '--modules', 'curl,nuclei,whatweb', '--exclude', 'nuclei,sslscan'])
        self.assertEqual(args.modules, ['curl', 'whatweb'])
        for excluded in ('unknown', '', 'curl,', ','.join(w.MODULES)):
            with self.subTest(excluded=excluded), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    w.parse_args(['example.com', '--exclude', excluded])
                self.assertEqual(caught.exception.code, 2)

    def test_excluded_dependencies_are_not_checked(self):
        excluded = ','.join(m for m in w.MODULES if m != 'curl')
        with patch.object(w.shutil, 'which', return_value=None) as which, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(w.main(['example.com', '--exclude', excluded]), 1)
        self.assertEqual([call.args[0] for call in which.call_args_list], ['curl'])

    def test_progress_states_and_no_secret_urls(self):
        stream = io.StringIO()
        target = 'https://example.com/private?token=secret-token'
        with contextlib.redirect_stderr(stream), w.Progress([(target, True)], ['curl'], interval=.01) as progress:
            progress.update(target, 'curl', 'running')
            progress.render()
            progress.update(target, 'curl', 'completed')
        text = stream.getvalue()
        self.assertIn('queued=1', text)
        self.assertIn('running=1', text)
        self.assertIn('completed=1', text)
        self.assertNotIn('secret-token', text)
        quiet = io.StringIO()
        with contextlib.redirect_stderr(quiet), w.Progress([(target, True)], ['curl'], enabled=False) as progress:
            progress.update(target, 'curl', 'running')
        self.assertEqual(quiet.getvalue(), '')

    def test_normalization_and_deduplication(self):
        with tempfile.TemporaryDirectory() as temp:
            targets = Path(temp) / 'targets.txt'
            targets.write_text('# comment\nExample.COM\nhttps://example.com:443/\nhttp://example.com\n')
            args = w.parse_args(['-l', str(targets)])
            self.assertEqual(args.targets, [('https://example.com/', True), ('http://example.com/', True)])
        self.assertEqual(w.normalize_target('[::1]:8080')[0], 'https://[::1]:8080/')

    def test_invalid_arguments(self):
        for args in ([], ['example.com', '--threads', '0'], ['example.com', '--tool-timeout', 'nan'],
                     ['ftp://example.com'], ['https://u:p@example.com'], ['--modules', 'oops', 'example.com'],
                     ['https://example.com:0'], ['-H', 'Authorization: secret\nInjected: x', 'example.com']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    w.parse_args(args)
                self.assertEqual(caught.exception.code, 2)

    def test_authenticated_batch_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'targets'
            path.write_text('one.test\ntwo.test\n')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                w.parse_args(['-l', str(path), '-H', 'Authorization: Bearer private-token'])

    def test_scheme_and_tls_options(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.scheme == 'https':
                raise httpx.ConnectError('certificate failure')
            return httpx.Response(403)
        real_client = httpx.Client
        def client(**kwargs):
            self.assertFalse(kwargs['follow_redirects'])
            self.assertFalse(kwargs['verify'])
            return real_client(transport=httpx.MockTransport(handler), **kwargs)
        args = w.parse_args(['https://example.com', '--insecure', '-H', 'Authorization: Bearer secret-value'])
        with patch.object(w.httpx, 'Client', side_effect=client):
            self.assertIsNone(w.probe_target('https://example.com/', True, args, threading.Event())[0])
            self.assertEqual(len(requests), 1)
            args.allow_scheme_fallback = True
            target, info = w.probe_target('https://example.com/', True, args, threading.Event())
        self.assertEqual(target, 'http://example.com/')
        self.assertEqual(info['http_status'], 403)
        self.assertTrue(info['scheme_changed'])
        self.assertEqual(requests[-1].headers['authorization'], 'Bearer secret-value')

    def test_header_files_and_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            headers = Path(temp) / 'headers'
            headers.write_text('Authorization: Bearer secret-token\nX-Api-Key: api-value\n')
            cookie = Path(temp) / 'cookie'
            cookie.write_text('session=cookie-value; other=second-value\n')
            args = w.parse_args(['example.com', '--headers-file', str(headers), '--cookie-file', str(cookie)])
            redactor = w.Redactor(args.headers)
            text = redactor('secret-token api-value cookie-value second-value\nSet-Cookie: new-secret\n')
            for secret in ('secret-token', 'api-value', 'cookie-value', 'second-value', 'new-secret'):
                self.assertNotIn(secret, text)
            value = {'request': 'Authorization: Bearer secret-token\r\nCookie: session=cookie-value'}
            self.assertIsInstance(json.loads(redactor(json.dumps(value))), dict)

    def test_adapter_arguments(self):
        args = w.parse_args(['https://example.com/path', '-H', 'Authorization: Bearer secret-token'])
        with tempfile.TemporaryDirectory() as temp:
            commands = {m: w.build_command(m, 'https://example.com/path', Path(temp), args)[0] for m in w.MODULES}
        self.assertEqual(commands['curl'][:6], ['curl', '--disable', '--head', '--silent', '--show-error', '--url'])
        self.assertIn('--location', commands['curl'])
        self.assertNotIn('--insecure', commands['curl'])
        self.assertEqual(commands['waybackurls'], ['waybackurls', 'example.com'])
        self.assertIn('-rate-limit', commands['nuclei'])
        self.assertIn('-jsonl', commands['nuclei'])
        self.assertNotIn('-etags', commands['nuclei'])
        self.assertIn('--max-rate', commands['dirsearch'])
        self.assertNotIn('-F', commands['dirsearch'])
        self.assertIn('-Add-header', commands['nikto'])
        self.assertEqual(commands['testssl'][-1], 'example.com:443')
        self.assertIn('--reqheader', commands['testssl'])
        self.assertEqual(commands['sslscan'], ['sslscan', '--no-colour', 'example.com:443'])
        for module in w.AUTH_MODULES:
            self.assertIn('Authorization: Bearer secret-token', commands[module])
        self.assertNotIn('Authorization: Bearer secret-token', commands['waybackurls'])

    def test_tls_endpoint_and_executable_alias(self):
        self.assertEqual(w.tls_endpoint('https://example.com:8443/path?x=y'), 'example.com:8443')
        self.assertEqual(w.tls_endpoint('https://[::1]:9443/path'), '[::1]:9443')
        with patch.object(w.shutil, 'which', side_effect=lambda name: '/tools/testssl.sh' if name == 'testssl.sh' else None):
            self.assertEqual(w.tool_executable('testssl'), '/tools/testssl.sh')

    def test_output_names_are_bounded_and_collision_resistant(self):
        self.assertNotEqual(w.target_key('https://example.com/a?b=c'), w.target_key('https://example.com/a_b=c'))
        self.assertLess(len(w.target_key('https://example.com/' + 'a' * 10000)), 100)

    def test_selected_dependencies_only(self):
        with patch.object(w.shutil, 'which', return_value=None) as which, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(w.main(['example.com', '--modules', 'nuclei']), 1)
        self.assertEqual([call.args[0] for call in which.call_args_list], ['nuclei'])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        source = (ROOT / 'tests' / 'fake_scanner.py').read_text()
        for module in w.MODULES:
            tool = self.bin / module
            tool.write_text('#!' + sys.executable + '\n' + source)
            tool.chmod(0o700)
        self.environment = patch.dict(os.environ, {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'WEBRAPTOR_TEST_MODE': 'success'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        # Scanner workflow tests use dummy tools; automatic verification has its
        # own real HTTP/TLS integration coverage in test_verification.py.
        self.verifier = patch.object(w, 'verify_target', return_value={'status': 'completed', 'checks': []})
        self.verification_mock = self.verifier.start()
        self.addCleanup(self.verifier.stop)
        w.STOP.clear()

    def run_main(self, *extra):
        with patch.object(w, 'probe_target', side_effect=lambda target, *a: (target, {'status': 'reachable', 'http_status': 200})), contextlib.redirect_stdout(io.StringIO()):
            return w.main(['https://example.com', '--output-dir', str(self.root / 'results'), *extra])

    def summaries(self):
        return [json.loads(p.read_text()) for p in (self.root / 'results').glob('*/2*/summary.json') if p.parent.parent.name != '_runs']


    def start_http_fixture(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(dict(self.headers))
                self.send_response(403)
                self.end_headers()
            def do_HEAD(self):
                requests.append(dict(self.headers, method='HEAD'))
                if self.path in ('/redirect', '/loop'):
                    self.send_response(302)
                    self.send_header('Location', '/loop' if self.path == '/loop' else '/final')
                else:
                    self.send_response(403)
                self.send_header('X-WebRaptor-Test', 'head-response')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)
        return 'http://127.0.0.1:' + str(server.server_port), requests

    @unittest.skipUnless(REAL_CURL, 'curl executable is required')
    def test_real_curl_head_output(self):
        target, requests = self.start_http_fixture()
        args = w.parse_args([target, '--modules', 'curl', '-H', 'Authorization: Bearer head-test-token'])
        folder = self.root / 'curl-run'
        folder.mkdir()
        original_builder = w.build_command
        def builder(*arguments):
            cmd, artifact = original_builder(*arguments)
            cmd[0] = REAL_CURL
            return cmd, artifact
        with patch.object(w, 'build_command', side_effect=builder):
            result = w.execute_module('curl', target, folder, args, threading.BoundedSemaphore(1), threading.Event(), w.Redactor(args.headers))
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(requests[0]['method'], 'HEAD')
        self.assertEqual(requests[0]['Authorization'], 'Bearer head-test-token')
        self.assertEqual(len(requests), 1)
        output = (folder / 'curl_results.txt').read_text()
        self.assertIn('403', output)
        self.assertIn('X-WebRaptor-Test: head-response', output)
        self.assertIn('curl_results.txt', result['artifacts'])
        args.insecure = True
        self.assertIn('--insecure', w.build_command('curl', target, folder, args)[0])

    @unittest.skipUnless(REAL_CURL, 'curl executable is required')
    def test_curl_redirect_chain_and_loop_limit(self):
        target, requests = self.start_http_fixture()
        args = w.parse_args([target, '--modules', 'curl'])
        for route, status in (('/redirect', 'completed'), ('/loop', 'failed')):
            with self.subTest(route=route):
                requests.clear()
                cmd, artifact = w.build_command('curl', target + route, self.root, args)
                cmd[0] = REAL_CURL
                result = w.run_command(cmd, artifact, self.root / 'curl-error.log', 10, threading.Event(), w.Redactor())
                self.assertEqual(result['status'], status)
                self.assertTrue(all(r['method'] == 'HEAD' for r in requests))
                output = artifact.read_text()
                self.assertIn('302', output)
                if route == '/redirect':
                    self.assertEqual(len(requests), 2)
                    self.assertIn('403', output)
                    self.assertIn('Location: /final', output)
                else:
                    self.assertEqual(result['exit_code'], 47)
                    self.assertLessEqual(len(requests), 11)

    def test_real_http_probe_and_cli(self):
        target, requests = self.start_http_fixture()
        result = subprocess.run([sys.executable, str(ROOT / 'webraptor.py'), target,
            '--modules', 'whatweb,nuclei', '--output-dir', str(self.root / 'results'),
            '-H', 'Authorization: Bearer local-test-token'], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests[0]['Authorization'], 'Bearer local-test-token')
        self.assertEqual(self.summaries()[0]['probe']['http_status'], 403)
        self.assertNotIn('local-test-token', result.stdout + result.stderr)

    def test_real_sigterm_exit_code_and_report(self):
        target, _ = self.start_http_fixture()
        events = self.root / 'events'
        environment = dict(os.environ, WEBRAPTOR_TEST_MODE='hang', WEBRAPTOR_TEST_EVENTS=str(events))
        proc = subprocess.Popen([sys.executable, str(ROOT / 'webraptor.py'), target,
            '--modules', 'whatweb,nikto', '--threads', '1', '--output-dir', str(self.root / 'results')],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not events.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(events.exists())
            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 130, stdout + stderr)
            self.assertEqual(self.summaries()[0]['status'], 'cancelled')
            modules = self.summaries()[0]['modules']
            self.assertTrue(all(m['status'] == 'cancelled' for m in modules), modules)
            self.assertEqual(len(events.read_text().splitlines()), 1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def manifest(self):
        return sorted((self.root / 'results' / '_runs').glob('*/run.json'))[-1]

    def resume(self, manifest, *extra):
        with patch.object(w, 'probe_target', side_effect=lambda target, *a: (target, {'status': 'reachable'})), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return w.main(['--resume', str(manifest), '--no-progress', *extra])

    def test_check_tools_without_target_or_network(self):
        output = io.StringIO()
        with patch.object(w, 'probe_target') as probe, contextlib.redirect_stdout(output):
            self.assertEqual(w.main(['--check-tools']), 0)
        probe.assert_not_called()
        self.assertIn('nuclei: OK', output.getvalue())
        self.assertFalse((self.root / 'results').exists())
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_HELP': 'missing'}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(['--check-tools', '--modules', 'curl']), 1)

    def test_resume_preserves_completed_and_retries_failed(self):
        events = self.root / 'events'
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_FAIL_MODULE': 'nikto'}):
            self.assertEqual(self.run_main('--modules', 'curl,nikto', '--no-progress'), 1)
        old = self.summaries()[0]
        original = Path(old['run_directory']) / 'curl_results.txt'
        before = original.read_bytes()
        manifest = self.manifest()
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_EVENTS': str(events)}):
            self.assertEqual(self.resume(manifest, '--tool-timeout', '60'), 0)
        starts = [json.loads(line)['module'] for line in events.read_text().splitlines() if json.loads(line)['event'] == 'start']
        self.assertEqual(starts, ['nikto'])
        latest = sorted(self.summaries(), key=lambda r: r['started_at'])[-1]
        self.assertIn('reused_from', latest['modules'][0])
        self.assertEqual(original.read_bytes(), before)
        self.assertNotEqual(latest['run_directory'], old['run_directory'])

    def test_resume_modified_output_reruns_and_auth_is_not_saved(self):
        self.assertEqual(self.run_main('--modules', 'curl', '--no-progress', '-H', 'Authorization: Bearer private-resume-token'), 0)
        manifest = self.manifest()
        self.assertNotIn('private-resume-token', manifest.read_text())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            w.parse_args(['--resume', str(manifest)])
        (Path(self.summaries()[0]['run_directory']) / 'curl_results.txt').write_text('modified')
        self.assertEqual(self.resume(manifest, '-H', 'Authorization: Bearer new-session-token'), 0)
        latest = sorted(self.summaries(), key=lambda r: r['started_at'])[-1]
        self.assertNotIn('reused_from', latest['modules'][0])

    def test_resume_completed_does_not_require_tools_or_probe(self):
        self.assertEqual(self.run_main('--modules', 'curl', '--no-progress'), 0)
        # Runs made before automatic verification have no advisory-file setting.
        manifest = self.manifest()
        data = json.loads(manifest.read_text())
        data['settings']['js_advisories'] = '/retired/advisories.json'
        manifest.write_text(json.dumps(data))
        with patch.object(w, 'tool_executable', return_value=None), patch.object(w, 'probe_target') as probe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(['--resume', str(manifest), '--no-progress']), 0)
        probe.assert_not_called()
        self.assertEqual(self.verification_mock.call_count, 2)

    def test_resume_pending_target_from_manifest(self):
        self.assertEqual(self.run_main('--modules', 'curl', '--no-progress'), 0)
        manifest = self.manifest()
        data = json.loads(manifest.read_text())
        data['targets'].append(['https://pending.test/', True])
        manifest.write_text(json.dumps(data))
        self.assertEqual(self.resume(manifest), 0)
        latest_batch = json.loads((self.manifest().parent / 'summary.json').read_text())
        self.assertEqual(len(latest_batch['targets']), 2)

    def test_all_modules_and_html_escaping(self):
        self.assertEqual(self.run_main(), 0)
        summary = self.summaries()[0]
        self.assertEqual(len(summary['modules']), 8)
        report = (Path(summary['run_directory']) / 'report.html').read_text()
        self.assertIn('&lt;script&gt;', report)
        self.assertNotIn('<script>alert', report)
        nuclei = next(m for m in summary['modules'] if m['module'] == 'nuclei')
        self.assertEqual(nuclei['findings_status'], 'complete')
        self.assertEqual(len(nuclei['findings']), 1)
        for module in summary['modules']:
            for artifact in module['artifacts']:
                self.assertTrue((Path(summary['run_directory']) / artifact).exists())

    def test_tls_modules_without_http_probe(self):
        with patch.object(w, 'probe_target') as probe, contextlib.redirect_stdout(io.StringIO()):
            code = w.main(['https://example.com:8443/path', '--modules', 'testssl,sslscan',
                           '--output-dir', str(self.root / 'results'), '-H', 'Authorization: Bearer tls-secret-token'])
        probe.assert_not_called()
        self.assertEqual(code, 0)
        summary = self.summaries()[0]
        self.assertEqual(summary['probe']['status'], 'not_required')
        for module in summary['modules']:
            self.assertEqual(module['status'], 'completed')
            self.assertIn(module['module'] + '_results.txt', module['artifacts'])
            log = (Path(summary['run_directory']) / (module['module'] + '_stderr.log')).read_text()
            self.assertIn('example.com:8443', log)
            self.assertNotIn('/path', log)
            self.assertNotIn('tls-secret-token', log)

    def test_tls_runs_despite_http_probe_failure(self):
        with patch.object(w, 'probe_target', return_value=(None, {'status': 'unreachable'})), contextlib.redirect_stdout(io.StringIO()):
            code = w.main(['https://example.com', '--modules', 'curl,testssl,sslscan', '--output-dir', str(self.root / 'results')])
        self.assertEqual(code, 1)
        self.assertEqual([m['status'] for m in self.summaries()[0]['modules']], ['skipped', 'completed', 'completed'])

    def test_tls_explicit_http_is_not_applicable(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = w.main(['http://example.com', '--modules', 'testssl,sslscan', '--output-dir', str(self.root / 'results')])
        self.assertEqual(code, 0)
        self.assertEqual([m['status'] for m in self.summaries()[0]['modules']], ['not_applicable', 'not_applicable'])

    def test_unique_runs(self):
        self.assertEqual(self.run_main('--modules', 'whatweb'), 0)
        self.assertEqual(self.run_main('--modules', 'whatweb'), 0)
        self.assertEqual(len(self.summaries()), 2)

    def test_empty_vs_missing_vs_invalid_nuclei(self):
        for mode, code, status in [('empty', 0, 'complete'), ('missing', 1, 'output_missing'), ('invalid', 1, 'invalid_output')]:
            with self.subTest(mode=mode), patch.dict(os.environ, {'WEBRAPTOR_TEST_MODE': mode}):
                self.assertEqual(self.run_main('--modules', 'nuclei'), code)
                summary = sorted(self.summaries(), key=lambda r: r['started_at'])[-1]
                self.assertEqual(summary['modules'][0]['findings_status'], status)

    def test_failure_exit_and_stderr(self):
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_MODE': 'fail'}):
            self.assertEqual(self.run_main('--modules', 'whatweb'), 1)
        module = self.summaries()[0]['modules'][0]
        self.assertEqual(module['exit_code'], 7)
        self.assertEqual(module['status'], 'failed')
        log = Path(self.summaries()[0]['run_directory']) / 'whatweb_stderr.log'
        self.assertIn('diagnostic', log.read_text())

    def test_authenticated_logs_redacted(self):
        self.assertEqual(self.run_main('--modules', 'curl,whatweb,nikto,dirsearch,nuclei', '-H', 'Authorization: Bearer secret-token', '--cookie', 'session=cookie-secret'), 0)
        for path in (self.root / 'results').rglob('*'):
            if path.is_file():
                text = path.read_text()
                self.assertNotIn('secret-token', text)
                self.assertNotIn('cookie-secret', text)

    def test_timeout_keeps_partial_output_and_kills_descendant(self):
        pidfile = self.root / 'child.pid'
        stop = threading.Event()
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_MODE': 'child', 'WEBRAPTOR_TEST_CHILD_PID': str(pidfile)}):
            result = w.run_command([str(self.bin / 'whatweb')], self.root / 'out', self.root / 'err', .5, stop, w.Redactor())
        self.assertEqual(result['status'], 'timed_out')
        self.assertIn('partial output', (self.root / 'out').read_text())
        self.assertTrue(pidfile.exists())
        child = int(pidfile.read_text())
        # A reparented child may briefly remain as a zombie after SIGKILL.
        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(child)], capture_output=True, text=True).stdout.strip()
        self.assertTrue(not state or state.startswith('Z'), state)

    def test_cancellation_and_no_launch_after_stop(self):
        # Force the Darwin poll/killpg zombie race at each signaling stage.
        for stage, signals, clock in (
            ('term', [PermissionError(), ProcessLookupError()], [0]),
            ('probe', [None, PermissionError(), ProcessLookupError()], [0, 0]),
            ('kill', [None, PermissionError(), ProcessLookupError()], [0, 2]),
        ):
            proc = Mock(pid=12345)
            proc.poll.return_value = -signal.SIGTERM
            with self.subTest(stage=stage), patch.object(w.sys, 'platform', 'darwin'), patch.object(w.os, 'killpg', side_effect=signals), patch.object(w.time, 'monotonic', side_effect=clock):
                w.terminate_group(proc)
            self.assertEqual(proc.wait.call_count, 2)
            proc.wait.assert_any_call(timeout=1.0)
        for code in (None, -signal.SIGTERM):
            proc = Mock(pid=12345)
            proc.poll.return_value = code
            if code is None:
                proc.wait.side_effect = subprocess.TimeoutExpired('scanner', 1)
            with patch.object(w.sys, 'platform', 'darwin'), patch.object(w.os, 'killpg', side_effect=PermissionError()):
                with self.assertRaises(PermissionError):
                    w.terminate_group(proc)
        stop = threading.Event()
        events = self.root / 'cancel-events'
        def cancel_when_running():
            deadline = time.monotonic() + 5
            while not events.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            stop.set()
        timer = threading.Thread(target=cancel_when_running)
        timer.start()
        try:
            with patch.dict(os.environ, {'WEBRAPTOR_TEST_MODE': 'hang', 'WEBRAPTOR_TEST_EVENTS': str(events)}):
                result = w.run_command([str(self.bin / 'whatweb')], self.root / 'out', self.root / 'err', 10, stop, w.Redactor())
        finally:
            timer.join()
        self.assertTrue(events.exists(), 'Scanner must start before testing cancellation')
        self.assertEqual(result['status'], 'cancelled')
        with patch.object(w.subprocess, 'Popen') as popen:
            result = w.run_command(['whatweb'], self.root / 'out', self.root / 'err', 10, stop, w.Redactor())
            popen.assert_not_called()
        self.assertEqual(result['status'], 'cancelled')

    def test_batch_global_concurrency(self):
        targets = self.root / 'targets'
        targets.write_text('one.test\ntwo.test\nthree.test\none.test\n')
        events = self.root / 'events'
        with patch.dict(os.environ, {'WEBRAPTOR_TEST_MODE': 'slow', 'WEBRAPTOR_TEST_EVENTS': str(events)}), patch.object(w, 'probe_target', side_effect=lambda target, *a: (target, {'status': 'reachable'})), contextlib.redirect_stdout(io.StringIO()):
            code = w.main(['-l', str(targets), '--output-dir', str(self.root / 'results'), '--target-concurrency', '3', '--threads', '2', '--modules', 'whatweb,nikto'])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.summaries()), 3)
        active = maximum = 0
        for item in sorted((json.loads(line) for line in events.read_text().splitlines()), key=lambda r: r['time']):
            active += 1 if item['event'] == 'start' else -1
            maximum = max(maximum, active)
        self.assertEqual(active, 0)
        self.assertEqual(maximum, 2)

    def test_unreachable_is_reported_and_passive_module_can_run(self):
        with patch.object(w, 'probe_target', return_value=(None, {'status': 'unreachable'})), contextlib.redirect_stdout(io.StringIO()):
            code = w.main(['example.com', '--output-dir', str(self.root / 'results'), '--modules', 'whatweb,waybackurls'])
        self.assertEqual(code, 1)
        self.assertEqual([m['status'] for m in self.summaries()[0]['modules']], ['skipped', 'completed'])


if __name__ == '__main__':
    unittest.main()
