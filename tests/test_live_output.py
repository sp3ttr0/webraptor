import contextlib
import io
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import webraptor as w


class LiveOutputTests(unittest.TestCase):
    def test_streams_before_exit_and_redacts_split_writes_and_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seen = threading.Event()
            lines = []
            def receive(text):
                lines.append(text)
                seen.set()
            code = "import os,time;os.write(1,b'progress sec');time.sleep(.15);os.write(1,b'ret-token\\r');os.write(2,b'Authorization: new-secret\\n');time.sleep(1);os.write(1,b'final')"
            result = {}
            worker = threading.Thread(target=lambda: result.update(w.run_command(
                [sys.executable, '-c', code], root/'out', root/'err', 5,
                threading.Event(), w.Redactor([('Authorization','Bearer secret-token')]), on_output=receive)))
            worker.start()
            self.assertTrue(seen.wait(2))
            self.assertTrue(worker.is_alive(), 'output must arrive before process exit')
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result['status'], 'completed')
            self.assertIn('progress [REDACTED]', lines)
            self.assertIn('Authorization: [REDACTED]', lines)
            self.assertIn('final', lines)
            self.assertNotIn('secret-token', '\n'.join(lines))
            self.assertNotIn('new-secret', '\n'.join(lines))
            self.assertNotIn('secret-token', (root/'out').read_text())

    def test_parallel_default_and_reported_percentages_only(self):
        self.assertEqual(w.parse_args(['https://localhost']).threads, 6)
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal()
        target = 'https://example.com/private?token=secret'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM': 'xterm'}):
            progress = w.Progress([(target, True)], ['whatweb', 'dirsearch', 'nuclei'])
            for module in ('whatweb', 'dirsearch', 'nuclei'):
                progress.update(target, module, 'running')
            progress.output(target, 'whatweb', 'SECRET RAW OUTPUT 99%')
            progress.output(target, 'dirsearch', '[####                ] 20% 20/100 5/s job:1/1 errors:0')
            progress.output(target, 'nuclei', '[0:00:05] Templates: 10 | Requests: 25/100 (25%) | Errors: 0')
            progress.render()
            progress.update(target, 'whatweb', 'completed')
            progress.render()
        text = stream.getvalue()
        self.assertIn('20%', text)
        self.assertIn('25%', text)
        self.assertNotIn('99%', text)
        self.assertNotIn('SECRET RAW', text)
        self.assertNotIn('private', text)
        self.assertIn('Finished', text)
        self.assertIn('\x1b[', text)
        self.assertNotIn((w.target_key(target), 'whatweb'), progress.percentages)

    def test_dirsearch_metrics_staleness_and_recovery(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'https://localhost'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM': 'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['dirsearch'])
            p.update(target, 'dirsearch', 'running')
            p.output(target, 'dirsearch', '0% 5/10000 1.5/s job:1/1 errors:3')
            p.render()
            self.assertIn('Requests 5/10000 | 1.5/s | errors 3', stream.getvalue())
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('0% STALE', stream.getvalue())
            self.assertIn('Last progress: 31s ago', stream.getvalue())
            p.output(target, 'dirsearch', 'raw finding with 90% and errors:0')
            self.assertEqual(p.scanner_metrics[(w.target_key(target), 'dirsearch')]['updated'], 100)
            p.output(target, 'dirsearch', '[##                  ] 10% 1000/10000 5/s job:1/1 errors:4')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('STALE', stream.getvalue())
            self.assertIn('Requests 1000/10000', stream.getvalue())
            p.update(target, 'dirsearch', 'completed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('STALE', stream.getvalue())

    def test_dirsearch_missing_updates_and_unknown_fields(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'https://localhost'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['dirsearch']); p.update(target, 'dirsearch', 'running')
            clock.return_value = 140; p.render()
            self.assertIn('Awaiting progress: 40s', stream.getvalue())
            self.assertNotIn('0%', stream.getvalue())
            self.assertIn('STALE', stream.getvalue())
            p.output(target, 'dirsearch', '1% 1/100')
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('unknown rate | errors ?', stream.getvalue())

    def test_cursor_redraw_progress_streams_before_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); seen = threading.Event(); lines = []
            def receive(text):
                lines.append(text)
                if '1% 1/100' in text:
                    seen.set()
            code = "import os,time;os.write(1,b'1% 1/100 2/s errors:0');time.sleep(.1);os.write(1,b'\\x1b[1K\\x1b[0G2% 2/100 2/s errors:0');time.sleep(.8)"
            worker = threading.Thread(target=lambda: w.run_command([sys.executable, '-c', code], root/'out', root/'err', 5, threading.Event(), w.Redactor(), on_output=receive))
            worker.start()
            try:
                self.assertTrue(seen.wait(.7))
                self.assertTrue(worker.is_alive())
            finally:
                worker.join(5)
            self.assertIn('2% 2/100 2/s errors:0', lines)

    def test_nuclei_metrics_staleness_and_recovery(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'https://localhost'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM': 'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['nuclei'])
            p.update(target, 'nuclei', 'running')
            p.output(target, 'nuclei', '[0:00:05] Templates: 1 | Hosts: 1 | RPS: 2.5 | Matched: 0 | Errors: 3 | Requests: 5/100 (5%)')
            p.render()
            self.assertIn('Requests 5/100 | 2.5/s | errors 3', stream.getvalue())
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('5% STALE', stream.getvalue())
            self.assertIn('Last progress: 31s ago', stream.getvalue())
            p.output(target, 'nuclei', 'unrelated finding Requests: 90/100 (90%)')
            self.assertEqual(p.scanner_metrics[(w.target_key(target), 'nuclei')]['done'], 5)
            p.output(target, 'nuclei', '[0:00:36] RPS: 0 | Errors: 4 | Requests: 10/100 (10%)')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('STALE', stream.getvalue())
            self.assertIn('Requests 10/100 | 0/s | errors 4', stream.getvalue())
            p.update(target, 'nuclei', 'failed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('Last progress', stream.getvalue())
            self.assertNotIn('STALE', stream.getvalue())

    def test_nuclei_unknown_fields_and_invalid_totals(self):
        target = 'https://localhost'
        p = w.Progress([(target, True)], ['nuclei'])
        with contextlib.redirect_stderr(io.StringIO()):
            p.update(target, 'nuclei', 'running')
        key = (w.target_key(target), 'nuclei')
        for line in ('[0:00:05] Requests: 0/0 (0%)', '[0:00:05] Requests: 20/10 (100%)', '[0:00:05] Requests: 5/10 (200%)'):
            p.output(target, 'nuclei', line)
        self.assertNotIn(key, p.scanner_metrics)
        p.output(target, 'nuclei', '[0:00:05] Requests: 5/10 (50%)')
        self.assertIsNone(p.scanner_metrics[key]['rate'])
        self.assertIsNone(p.scanner_metrics[key]['errors'])
        with contextlib.redirect_stderr(io.StringIO()):
            p.update(target, 'nuclei', 'failed'); p.update(target, 'nuclei', 'running')
        self.assertNotIn(key, p.scanner_metrics)

    def test_nuclei_json_statistics_and_match_output(self):
        target = 'https://localhost'; key = (w.target_key(target), 'nuclei')
        p = w.Progress([(target, True)], ['nuclei'])
        with contextlib.redirect_stderr(io.StringIO()):
            p.update(target, 'nuclei', 'running')
        p.output(target, 'nuclei', '{"duration":"0:00:05","percent":"15","requests":"9","total":"60","rps":"1","errors":"2"}')
        self.assertEqual(p.percentages[key], 15)
        self.assertEqual(p.scanner_metrics[key]['done'], 9)
        self.assertEqual(p.scanner_metrics[key]['rate'], '1')
        self.assertEqual(p.scanner_metrics[key]['errors'], '2')
        for text in ('{"template-id":"finding","percent":"99"}', '{invalid json', '[]', '{"duration":"0:00:05","percent":null,"requests":9,"total":60}'):
            p.output(target, 'nuclei', text)
        self.assertEqual(p.percentages[key], 15)
        p.output(target, 'nuclei', '{"duration":"0:00:10","percent":50,"requests":30,"total":60,"rps":1.5,"errors":0}')
        self.assertEqual(p.scanner_metrics[key]['rate'], '1.5')
        self.assertEqual(p.percentages[key], 50)

    def test_nikto_reported_activity_and_stale_progress(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'http://localhost'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['nikto']); p.update(target, 'nikto', 'running')
            p.output(target, 'nikto', "- STATUS: Completed 50 requests (~2% complete, ~20 minutes left): currently in plugin 'Nikto Tests'")
            p.output(target, 'nikto', '- STATUS: Running average: 100 requests: 0.10000 sec, 10 requests: 0.1200 sec.')
            p.render(); text = stream.getvalue()
            self.assertIn('Requests 50', text)
            self.assertIn('plugin Nikto Tests', text)
            self.assertIn('avg latency (10): 0.1200s', text)
            self.assertNotIn('/s', text)
            self.assertNotIn('errors 0', text)
            clock.return_value = 131
            p.output(target, 'nikto', '+ /some-secret-url: observation')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('2% STALE', text)
            self.assertIn('Last progress: 31s ago', text)
            self.assertIn('Last output: 0s ago', text)
            self.assertNotIn('some-secret-url', text)
            p.output(target, 'nikto', '- STATUS: Completed 100 requests')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('STALE', stream.getvalue())
            self.assertNotIn('2%', stream.getvalue())
            self.assertIn('Requests 100', stream.getvalue())
            p.update(target, 'nikto', 'running')
            p.update(target, 'nikto', 'failed')
            p.update(target, 'nikto', 'running')
            self.assertNotIn((w.target_key(target), 'nikto'), p.nikto_activity)

    def test_testssl_stages_output_age_and_silent_period(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        target = 'https://localhost'; stream = Terminal()
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['testssl']); p.update(target, 'testssl', 'running')
            p.output(target, 'testssl', ' Testing protocols via sockets except NPN+ALPN ')
            p.render(); self.assertIn('Stage: TLS protocols', stream.getvalue())
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('Last output: 31s ago | STALE', stream.getvalue())
            p.output(target, 'testssl', 'TLS 1.2 offered (OK); secret target information')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertNotIn('STALE', text)
            self.assertIn('Stage: TLS protocols (31s)', text)
            self.assertIn('Last output: 0s ago', text)
            self.assertNotIn('secret target', text)
            p.output(target, 'testssl', ' Testing HTTP header response @ "/secret" ')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('Stage: HTTP headers (0s)', text)
            self.assertNotIn('/secret', text)
            for invented in ('%', 'Requests', 'errors 0', '/s'):
                self.assertNotIn(invented, text)
            p.update(target, 'testssl', 'completed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('Last output', stream.getvalue())
            p.update(target, 'testssl', 'running')
            self.assertNotIn((w.target_key(target), 'testssl'), p.tls_activity)

    def test_testssl_unknown_headings_do_not_invent_stage(self):
        target = 'https://localhost'; key = (w.target_key(target), 'testssl')
        with contextlib.redirect_stderr(io.StringIO()):
            p = w.Progress([(target, True)], ['testssl']); p.update(target, 'testssl', 'running')
        p.output(target, 'testssl', 'Some unrecognized future testssl output 75%')
        self.assertNotIn('stage', p.tls_activity[key])
        self.assertNotIn(key, p.percentages)
        self.assertNotIn(key, p.scanner_metrics)

    def test_sslscan_stages_staleness_and_unknown_output(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        target = 'https://localhost'; stream = Terminal(); key = (w.target_key(target), 'sslscan')
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['sslscan']); p.update(target, 'sslscan', 'running')
            p.output(target, 'sslscan', 'unknown output 75%')
            self.assertNotIn('stage', p.tls_activity[key])
            p.output(target, 'sslscan', '  Supported Server Cipher(s):')
            p.render(); self.assertIn('Stage: Server cipher support', stream.getvalue())
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('Last output: 31s ago | STALE', stream.getvalue())
            p.output(target, 'sslscan', 'Preferred TLSv1.3 256 bits TLS_AES_256_GCM_SHA384')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertNotIn('STALE', text)
            self.assertIn('Server cipher support (31s)', text)
            self.assertNotIn('TLS_AES', text)
            p.output(target, 'sslscan', 'SSL Certificate:')
            p.output(target, 'sslscan', 'Subject: secret.example.com')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('Stage: Server certificate (0s)', text)
            self.assertNotIn('secret.example.com', text)
            for invented in ('%', 'Requests', 'errors 0', '/s'):
                self.assertNotIn(invented, text)
            p.update(target, 'sslscan', 'completed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertNotIn('Last output', stream.getvalue())
            p.update(target, 'sslscan', 'running')
            self.assertNotIn(key, p.tls_activity)

    def test_terminal_stdout_delivers_buffered_output_live_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); seen = threading.Event(); lines = []
            def receive(text):
                lines.append(text); seen.set()
            code = "import sys,time; assert sys.stdout.isatty();print('secret-token');time.sleep(1)"
            result = {}
            worker = threading.Thread(target=lambda: result.update(w.run_command(
                [sys.executable, '-c', code], root/'out', root/'err', 5, threading.Event(),
                w.Redactor([('X-Key','secret-token')]), on_output=receive, tty_stdout=True)))
            worker.start()
            try:
                self.assertTrue(seen.wait(.8))
                self.assertTrue(worker.is_alive())
            finally:
                worker.join(5)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(lines, ['[REDACTED]'])
            self.assertNotIn('secret-token', (root/'out').read_text())
            # Quiet scans must also drain the terminal and preserve their logs.
            result = w.run_command([sys.executable, '-c', "print('x'*100000)"], root/'quiet', root/'err',
                                   5, threading.Event(), w.Redactor(), tty_stdout=True)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(len((root/'quiet').read_text().strip()), 100000)

    def test_whatweb_reported_status_stages_and_stale_output(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'http://localhost'; key = (w.target_key(target), 'whatweb')
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['whatweb']); p.update(target, 'whatweb', 'running')
            p.render(); self.assertIn('Awaiting response/report output', stream.getvalue())
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('Awaiting output: 31s | STALE', stream.getvalue())
            p.output(target, 'whatweb', 'WhatWeb report for http://secret-target/')
            p.output(target, 'whatweb', 'Status    : 403 Forbidden')
            p.output(target, 'whatweb', 'Detected Plugins:')
            p.output(target, 'whatweb', '[ WordPress ]')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('Stage: Detected plugin details (0s)', text)
            self.assertIn('Reported HTTP status: 403', text)
            self.assertIn('Last output: 0s ago', text)
            self.assertNotIn('STALE', text)
            self.assertNotIn('secret-target', text)
            for invented in ('%', 'Requests', 'errors 0', '/s'):
                self.assertNotIn(invented, text)
            p.output(target, 'whatweb', 'HTTP Headers:')
            self.assertEqual(p.whatweb_activity[key]['stage'], 'HTTP response headers')
            p.update(target, 'whatweb', 'completed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('Reported HTTP status: 403', stream.getvalue())
            self.assertNotIn('Last output', stream.getvalue())
            p.update(target, 'whatweb', 'running')
            self.assertNotIn(key, p.whatweb_activity)

    def test_whatweb_error_and_unrecognized_output(self):
        target = 'http://localhost'; key = (w.target_key(target), 'whatweb')
        with contextlib.redirect_stderr(io.StringIO()):
            p = w.Progress([(target, True)], ['whatweb']); p.update(target, 'whatweb', 'running')
        p.output(target, 'whatweb', 'HTTP/1.1 200 OK and 90% complete')
        self.assertNotIn('http_status', p.whatweb_activity[key])
        self.assertNotIn(key, p.percentages)
        p.output(target, 'whatweb', 'ERROR Opening: http://secret - execution expired')
        self.assertEqual(p.whatweb_activity[key]['stage'], 'Connection error reported')
        p.output(target, 'whatweb', 'Status : 999 fake')
        self.assertNotIn('http_status', p.whatweb_activity[key])

    def test_wayback_received_urls_last_update_and_staleness(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        target = 'http://localhost'; key = (w.target_key(target), 'waybackurls'); stream = Terminal()
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['waybackurls']); p.update(target, 'waybackurls', 'running')
            p.render(); self.assertIn('Awaiting archived URL output', stream.getvalue())
            p.output(target, 'waybackurls', 'https://archive.example/private?token=secret')
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('URLs received: 1', text)
            self.assertIn('Last URL: 31s ago', text)
            self.assertIn('Last output: 31s ago | STALE', text)
            p.output(target, 'waybackurls', 'provider warning with 99% and 100 requests')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertNotIn('STALE', text)
            self.assertIn('Last URL: 31s ago', text)
            self.assertIn('Last output: 0s ago', text)
            for value in ('javascript:alert(1)', 'http://[bad', 'http://', 'https://example.test/ contains spaces'):
                p.output(target, 'waybackurls', value)
            self.assertEqual(p.wayback_activity[key]['urls'], 1)
            p.output(target, 'waybackurls', 'http://archive.example/second')
            self.assertEqual(p.wayback_activity[key]['urls'], 2)
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            for hidden in ('archive.example', 'secret', '%', '/s', 'errors 0'):
                self.assertNotIn(hidden, text)
            p.update(target, 'waybackurls', 'completed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('URLs received: 2', stream.getvalue())
            self.assertNotIn('Last URL', stream.getvalue())
            p.update(target, 'waybackurls', 'running')
            self.assertNotIn(key, p.wayback_activity)

    def test_wayback_activity_stream_retains_redacted_urls_in_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = 'http://localhost'
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream):
                p = w.Progress([(target, True)], ['waybackurls']); p.update(target, 'waybackurls', 'running')
                result = w.run_command([sys.executable, '-c', "import sys;print('https://archive.example/a?token=secret-token');print('diagnostic',file=sys.stderr);print('https://archive.example/b')"],
                    root/'urls', root/'err', 5, threading.Event(), w.Redactor([('X-Key','secret-token')]),
                    on_output=lambda line: p.output(target, 'waybackurls', line))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(p.wayback_activity[(w.target_key(target), 'waybackurls')]['urls'], 2)
            self.assertNotIn('archive.example', stream.getvalue())
            self.assertIn('https://archive.example/b', (root/'urls').read_text())
            self.assertNotIn('secret-token', (root/'urls').read_text())
            self.assertIn('diagnostic', (root/'err').read_text())

    def test_curl_response_activity_stale_output_and_error_code(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        target = 'http://localhost'; key = (w.target_key(target), 'curl'); stream = Terminal()
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.time, 'monotonic', return_value=100) as clock:
            p = w.Progress([(target, True)], ['curl']); p.update(target, 'curl', 'running')
            p.render(); self.assertIn('Awaiting HTTP response headers', stream.getvalue())
            p.output(target, 'curl', 'HTTP/1.1 302 Found')
            p.output(target, 'curl', 'Location: http://private-host/secret')
            clock.return_value = 131
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('Reported HTTP status: 302 | HTTP/1.1', text)
            self.assertIn('Last response: 31s ago', text)
            self.assertIn('Last output: 31s ago | STALE', text)
            p.output(target, 'curl', 'HTTP/2 200')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertNotIn('STALE', text)
            self.assertIn('Reported HTTP status: 200 | HTTP/2', text)
            self.assertIn('Last response: 0s ago', text)
            p.output(target, 'curl', 'curl: (60) certificate error private-host')
            stream.seek(0); stream.truncate(); p.render(); text = stream.getvalue()
            self.assertIn('Reported curl error: 60', text)
            for hidden in ('private-host', 'secret', '%', '/s', 'Requests'):
                self.assertNotIn(hidden, text)
            p.update(target, 'curl', 'failed')
            stream.seek(0); stream.truncate(); p.render()
            self.assertIn('Reported curl error: 60', stream.getvalue())
            self.assertNotIn('Last output', stream.getvalue())
            p.update(target, 'curl', 'running')
            self.assertNotIn(key, p.curl_activity)

    def test_curl_unrecognized_output_does_not_invent_metrics(self):
        target = 'http://localhost'; key = (w.target_key(target), 'curl')
        with contextlib.redirect_stderr(io.StringIO()):
            p = w.Progress([(target, True)], ['curl']); p.update(target, 'curl', 'running')
        for text in ('X-Fake: HTTP/1.1 200 OK', 'HTTP/1.1 999 fake', 'Progress: 75%'):
            p.output(target, 'curl', text)
        self.assertNotIn('http_status', p.curl_activity[key])
        self.assertNotIn(key, p.percentages)
        self.assertNotIn(key, p.scanner_metrics)

    def test_all_modules_keep_headings_and_fit_standard_terminal(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal(); target = 'https://localhost'
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM':'xterm'}), patch.object(w.shutil, 'get_terminal_size', return_value=w.os.terminal_size((140,24))):
            p = w.Progress([(target, True)], list(w.MODULES)+['verification'])
            for module in w.MODULES:
                p.update(target, module, 'running')
            for module, line in [('curl','HTTP/1.1 200 OK'), ('whatweb','Status : 200 OK'),
                ('nikto',"- STATUS: Completed 50 requests (~2% complete): currently in plugin 'Nikto Tests'"),
                ('waybackurls','https://private.invalid/sample'), ('dirsearch','50% 50/100 2/s errors:0'),
                ('nuclei','[0:00:05] RPS: 2 | Errors: 0 | Requests: 50/100 (50%)'),
                ('testssl','Testing protocols'), ('sslscan','Supported Server Cipher(s):')]:
                p.output(target,module,line)
            p.render()
        text = w.re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', stream.getvalue()).replace('\r','')
        for module in list(w.MODULES)+['verification']:
            self.assertIn(p.LABELS.get(module,module), text)
        self.assertIn('req 50/100', text)
        self.assertIn('output', text)
        self.assertNotIn('private.invalid', text)
        self.assertLessEqual(len(text.splitlines()),23)
        self.assertTrue(all(len(line)<140 for line in text.splitlines()))

    def test_terminal_escape_cannot_hide_supplied_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);lines=[]
            result = w.run_command([sys.executable,'-c',"print('sec\\x1b[31mret-token')"],root/'out',root/'err',5,threading.Event(),w.Redactor([('X-Key','secret-token')]),on_output=lines.append)
            self.assertEqual(result['status'],'completed')
            self.assertEqual(lines,['[REDACTED]'])

    def test_panel_refresh_worker_stops_and_limits_width(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal()
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM': 'xterm'}), patch.object(w.shutil, 'get_terminal_size', return_value=w.os.terminal_size((45, 12))):
            with w.Progress([('https://localhost', True)], ['nikto'], interval=.01) as progress:
                progress.update('https://localhost', 'nikto', 'running')
                self.assertTrue(progress.worker.is_alive())
                progress.output('https://localhost', 'nikto', 'raw scanner line')
                progress.update('https://localhost', 'nikto', 'completed')
            self.assertFalse(progress.worker.is_alive())
        self.assertNotIn('raw scanner line', stream.getvalue())
        for line in stream.getvalue().splitlines():
            clean = w.re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line)
            self.assertLessEqual(len(clean), 44)

    def test_completion_outcomes_and_plain_output(self):
        results = [{'status': 'completed', 'run_directory': '/tmp/demo'}]
        for status, cancelled, expected in [('completed', False, 'Scan complete'), ('incomplete', False, 'Scan incomplete'), ('cancelled', True, 'Scan cancelled')]:
            results[0]['status'] = status
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                w.print_completion(results, Path('/tmp/batch'), 12.5, cancelled)
            text = stream.getvalue()
            self.assertIn(expected, text)
            self.assertIn('/tmp/demo/report.html', text)
            self.assertIn('/tmp/demo/logs', text)
            self.assertIn('/tmp/batch/run.json', text)
            self.assertNotIn('\x1b', text)
            if status != 'completed':
                self.assertNotIn('reports ready', text)

    def test_panel_state_colors_and_no_color_preference(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        for no_color in (False, True):
            stream = Terminal()
            env = {'TERM': 'xterm'}
            if no_color:
                env['NO_COLOR'] = '1'
            with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, env, clear=True):
                progress = w.Progress([('https://localhost', True)], ['nikto', 'nuclei'])
                progress.update('https://localhost', 'nikto', 'running')
                progress.update('https://localhost', 'nuclei', 'failed')
                progress.render()
            text = stream.getvalue()
            self.assertIn('WEBRAPTOR', text)
            self.assertIn('Hunt Smarter', text)
            self.assertEqual(w.Fore.CYAN in text, not no_color)
            self.assertEqual(w.Fore.RED in text, not no_color)

    def test_incomplete_panel_status_is_amber_and_separate_from_failure(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        stream = Terminal()
        with contextlib.redirect_stderr(stream), patch.dict(w.os.environ, {'TERM': 'xterm'}, clear=True):
            progress = w.Progress([('https://localhost', True)], ['nikto'])
            progress.update('https://localhost', 'nikto', 'incomplete')
            progress.render()
        output = stream.getvalue()
        self.assertIn('Incomplete', output)
        self.assertIn('Incomplete 1', output)
        self.assertIn('Failed 0', output)
        self.assertIn(w.Fore.YELLOW, output)

    def test_nonterminal_status_only_and_quiet_mode(self):
        for enabled in (True, False):
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream):
                with w.Progress([('https://example.com', True)], ['nikto'], enabled=enabled) as progress:
                    progress.update('https://example.com', 'nikto', 'running')
                    progress.output('https://example.com', 'nikto', 'raw evidence')
                    progress.render(); progress.render()
                    progress.update('https://example.com', 'nikto', 'completed')
            text = stream.getvalue()
            self.assertNotIn('raw evidence', text)
            self.assertNotIn('\x1b', text)
            if enabled:
                self.assertEqual(text.count('Running Nikto'), 1)
                self.assertEqual(text.count('Nikto: Finished'), 1)
            else:
                self.assertEqual(text, '')
