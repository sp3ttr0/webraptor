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
