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

    def test_terminal_escape_cannot_hide_supplied_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);lines=[]
            result = w.run_command([sys.executable,'-c',"print('sec\\x1b[31mret-token')"],root/'out',root/'err',5,threading.Event(),w.Redactor([('X-Key','secret-token')]),on_output=lines.append)
            self.assertEqual(result['status'],'completed')
            self.assertEqual(lines,['[REDACTED]'])

    def test_compact_terminal_and_nonterminal_progress(self):
        class Terminal(io.StringIO):
            def isatty(self): return True
        for stream in (io.StringIO(), Terminal()):
            with contextlib.redirect_stderr(stream), patch.object(w.shutil,'get_terminal_size',return_value=__import__('os').terminal_size((60,24))):
                progress=w.Progress([('https://example.com/private?token=secret',True)],['nikto'])
                progress.update('https://example.com/private?token=secret','nikto','running')
                progress.render();first=stream.getvalue();progress.render()
                if not stream.isatty(): self.assertEqual(first,stream.getvalue())
                progress.output('https://example.com','nikto','observed header')
            self.assertIn('observed header',stream.getvalue())
            self.assertNotIn('[nikto]',stream.getvalue())
            self.assertIn('Running Nikto',stream.getvalue())
            self.assertNotIn('[progress',stream.getvalue())
            self.assertNotIn('private',stream.getvalue())
            if stream.isatty():
                for line in stream.getvalue().split('\r'):
                    if line.startswith('\x1b[2K[progress'):
                        self.assertLessEqual(len(line.split('\n')[0])-4,59)
