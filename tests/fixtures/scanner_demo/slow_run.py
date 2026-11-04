"""Exercise real Dirsearch progress against a slow loopback-only target."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[3]

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/':
            time.sleep(.35)
        found = self.path == '/' or self.path in {f'/page{i}' for i in range(0, 100, 10)}
        body = ('Slow local demo page' if found else 'Missing').encode()
        self.send_response(200 if found else 404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server, tempfile.TemporaryDirectory() as temp:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    wordlist = Path(temp) / 'paths.txt'
    wordlist.write_text('\n'.join(f'page{i}' for i in range(100)))
    env = dict(os.environ, COLUMNS='160', TERM='xterm-256color', PYTHONUNBUFFERED='1')
    try:
        result = subprocess.run([sys.executable, str(ROOT/'webraptor.py'),
            f'http://127.0.0.1:{server.server_port}', '--modules', 'dirsearch',
            '--wordlist', str(wordlist), '--dirsearch-threads', '2', '--dirsearch-rate', '5',
            '--tool-timeout', '120', '--output-dir', str(ROOT/'results/dirsearch-slow-demo')],
            cwd=ROOT, env=env)
    finally:
        server.shutdown()
    sys.exit(result.returncode)
