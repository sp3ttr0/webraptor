"""Run real Nuclei with a harmless template against a slow loopback target."""
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
        if self.path.startswith('/slow/'):
            time.sleep(.5)
        body = b'WEBRAPTOR_SLOW_NUCLEI_FIXTURE'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server, tempfile.TemporaryDirectory() as temp:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    template = Path(temp) / 'slow.yaml'
    paths = '\n'.join("      - '{{BaseURL}}/slow/" + str(i) + "'" for i in range(60))
    template.write_text('''id: webraptor-slow-local-demo
info:
  name: WebRaptor slow loopback fixture
  author: webraptor
  severity: info
http:
  - method: GET
    path:
''' + paths + '''
    matchers:
      - type: word
        words:
          - WEBRAPTOR_SLOW_NUCLEI_FIXTURE
''')
    env = dict(os.environ, COLUMNS='140', TERM='xterm-256color')
    try:
        result = subprocess.run([sys.executable, str(ROOT/'webraptor.py'),
            f'http://127.0.0.1:{server.server_port}', '--modules', 'nuclei',
            '--nuclei-template', str(template), '--nuclei-rate', '5',
            '--tool-timeout', '120', '--output-dir', str(ROOT/'results/nuclei-slow-demo')],
            cwd=ROOT, env=env)
    finally:
        server.shutdown()
    sys.exit(result.returncode)
