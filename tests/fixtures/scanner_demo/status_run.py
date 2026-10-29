"""Real Dirsearch integration fixture with five distinct response codes."""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        codes = {f'/status{code}': code for code in (200,301,403,404,500)}
        code = codes.get(self.path, 200 if self.path == '/' else 404)
        # Distinct bodies prevent a seeded 404 from matching the wildcard baseline.
        data = (f'WebRaptor explicit fixture response {code}: {self.path}' if self.path in codes else 'Generic missing page').encode()
        self.send_response(code)
        if code == 301:
            self.send_header('Location', '/status200')
        self.send_header('Content-Type','text/plain')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*args): pass
with ThreadingHTTPServer(('127.0.0.1',0),Target) as server:
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        subprocess.run([sys.executable,str(ROOT/'webraptor.py'),f'http://127.0.0.1:{server.server_port}',
            '--modules','dirsearch','--no-progress','--tool-timeout','60',
            '--wordlist',str(Path(__file__).with_name('status_paths.txt')),
            '--output-dir',str(ROOT/'results/dirsearch-status-demo')],cwd=ROOT,check=True)
    finally: server.shutdown()
