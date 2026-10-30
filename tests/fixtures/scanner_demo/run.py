"""Run the real five scanner modules against a harmless loopback fixture."""
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
class Target(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.49'
    sys_version = ''
    def do_HEAD(self):
        self.respond(False)
    def do_GET(self):
        self.respond(True)
    def respond(self, body):
        pages = {'/': '<html><head><title>WebRaptor Local Demo</title><meta name="generator" content="WordPress 6.0"></head><body>Local scanner demonstration</body></html>',
                 '/robots.txt': 'User-agent: *\nDisallow: /admin/\nDisallow: /backup.txt\n',
                 '/admin': '<html><title>Administration</title>Local demo admin page</html>',
                 '/admin/': '<html><title>Administration</title>Local demo admin page</html>',
                 '/backup.txt': 'WEBRAPTOR_LOCAL_DEMO_BACKUP\nSynthetic fixture data only.\n',
                 '/server-status': 'Apache Server Status — local fixture only'}
        content = pages.get(self.path)
        self.send_response(200 if content is not None else 404)
        self.send_header('Content-Type', 'text/html' if self.path in ('/', '/admin', '/admin/') else 'text/plain')
        self.end_headers()
        if body:
            self.wfile.write((content or 'Not found').encode())
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}'
    print('LOCAL_TARGET=' + url, flush=True)
    try:
        result = subprocess.run([sys.executable, str(ROOT/'webraptor.py'), url,
            '--modules', 'whatweb,nikto,waybackurls,dirsearch,nuclei', '--no-progress',
            '--tool-timeout', '180', '--nikto-pause', '0.001', '--dirsearch-rate', '30',
            '--wordlist', str(Path(__file__).with_name('paths.txt')),
            '--nuclei-template', str(Path(__file__).with_name('nuclei.yaml')),
            '--output-dir', str(ROOT/'results/scanner-demo')], cwd=ROOT)
        sys.exit(result.returncode)
    finally:
        server.shutdown()
