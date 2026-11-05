"""Demonstrate GET-vs-HEAD/redirect evidence using real curl on loopback."""
import json
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w
import verification as v
from output_layout import organize_output

class Handler(BaseHTTPRequestHandler):
    def respond(self, head=False):
        if self.path == '/':
            self.send_response(302)
            self.send_header('Location', '/final')
        else:
            self.send_response(200)
            self.send_header('Content-Security-Policy', "default-src 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Demo-Method', 'HEAD' if head else 'GET')
        self.send_header('Content-Length', '0')
        self.end_headers()
    def do_GET(self): self.respond()
    def do_HEAD(self): self.respond(True)
    def log_message(self, *args): pass

with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f'http://127.0.0.1:{server.server_port}/'
    folder = ROOT/'results/curl-header-evidence-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    args = w.parse_args([target, '--modules', 'curl'])
    stop, redact = threading.Event(), w.Redactor()
    try:
        module = w.execute_module('curl', target, folder, args, threading.BoundedSemaphore(1), stop, redact)
        assert module['status'] == 'completed', module
        def no_more_scanners(*args, **kwargs):
            raise AssertionError('Unexpected extra scanner invocation')
        report = v.assess_target(target, args, folder, stop, no_more_scanners, redact, [module])
        finding = next(check for check in report['checks'] if check['check'] == 'Content Security Policy Not Implemented')
        assert finding['status'] == 'found' and finding['verified']
        assert report['http_status'] == 302
        raw = next(source['raw_output'] for source in finding['evidence_sources'] if source['tool'] == 'curl')
        assert '302 Found' in raw and '200 OK' in raw and "Content-Security-Policy: default-src 'none'" in raw
        assert 'X-Demo-Method: HEAD' in raw
        html = v.render_report(report)
        assert 'supporting-files' in html and 'curl · Raw evidence' not in html
        assert 'HEAD · Redirects followed' in html
        organize_output(folder, dict(target=target, status=report['status'], modules=[module], verification=report))
        print('Verified missing CSP on GET 302; retained HEAD 302 + HEAD 200 headers as additional evidence.')
        print('REPORT:', folder/'report.html')
    finally:
        server.shutdown()
