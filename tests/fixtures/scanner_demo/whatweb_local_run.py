"""Exercise real WhatWeb activity against a slow loopback HTTP response."""
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class Target(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.49'
    sys_version = ''
    def do_GET(self):
        time.sleep(3)
        body = b'<html><title>Local WhatWeb demo</title><meta name="generator" content="WordPress 6.0"></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f'http://127.0.0.1:{server.server_port}'
    folder = ROOT/'results/whatweb-local-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    print('Local target:', target)
    try:
        with w.Progress([(target, True)], ['whatweb']) as progress:
            progress.update(target, 'whatweb', 'running')
            result = w.run_command(['whatweb', '-v', '--color=never', '--max-threads=1',
                '--wait=1', '--follow-redirect=never', target], folder/'whatweb_stdout.log',
                folder/'whatweb_stderr.log', 60, threading.Event(), w.Redactor(),
                on_output=lambda line: progress.output(target, 'whatweb', line), tty_stdout=True)
            progress.update(target, 'whatweb', result['status'])
        w.write_json(folder/'summary.json', result)
        print('Scanner status:', result['status'])
        print('Evidence:', folder)
    finally:
        server.shutdown()
