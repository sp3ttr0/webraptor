"""Bounded real Nikto scan against a slow loopback target; no external targets."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(.04)
        body = b'Nikto slow local fixture' if self.path == '/' else b'Missing'
        self.send_response(200 if self.path == '/' else 404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_HEAD = do_GET
    do_POST = do_GET
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}'
    folder = ROOT/'results/nikto-slow-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    print('Slow local target:', url)
    print('Bounded demonstration: Nikto tests plugin, 20-second scan limit.')
    try:
        with w.Progress([(url, True)], ['nikto']) as progress:
            progress.update(url, 'nikto', 'running')
            cmd = ['nikto', '-host', url, '-ask', 'no', '-nointeractive', '-Display', 'P',
                   '-Plugins', 'tests(report:10)', '-Pause', '.001', '-maxtime', '20']
            result = w.run_command(cmd, folder/'nikto_stdout.log', folder/'nikto_stderr.log',
                60, threading.Event(), w.Redactor(), on_output=lambda line: progress.output(url, 'nikto', line))
            progress.update(url, 'nikto', result['status'])
        (folder/'summary.json').write_text(json.dumps(result, indent=2))
        print('Native scanner status:', result['status'])
        print('Evidence:', folder)
    finally:
        server.shutdown()
