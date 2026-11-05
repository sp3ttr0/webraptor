"""Exercise native Nikto termination against loopback and retain partial evidence."""
import json
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w
import verification as v
from output_layout import organize_output

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(.05)
        body = b'Local Nikto termination fixture'
        self.send_response(200 if self.path == '/' else 404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, BrokenPipeError):
            pass
    do_HEAD = do_GET
    do_POST = do_GET
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f'http://127.0.0.1:{server.server_port}/'
    folder = ROOT/'results/nikto-terminated-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    args = w.parse_args([target, '--modules', 'nikto', '--tool-timeout', '60'])
    original = w.build_command
    def command(module, url, path, options):
        cmd, artifact = original(module, url, path, options)
        return cmd + ['-Plugins', 'tests(report:10)', '-maxtime', '3'], artifact
    try:
        with patch.object(w, 'build_command', side_effect=command), w.Progress([(target, True)], ['nikto']) as panel:
            args.progress = panel
            result = w.execute_module('nikto', target, folder, args, threading.BoundedSemaphore(1), threading.Event(), w.Redactor())
        assert result['status'] == 'incomplete', result
        assert result['findings_status'] == 'partial'
        raw = (folder/'nikto_results.txt').read_text()
        assert 'Scan terminated:' in raw
        report = dict(target=target, checks=[], scanner_results=__import__('scanner_report').collect_scanner_results([result], folder))
        summary = organize_output(folder, dict(target=target, status='incomplete', modules=[result], verification=report))
        html = (folder/'report.html').read_text()
        assert 'incomplete' in html and 'Scan terminated:' in html
        print('Native exit code:', result.get('exit_code'))
        print('Status:', result['status'], '| Findings:', result['findings_status'])
        print('Report:', folder/'report.html')
    finally:
        server.shutdown()
