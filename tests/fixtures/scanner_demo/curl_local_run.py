"""Real curl against a local redirect followed by delayed HTTP headers."""
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class Target(BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == '/':
            self.send_response(302)
            self.send_header('Location', '/delayed')
        else:
            time.sleep(35)
            self.send_response(200)
        self.send_header('X-Demo-Evidence', 'curl-local-header-evidence')
        self.send_header('Content-Length', '0')
        self.end_headers()
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f'http://127.0.0.1:{server.server_port}'
    folder = ROOT/'results/curl-local-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    print('Local curl target:', target)
    print('Redirect followed by a 35-second delayed response.')
    try:
        args = w.parse_args([target, '--modules', 'curl'])
        cmd, artifact = w.build_command('curl', target, folder, args)
        with w.Progress([(target, True)], ['curl']) as progress:
            progress.update(target, 'curl', 'running')
            result = w.run_command(cmd, artifact, folder/'curl_stderr.log', 60,
                threading.Event(), w.Redactor(), on_output=lambda line: progress.output(target, 'curl', line), tty_stdout=True)
            progress.update(target, 'curl', result['status'])
        result['activity'] = progress.curl_activity.get((w.target_key(target), 'curl'), {})
        w.write_json(folder/'summary.json', result)
        print('Scanner status:', result['status'])
        print('Evidence:', folder)
        if result['status'] != 'completed' or result['activity'].get('http_status') != '200':
            sys.exit(1)
    finally:
        server.shutdown()
