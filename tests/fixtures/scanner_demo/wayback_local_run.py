"""Test installed Waybackurls using local sample archive-provider responses."""
import json
import os
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class ArchiveProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        host = urlsplit(self.path).hostname
        if host == 'web.archive.org':
            time.sleep(1)
            payload = json.dumps([['urlkey', 'timestamp', 'original'],
                ['', '20200101000000', 'https://archive-fixture.invalid/one'],
                ['', '20200101000000', 'https://archive-fixture.invalid/two']]).encode()
        elif host == 'index.commoncrawl.org':
            # Leave enough silence to exercise the 30-second stale indicator.
            time.sleep(36)
            payload = ('\n'.join(json.dumps({'url': url, 'timestamp': '20200101000000'})
                for url in ['https://archive-fixture.invalid/two',
                            'https://archive-fixture.invalid/three',
                            'https://archive-fixture.invalid/four']) + '\n').encode()
        else:
            self.send_error(403)
            return
        self.server.providers.append(host)
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def do_CONNECT(self):
        self.send_error(403)
    def log_message(self, *args):
        pass

with ThreadingHTTPServer(('127.0.0.1', 0), ArchiveProxy) as server:
    server.providers = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proxy = f'http://127.0.0.1:{server.server_port}'
    for name in ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'):
        os.environ[name] = proxy
    for name in ('NO_PROXY', 'no_proxy', 'VT_API_KEY'):
        os.environ[name] = ''
    folder = ROOT/'results/wayback-local-demo'/time.strftime('%Y%m%dT%H%M%S')
    folder.mkdir(parents=True)
    target = 'http://archive-fixture.invalid'
    print('Sample archive responses from a loopback proxy; no live archive results.')
    try:
        with w.Progress([(target, True)], ['waybackurls']) as progress:
            progress.update(target, 'waybackurls', 'running')
            result = w.run_command([w.tool_executable('waybackurls'), 'archive-fixture.invalid'],
                folder/'waybackurls_stdout.log', folder/'waybackurls_stderr.log', 60,
                threading.Event(), w.Redactor(), on_output=lambda line: progress.output(target, 'waybackurls', line))
            progress.update(target, 'waybackurls', result['status'])
        result['activity'] = progress.wayback_activity.get((w.target_key(target), 'waybackurls'), {})
        result['sample_data'] = True
        result['local_providers'] = server.providers
        w.write_json(folder/'summary.json', result)
        print('Scanner status:', result['status'])
        print('URLs received:', result['activity'].get('urls', 0))
        print('Evidence:', folder)
        if result['status'] != 'completed' or result['activity'].get('urls') != 4:
            sys.exit(1)
    finally:
        server.shutdown()
