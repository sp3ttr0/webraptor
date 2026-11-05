"""Full native TLS checks against loopback; audit default/fallback evidence for every TLS check."""
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w
import verification as v
from unittest.mock import patch
from output_layout import organize_output

TLS_CHECKS = {'Weak SSL/TLS Ciphers', 'TLSv1.3 Disabled', 'Wildcard SSL Certificates in Use',
              'SSLv2 Enabled', 'SSLv3 Enabled', 'TLSv1.0 Enabled', 'TLSv1.1 Enabled',
              'SSL Certificate Using Weak Hashing Algorithm', 'Expired SSL Certificate'}
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *args): pass

os.environ['PATH'] = str(ROOT/'.venv/bin') + os.pathsep + os.environ.get('PATH', '')
with tempfile.TemporaryDirectory() as temp:
    cert, key = Path(temp)/'cert.pem', Path(temp)/'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
                    '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0')
    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        target = f'https://127.0.0.1:{server.server_port}/'
        folder = ROOT/'results/full-tls-evidence-demo'/time.strftime('%Y%m%dT%H%M%S')
        folder.mkdir(parents=True)
        args = w.parse_args([target, '--modules', 'testssl,sslscan', '--insecure', '--tool-timeout', '600'])
        stop, redact = threading.Event(), w.Redactor()
        quick = '--quick-ciphers' in sys.argv
        original_build = w.build_command
        def build(module, url, path, options):
            cmd, artifact = original_build(module, url, path, options)
            if quick and module == 'testssl':
                cmd[-1:-1] = ['-P', '--nodns', 'none']
            return cmd, artifact
        try:
            modules = []
            with patch.object(w, 'build_command', side_effect=build), w.Progress([(target, True)], args.modules) as panel:
                args.progress = panel
                for module in args.modules:
                    modules.append(w.execute_module(module, target, folder, args, threading.BoundedSemaphore(1), stop, redact))
            assert all(module['status'] == 'completed' for module in modules), modules
            print('Native scanner checks completed (focused ciphers)' if quick else 'Full native scanner checks completed', flush=True)
            def no_duplicate_scanner(*args, **kwargs):
                raise AssertionError('Verification launched a duplicate scanner')
            report = v.assess_target(target, args, folder, stop, no_duplicate_scanner, redact, modules)
            cipher = next(check for check in report['checks'] if check['check'] == 'Weak SSL/TLS Ciphers')
            assert cipher['verified'] and {'sslscan', 'testssl'} <= {item['source'] for item in cipher['evidence']}, cipher
            audit = []
            for finding in report['checks']:
                if finding['check'] not in TLS_CHECKS: continue
                sources = finding['evidence_sources']
                default = v.render_sources(sources, compact=True)
                fallback = v.render_sources([source for source in sources if source.get('tool') != 'testssl'], compact=True)
                assert 'open><summary>testssl · Raw evidence' in default, finding['check']
                assert 'open><summary>sslscan · Raw evidence' in fallback, finding['check']
                audit.append(dict(check=finding['check'], status=finding['status'], testssl_default=True, sslscan_fallback=True))
            assert len(audit) == 9
            organize_output(folder, dict(target=target, status=report['status'], modules=modules, verification=report))
            (folder/'data/evidence_layout_audit.json').write_text(json.dumps(audit, indent=2))
            print(json.dumps(audit, indent=2), flush=True)
            print('REPORT:', folder/'report.html', flush=True)
        finally:
            server.shutdown()
