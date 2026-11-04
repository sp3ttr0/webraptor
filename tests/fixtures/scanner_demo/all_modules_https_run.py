"""All eight real scanners against HTTPS loopback; archive data is local sample data.
Nikto uses tests(report:10) with a 20-second limit. testssl selects protocols,
server defaults and HTTP headers. Pass --full-checks to run only Nikto and testssl with their full default checks.
Pass --all-full-checks for all eight modules with full Nikto/testssl checks.
Normal CLI defaults are unchanged.
"""
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

RESUMPTION_CHECKS = '--resumption-checks' in sys.argv
ALL_FULL_CHECKS = '--all-full-checks' in sys.argv
FULL_CHECKS = '--full-checks' in sys.argv or RESUMPTION_CHECKS or ALL_FULL_CHECKS

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class Target(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.49'
    sys_version = ''
    def do_GET(self):
        time.sleep(0 if FULL_CHECKS else .15)
        known = self.path == '/' or self.path.startswith('/page') or self.path == '/backup.txt'
        body = (b'<title>All eight local demo</title><meta name="generator" content="WordPress 6.0">WEBRAPTOR_LOCAL_DEMO_BACKUP'
                if known else b'Generic missing page')
        self.send_response(200 if known else 404)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Demo-Evidence', 'all-eight-local-evidence')
        self.end_headers()
        try:
            if self.command != 'HEAD':
                self.wfile.write(body)
        except (BrokenPipeError, ssl.SSLError, ConnectionResetError):
            pass
    do_HEAD = do_GET
    do_POST = do_GET
    def log_message(self, *args):
        pass

class LocalServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        with (self.evidence_folder/'server_errors.log').open('a') as log:
            traceback.print_exc(file=log)

class ArchiveProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        host = urlsplit(self.path).hostname
        if host == 'web.archive.org':
            time.sleep(2)
            payload = json.dumps([['urlkey','timestamp','original'],
                ['', '20200101000000', self.server.target+'/sample-archive-one']]).encode()
        elif host == 'index.commoncrawl.org':
            time.sleep(12)
            payload = (json.dumps({'timestamp':'20200101000000',
                'url':self.server.target+'/sample-archive-two'})+'\n').encode()
        else:
            self.send_error(403)
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def do_CONNECT(self):
        self.send_error(403)
    def log_message(self, *args):
        pass

with tempfile.TemporaryDirectory() as temp:
    temp = Path(temp)
    cert, key = temp/'cert.pem', temp/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256',
        '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost',
        '-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.environ['PATH'] = str(ROOT/'.venv/bin') + os.pathsep + os.environ.get('PATH','')
    # Trust only the ephemeral demo certificate in child scanner processes.
    os.environ['SSL_CERT_FILE'] = str(cert)
    os.environ['REQUESTS_CA_BUNDLE'] = str(cert)
    # The installed WhatWeb modifies a DEFAULT_PARAMS hash frozen by new Ruby.
    # Keep this compatibility shim local to the demo process; no tool files change.
    ruby_compat = temp/'whatweb_compat.rb'
    ruby_compat.write_text("require 'openssl'\nparams = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.dup\nOpenSSL::SSL::SSLContext.send(:remove_const, :DEFAULT_PARAMS)\nOpenSSL::SSL::SSLContext.const_set(:DEFAULT_PARAMS, params)\n")
    os.environ['RUBYOPT'] = (os.environ.get('RUBYOPT', '') + ' -r' + str(ruby_compat)).strip()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert,key)
    with LocalServer(('127.0.0.1',0),Target) as server, ThreadingHTTPServer(('127.0.0.1',0),ArchiveProxy) as proxy:
        output = ROOT/('results/all-eight-full-https-demo' if ALL_FULL_CHECKS else 'results/testssl-resumption-demo' if RESUMPTION_CHECKS else 'results/full-nikto-testssl-demo' if FULL_CHECKS else 'results/all-modules-https-demo')/time.strftime('%Y%m%dT%H%M%S')
        output.mkdir(parents=True)
        (output/'logs').mkdir()
        (output/'data').mkdir()
        server.evidence_folder = output/'logs'
        server.socket = context.wrap_socket(server.socket,server_side=True)
        target = f'https://127.0.0.1:{server.server_port}'
        proxy.target = target
        for endpoint in (server,proxy):
            threading.Thread(target=endpoint.serve_forever,daemon=True).start()
        for name in ('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy','ALL_PROXY','all_proxy'):
            os.environ[name] = f'http://127.0.0.1:{proxy.server_port}'
        for name in ('NO_PROXY','no_proxy'):
            os.environ[name] = '127.0.0.1,localhost'
        os.environ['VT_API_KEY'] = ''
        paths = temp/'paths.txt'
        paths.write_text('\n'.join(f'page{i}' for i in range(60)))
        template = temp/'local.yaml'
        requests = '\n'.join("      - '{{BaseURL}}/page"+str(i)+"'" for i in range(80))
        template.write_text('''id: webraptor-all-eight-local
info:
  name: All eight local demo marker
  author: webraptor
  severity: info
http:
  - method: GET
    path:
'''+requests+'''
    matchers:
      - type: word
        words:
          - WEBRAPTOR_LOCAL_DEMO_BACKUP
''')
        original_build = w.build_command
        def bounded_command(module, target, folder, args):
            cmd, artifact = original_build(module,target,folder,args)
            if module == 'nikto' and not FULL_CHECKS:
                cmd += ['-Plugins','tests(report:10)','-maxtime','20']
            if module == 'testssl' and not FULL_CHECKS:
                cmd[-1:-1] = ['--nodns','none','-p','-S','-h']
            if module == 'testssl' and FULL_CHECKS:
                original_backend = Path('/opt/homebrew/opt/openssl@4/bin/openssl')
                if original_backend.is_file():
                    cmd[-1:-1] = ['--openssl', str(original_backend)]
            if module == 'testssl' and RESUMPTION_CHECKS:
                cmd[-1:-1] = ['-S']
            return cmd,artifact
        w.build_command = bounded_command
        print('LOCAL HTTPS TARGET:',target)
        if RESUMPTION_CHECKS:
            print('Focused native testssl server-default/session-resumption check, with the upstream fix.')
        elif ALL_FULL_CHECKS:
            print('All eight installed modules; full native Nikto and testssl checks; eight scanner slots.')
            print('No Nikto/testssl plugin restrictions or native scan-time limits. Waybackurls uses labelled local archive samples.')
        elif FULL_CHECKS:
            print('Full native Nikto and testssl default checks; no plugin restrictions or native scan-time limits.')
            print('WebRaptor per-module timeout: 1800 seconds. Target response delay disabled.')
        else:
            print('All eight installed modules; eight concurrent scanner slots.')
            print('Demo scope: bounded Nikto tests, selected testssl checks, local sample archive URLs.')
        print('The Apache/WordPress fingerprints and Nuclei marker are synthetic fixture data.')
        try:
            selection = ['--modules','testssl'] if RESUMPTION_CHECKS else ['--modules','nikto,testssl'] if FULL_CHECKS and not ALL_FULL_CHECKS else []
            result = w.main([target,'--insecure','--threads','2' if FULL_CHECKS and not ALL_FULL_CHECKS else '8',
                '--tool-timeout','1800' if FULL_CHECKS else '180',*selection,
                '--nikto-pause','.001','--dirsearch-threads','2','--dirsearch-rate','10',
                '--wordlist',str(paths),'--nuclei-template',str(template),'--nuclei-rate','5',
                '--output-dir',str(output)])
            # Mark archive samples in the rendered report as well as fixture metadata.
            from verification import render_report
            for verification_path in output.glob('*/20*/data/verification.json'):
                report = json.loads(verification_path.read_text())
                for scanner in report.get('scanner_results', []):
                    if scanner['module'] == 'waybackurls':
                        scanner['sample_data'] = True
                w.write_json(verification_path, report)
                (verification_path.parent.parent/'report.html').write_text(render_report(report))
                summary_path = verification_path.parent/'summary.json'
                summary = json.loads(summary_path.read_text())
                summary['verification'] = report
                w.write_json(summary_path, summary)
            # Persist the fixture scope alongside the reports.
            w.write_json(output/'data/demo_scope.json',{'target':target,'sample_archive_data':ALL_FULL_CHECKS or not FULL_CHECKS,
                'nikto_limit_seconds':None if FULL_CHECKS else 20,
                'testssl_checks':'server defaults and session resumption' if RESUMPTION_CHECKS else 'full defaults' if FULL_CHECKS else ['protocols','server defaults','HTTP headers'],
                'modules':['testssl'] if RESUMPTION_CHECKS else ['nikto','testssl'] if FULL_CHECKS and not ALL_FULL_CHECKS else list(w.MODULES)})
        finally:
            server.shutdown()
            proxy.shutdown()
        sys.exit(result)
