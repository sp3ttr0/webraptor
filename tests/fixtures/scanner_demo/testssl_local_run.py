"""Exercise real TLS scanner activity against an ephemeral local HTTPS server."""
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODULE = 'sslscan' if '--sslscan' in sys.argv else 'testssl'

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import webraptor as w

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'WebRaptor local HTTPS fixture'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ssl.SSLError):
            pass
    do_HEAD = do_GET
    def log_message(self, *args):
        pass

class LocalServer(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        if MODULE == 'sslscan':
            # Make the very fast loopback probes visible in the live panel.
            time.sleep(.05)
        return connection, address

    def handle_error(self, request, client_address):
        # Malformed TLS probes can trigger HTTP parser disconnects. Preserve
        # fixture diagnostics separately from the scanner's terminal panel.
        import traceback
        with (self.evidence_folder/'server_errors.log').open('a') as log:
            traceback.print_exc(file=log)


with tempfile.TemporaryDirectory() as temp:
    cert, key = Path(temp)/'cert.pem', Path(temp)/'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with LocalServer(('127.0.0.1', 0), Target) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        target = f'https://127.0.0.1:{server.server_port}'
        folder = ROOT/('results/' + MODULE + '-local-demo')/time.strftime('%Y%m%dT%H%M%S')
        folder.mkdir(parents=True)
        server.evidence_folder = folder
        print('Local HTTPS target:', target)
        print('Scanner:', MODULE)
        try:
            with w.Progress([(target, True)], [MODULE]) as progress:
                progress.update(target, MODULE, 'running')
                cmd = ([w.tool_executable('sslscan'), '--no-colour', w.tls_endpoint(target)]
                    if MODULE == 'sslscan' else [w.tool_executable('testssl'), '--quiet', '--color', '0',
                    '--warnings', 'batch', '--nodns', 'none', '-p', '-S', '-h', w.tls_endpoint(target)])
                result = w.run_command(cmd, folder/(MODULE + '_stdout.log'), folder/(MODULE + '_stderr.log'), 180,
                    threading.Event(), w.Redactor(), on_output=lambda line: progress.output(target, MODULE, line), tty_stdout=(MODULE == 'sslscan'))
                progress.update(target, MODULE, result['status'])
            w.write_json(folder/'summary.json', result)
            print('Scanner status:', result['status'])
            print('Evidence:', folder)
        finally:
            server.shutdown()
