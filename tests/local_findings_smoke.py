"""Real loopback-only smoke test: normal CLI, curl, sslscan, HTML and JSON.

Run with the project's Python. Requires openssl, curl and sslscan in PATH.
Fixture keys live only in a temporary directory. No external target/advisory is used.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import html
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
EXACT = b'/*! LocalFixture library v1.0.0 */\n/* exact fixture bytes */'
FINGERPRINT = b'/*! LocalFixture library v1.0.0 */\n/* modified bytes */'
UNKNOWN = b'/* no known library fingerprint */'


class Rows(HTMLParser):
    """Extract collapsed finding content without relying on its visual layout."""
    def __init__(self):
        super().__init__()
        self.rows, self.finding, self.cell = [], None, None
        self.in_summary, self.depth, self.field = False, 0, None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'details' and 'finding' in attrs.get('class', '').split():
            self.finding = dict(check='', sources='', evidence='')
        if self.finding is None:
            return
        if tag == 'summary':
            self.in_summary = True
        if tag == 'div':
            if self.cell is not None:
                self.depth += 1
            elif attrs.get('data-field') in ('sources', 'evidence'):
                self.field, self.cell, self.depth = attrs['data-field'], [], 1
    def handle_data(self, data):
        if self.in_summary:
            self.finding['check'] += data
        if self.cell is not None:
            self.cell.append(data)
    def handle_endtag(self, tag):
        if tag == 'summary':
            self.in_summary = False
        if tag == 'div' and self.cell is not None:
            self.depth -= 1
            if self.depth == 0:
                self.finding[self.field] = ''.join(self.cell)
                self.cell = None
        if tag == 'details' and self.finding is not None:
            self.rows.append([self.finding['check'], self.finding['sources'], self.finding['evidence']])
            self.finding = None


def command(*argv, cwd=None):
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True, timeout=30)


def certificates(folder):
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
            '-keyout', str(folder / 'ca.key'), '-out', str(folder / 'ca.pem'), '-days', '3',
            '-subj', '/CN=WebRaptor Local Fixture CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectKeyIdentifier=hash')
    (folder / 'index').touch()
    (folder / 'serial').write_text('1000\n')
    (folder / 'ca.conf').write_text('''[ca]
default_ca=local
[local]
database=index
serial=serial
new_certs_dir=.
certificate=ca.pem
private_key=ca.key
default_md=sha256
default_days=2
policy=policy
unique_subject=no
x509_extensions=server
[policy]
commonName=supplied
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:localhost,DNS:*.fixture.test,IP:127.0.0.1
''')
    for profile in ('valid', 'expired'):
        command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(folder / (profile + '.key')), '-out', str(folder / (profile + '.csr')),
                '-subj', '/CN=localhost')
        options = ['-startdate', '20000101000000Z', '-enddate', '20010101000000Z', '-md', 'sha1'] if profile == 'expired' else ['-md', 'sha256']
        command('openssl', 'ca', '-batch', '-notext', '-config', 'ca.conf',
                '-in', profile + '.csr', '-out', profile + '.pem', *options, cwd=folder)
    command('openssl', 'genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt', 'group:ffdhe2048',
            '-out', str(folder / 'dh.pem'))


class Target(BaseHTTPRequestHandler):
    def handle_request(self, head=False):
        profile = self.path.strip('/').split('.')[0]
        if self.path.endswith('.js'):
            body = FINGERPRINT if profile == 'fingerprint' else UNKNOWN if profile == 'unknown' else EXACT
            encoding, content_type = None, 'application/javascript'
        else:
            body = ('<!doctype html><html><head><title>Local finding fixture</title></head><body>'
                    '<script src="/' + profile + '.js"></script></body></html>').encode()
            encoding = 'gzip' if profile != 'missing' else None
            content_type = 'text/html'
            if encoding:
                body = gzip.compress(body)
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        if encoding:
            self.send_header('Content-Encoding', encoding)
        if profile != 'missing':
            for name, value in (
                ('Strict-Transport-Security', 'max-age=0'),
                ('Content-Security-Policy', "script-src * 'unsafe-inline' 'unsafe-eval'"),
                ('X-Content-Type-Options', 'invalid'), ('X-Content-Type-Options', 'nosniff'),
                ('Referrer-Policy', 'invalid'), ('Cross-Origin-Opener-Policy', 'unsafe-none'),
                ('X-Frame-Options', 'DENY'), ('X-XSS-Protection', '0')):
                self.send_header(name, value)
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass  # Header-only reachability probes intentionally close early.
    def do_GET(self):
        self.handle_request()
    def do_HEAD(self):
        self.handle_request(True)
    def log_message(self, *unused):
        pass


def target_server(folder, profile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ADH-AES128-SHA:@SECLEVEL=0')
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_dh_params(folder / 'dh.pem')
    context.load_cert_chain(folder / (profile + '.pem'), folder / (profile + '.key'))
    server = ThreadingHTTPServer(('127.0.0.1', 0), Target)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, worker


def expected(profile):
    # Every check has an independently specified expected status/verification flag.
    states = [
        ('Strict Transport Security Not Implemented', 'found', True),
        ('Content Security Policy Not Implemented', 'found' if profile == 'missing' else 'not_found', True),
        ('X-Content-Type-Options Not Implemented', 'found' if profile == 'missing' else 'potential', profile == 'missing'),
        ('Referrer Policy Not Implemented', 'found' if profile == 'missing' else 'potential', profile == 'missing'),
        ('Permissions Policy Not Implemented', 'found', True),
        ('Cross-Origin-Opener-Policy (COOP) Not Implemented', 'found' if profile == 'missing' else 'potential', profile == 'missing'),
        ('Cross-Origin-Resource-Policy (CORP) Not Implemented', 'found', True),
        ('Cross-Origin-Embedder-Policy (COEP) Not Implemented', 'found', True),
        ('Insecure Content Security Policy (CSP)', 'not_applicable' if profile == 'missing' else 'potential', False),
        ('Weak SSL/TLS Ciphers', 'found', True),
        ('TLSv1.3 Disabled', 'found', True),
        ('HTTP Compression Enabled (BREACH Vulnerability)', 'not_found' if profile == 'missing' else 'potential', False),
        ('Wildcard SSL Certificates in Use', 'unknown' if profile == 'expired' else 'found', profile != 'expired'),
        ('X-Frame-Options Found (Deprecated)', 'not_found' if profile == 'missing' else 'found', True),
        ('X-XSS-Protection Found (Deprecated)', 'not_found' if profile == 'missing' else 'found', True),
        ('Duplicate HTTP Security Headers Found', 'not_found' if profile == 'missing' else 'found', True),
        ('SSLv2 Enabled', 'not_found', True), ('SSLv3 Enabled', 'not_found', True),
        ('TLSv1.0 Enabled', 'found', True), ('TLSv1.1 Enabled', 'found', True),
        ('SSL Certificate Using Weak Hashing Algorithm', 'found' if profile == 'expired' else 'not_found', True),
        ('Expired SSL Certificate', 'found' if profile == 'expired' else 'not_found', True),
    ]
    return {name: dict(status=status, verified=verified) for name, status, verified in states}


def validate(report, profile, folder):
    wanted = expected(profile)
    actual = {c['check']: c for c in report['checks']}
    errors = []
    if set(actual) != set(wanted) or len(report['checks']) != 22:
        errors.append('Check names/count do not match the 22 expected checks')
    for name, desired in wanted.items():
        check = actual.get(name, {})
        if any(check.get(key) != value for key, value in desired.items()):
            errors.append(name + ': expected ' + str(desired) + ', got ' + str({k: check.get(k) for k in desired}))
    parser = Rows()
    markup = (folder / 'verification.html').read_text()
    parser.feed(markup)
    visible = [c for c in report['checks'] if c['status'] == 'found' and c['verified'] is True]
    if len(parser.rows) != len(visible):
        errors.append('HTML must contain only found and verified result rows')
    by_name = {row[0]: row for row in parser.rows}
    if set(by_name) != {c['check'] for c in visible}:
        errors.append('HTML includes an unexpected or unverified finding')
    for check in visible:
        row = by_name.get(check['check'], [])
        if not row or row[0] != check['check']:
            errors.append('HTML/JSON status mismatch: ' + check['check'])
            continue
        for text in (json.dumps(check['evidence'], ensure_ascii=False, indent=2), check['note']):
            if text not in row[2]:
                errors.append('HTML/JSON evidence mismatch: ' + check['check'])
        if 'severity' in check or 'severity_rationale' in check:
            errors.append('Unexpected risk rating: ' + check['check'])
        for source in check.get('evidence_sources', []):
            if source['tool'] not in row[1]:
                errors.append('HTML/JSON source mismatch: ' + check['check'])
            artifact = source.get('artifact')
            if artifact and hashlib.sha256((folder/artifact).read_bytes()).hexdigest() != source['sha256']:
                errors.append('Evidence hash mismatch: ' + check['check'])
        if 'remediation' in check or len(row) != 3:
            errors.append('Unexpected remediation or extra result column: ' + check['check'])
    summary = json.loads((folder / 'summary.json').read_text())
    if summary['verification'] != report:
        errors.append('Embedded summary differs from verification.json')
    if 'verification.html' not in (folder / 'report.html').read_text():
        errors.append('Main report has no verification link')
    if markup.count('<script>') != 1:
        errors.append('Expected only the trusted theme script')
    if 'Disclaimer' not in markup or 'themeToggle' not in markup:
        errors.append('Missing disclaimer or theme control')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'results' / 'local-validation')
    parser.add_argument('--serve', action='store_true', help='Serve retained reports on loopback after validation')
    args = parser.parse_args()
    output = args.output_dir.resolve() / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output.mkdir(parents=True, mode=0o700)
    outcomes = []
    with tempfile.TemporaryDirectory(prefix='webraptor-fixture-') as temp:
        folder = Path(temp)
        certificates(folder)
        servers = dict(valid=target_server(folder, 'valid'), expired=target_server(folder, 'expired'))
        try:
            environment = dict(os.environ, SSL_CERT_FILE=str(folder / 'ca.pem'))
            for profile in ('missing', 'mixed', 'fingerprint', 'unknown', 'expired'):
                server = servers['expired' if profile == 'expired' else 'valid'][0]
                target = 'https://localhost:' + str(server.server_port) + '/' + profile
                destination = output / profile
                cli = [sys.executable, str(ROOT / 'webraptor.py'), target, '--modules', 'curl',
                       '--insecure', '--no-progress', '--tool-timeout', '90', '--probe-timeout', '8',
                       '--output-dir', str(destination)]
                print('Running local profile:', profile, flush=True)
                run = subprocess.run(cli, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=150)
                destination.mkdir(exist_ok=True)
                (destination / 'cli_stdout.log').write_text(run.stdout)
                (destination / 'cli_stderr.log').write_text(run.stderr)
                paths = list(destination.rglob('verification.json'))
                if len(paths) != 1:
                    outcomes.append(dict(profile=profile, errors=['Missing or duplicate verification report'], exit_code=run.returncode))
                    print(run.stdout[-1000:], run.stderr[-1000:], flush=True)
                    continue
                report = json.loads(paths[0].read_text())
                errors = validate(report, profile, paths[0].parent)
                expected_exit = 1 if profile == 'expired' else 0
                if run.returncode != expected_exit:
                    errors.append('Expected CLI exit ' + str(expected_exit) + ', got ' + str(run.returncode))
                outcome = dict(profile=profile, target=target, exit_code=run.returncode,
                               status_counts=dict(Counter(c['status'] for c in report['checks'])),
                               verified_observations=sum(c['verified'] for c in report['checks']),
                               report=str(paths[0].relative_to(output)), errors=errors)
                outcomes.append(outcome)
                print(json.dumps(outcome), flush=True)
        finally:
            for server, worker in servers.values():
                server.shutdown()
                server.server_close()
                worker.join()
    passed = all(not o['errors'] for o in outcomes) and len(outcomes) == 5
    manifest = dict(passed=passed, profiles=outcomes, notes=[
        'Real loopback HTTPS targets, curl and sslscan; no scanner results mocked.',
        'SSLv2/SSLv3 are known disabled on these fixture servers; positive classifications have unit coverage.',
        'Expired/SHA-1 certificates are intentionally untrusted; wildcard verification must remain unknown there.',
    ])
    (output / 'validation.json').write_text(json.dumps(manifest, indent=2))
    items = ''.join('<li>' + html.escape(o['profile']) + ': ' + ('PASS' if not o['errors'] else 'FAIL') +
                    ' <a href="' + html.escape(o.get('report', '').replace('verification.json', 'verification.html')) + '">HTML</a>' +
                    ' <a href="' + html.escape(o.get('report', '')) + '">JSON</a></li>' for o in outcomes)
    (output / 'index.html').write_text('<!doctype html><html><meta charset="utf-8"><title>WebRaptor local validation</title>'
        '<h1>Local fixture validation: ' + ('PASS' if passed else 'FAIL') + '</h1><p>Five loopback profiles; 22 checks per profile.</p><ul>' + items + '</ul></html>')
    print('VALIDATION:', 'PASS' if passed else 'FAIL', str(output), flush=True)
    if args.serve:
        class Reports(SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=str(output), **kw)
            def log_message(self, *unused):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Reports) as server:
            print('REPORT_PREVIEW=http://127.0.0.1:' + str(server.server_port) + '/index.html', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
