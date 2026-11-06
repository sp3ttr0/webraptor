"""Evidence-based checks for one HTTP response and its original TLS endpoint.

A confirmed configuration observation is not proof of exploitability.
"""
from collections import Counter
from datetime import datetime, timezone
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import time
from urllib.parse import quote, urlsplit

from report_ui import page
import xml.etree.ElementTree as ET

import httpx

MAX_BODY = 2 * 1024 * 1024
SECURITY_HEADERS = (
    'strict-transport-security', 'content-security-policy',
    'content-security-policy-report-only', 'x-content-type-options',
    'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy',
    'cross-origin-resource-policy', 'cross-origin-embedder-policy',
    'x-frame-options', 'x-xss-protection',
)


def result(name, state, evidence=(), note='', verified=False):
    return dict(check=name, status=state, verified=verified,
                evidence=list(evidence), note=note)


def http_response_issue(snapshot, name):
    if snapshot.get('error'):
        return result(name, 'unknown', note=snapshot['error'])
    status = snapshot.get('http_status')
    if status != 200:
        return result(name, 'unknown', [dict(http_status=status)],
                      'HTTP 200 is required for HTTP header/content verification; this response is inconclusive.', False)
    return None


def header_check(snapshot, header, name):
    issue = http_response_issue(snapshot, name)
    if issue is not None:
        return issue
    values = [v for k, v in snapshot['headers'] if k.lower() == header]
    present = any(v.strip() for v in values)
    return result(name, 'not_found' if present else 'found',
                  [dict(header=header, values=values, http_status=snapshot['http_status'])],
                  'Presence check for this response only; policy correctness is separate.', True)


def check_hsts(s):
    if urlsplit(s['target']).scheme != 'https':
        return result('Strict Transport Security Not Implemented', 'not_applicable',
                      note='HSTS is only accepted over HTTPS; no HTTPS endpoint was inferred.')
    r = header_check(s, 'strict-transport-security', 'Strict Transport Security Not Implemented')
    if r['status'] == 'not_found':
        values = r['evidence'][0]['values']
        ages = [re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)', v, re.I) for v in values]
        if len(values) != 1 or not all(ages):
            r.update(status='potential', verified=False, note='Malformed or repeated HSTS; browser acceptance was not established.')
        elif not ages[0].group(1).strip('0'):
            r.update(status='found', note='max-age=0 disables HSTS for this host.')
    return r


def check_csp_missing(s):
    r = header_check(s, 'content-security-policy', 'Content Security Policy Not Implemented')
    if r['status'] == 'found' and s.get('meta_csp'):
        return result(r['check'], 'not_found', s['meta_csp'],
                      'A CSP meta policy was observed; it has narrower capabilities than an HTTP policy.', True)
    if r['status'] == 'found' and s.get('truncated'):
        return result(r['check'], 'unknown', note='Body truncated; a CSP meta policy may be outside the captured body.')
    return r


def check_x_content_type_options(s):
    return token_header_check(s, 'x-content-type-options', 'X-Content-Type-Options Not Implemented', {'nosniff'})


def check_referrer_policy(s):
    return token_header_check(s, 'referrer-policy', 'Referrer Policy Not Implemented',
                              {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
                               'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}, fallback=True)


def check_permissions_policy(s):
    return header_check(s, 'permissions-policy', 'Permissions Policy Not Implemented')


def check_coop(s):
    return token_header_check(s, 'cross-origin-opener-policy', 'Cross-Origin-Opener-Policy (COOP) Not Implemented',
                              {'unsafe-none', 'same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'})


def check_corp(s):
    return token_header_check(s, 'cross-origin-resource-policy', 'Cross-Origin-Resource-Policy (CORP) Not Implemented',
                              {'same-site', 'same-origin', 'cross-origin'})


def check_coep(s):
    return token_header_check(s, 'cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy (COEP) Not Implemented',
                              {'unsafe-none', 'require-corp', 'credentialless'})


def token_header_check(s, header, name, allowed, fallback=False):
    r = header_check(s, header, name)
    if r['status'] != 'not_found':
        return r
    values = r['evidence'][0]['values']
    if fallback:
        tokens = [value.strip() for v in values for value in v.split(',')]
    else:
        tokens = [(v.split(';')[0] if header.startswith('cross-origin-') else v).strip() for v in values]
    valid = any(t in allowed for t in tokens) if fallback else len(tokens) == 1 and tokens[0] in allowed
    if not valid:
        r.update(status='potential', verified=False, note='Header exists but its value is invalid or ambiguous; implementation is not verified.')
    elif tokens[-1] == 'unsafe-none':
        r.update(status='potential', verified=False, note='Explicit unsafe-none uses default behavior; isolation is not established.')
    return r


def check_insecure_csp(s):
    name = 'Insecure Content Security Policy (CSP)'
    issue = http_response_issue(s, name)
    if issue is not None:
        return issue
    policies = [v for k, v in s['headers'] if k.lower() == 'content-security-policy'] + s.get('meta_csp', [])
    if not policies:
        return result(name, 'not_applicable', note='No enforcing policy captured; see the missing-CSP check.')
    problems = []
    for policy in policies:
        directives = {}
        for clause in policy.split(';'):
            tokens = clause.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), tokens[1:])  # First duplicate directive wins.
        sources = directives.get('script-src', directives.get('default-src'))
        risks = []
        if sources is None:
            risks.append('Script sources unrestricted (no script-src/default-src).')
        else:
            nonce_hash = any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[^']+'", t) for t in sources)
            if "'unsafe-eval'" in sources:
                risks.append('unsafe-eval permits string evaluation.')
            if "'unsafe-inline'" in sources and not nonce_hash and "'strict-dynamic'" not in sources:
                risks.append('unsafe-inline without nonce/hash permits inline script.')
            if not (nonce_hash and "'strict-dynamic'" in sources) and any(t in ('*', 'http:', 'https:', 'data:') for t in sources):
                risks.append('Broad script source allowlist.')
        if risks:
            problems.append(dict(policy=policy, reasons=risks))
    return result(name, 'potential' if problems else 'not_found', problems,
                  'Static policy review only; multiple policies intersect. No browser bypass or XSS was demonstrated.', False)


def cipher_reasons(label, bits=''):
    """Classify observed suites, without treating SHA256/384 or AEAD as weak."""
    reasons = []
    if re.search(r'NULL|RC4|RC2|3DES|DES-CBC|EXPORT|(?:^|[_-])MD5(?:$|[_-])|(?:^|[_-])anon|^(?:ADH|AECDH|EXP)-', label, re.I):
        reasons.append('Weak encryption, authentication or export suite')
    if str(bits).isdigit() and int(bits) < 128:
        reasons.append('Encryption strength below 128 bits')
    if 'CBC' in label.upper() or re.search(r'^(?:ECDHE|DHE|RSA|AES|CAMELLIA|SEED|DES).*-(?:SHA|SHA256|SHA384)$', label, re.I) and not re.search(r'GCM|CCM|CHACHA', label, re.I):
        reasons.append('Deprecated CBC mode')
    if label.startswith('TLS_RSA_WITH_') or re.match(r'^(?:AES|CAMELLIA|SEED|DES|RC4|NULL)[0-9-]', label):
        reasons.append('Static RSA key exchange lacks forward secrecy')
    return reasons


def check_weak_tls_ciphers(s):
    name = 'Weak SSL/TLS Ciphers'
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    accepted = s.get('ciphers', [])
    weak = []
    for cipher in accepted + s.get('testssl_ciphers', []):
        reasons = cipher_reasons(cipher.get('cipher', ''), cipher.get('bits', ''))
        if reasons:
            weak.append(dict(cipher, reasons=reasons, source=cipher.get('source', 'sslscan')))
    if weak:
        return result(name, 'found', weak,
                      'Endpoint accepted weak or deprecated suites. CBC and static RSA are configuration observations, not proof of an exploitable attack.', True)
    return result(name, 'not_found' if s.get('cipher_scan_complete') and accepted else 'unknown',
                  note=s.get('cipher_error', 'No weak suite observed; probe coverage is not exhaustive.'))


def scanner_artifact(folder, modules, tool, suffix):
    """Only consume registered artifacts inside this target run; validate saved digests."""
    from hashlib import sha256
    module = next((item for item in modules if item.get('module') == tool), None)
    if module is None:
        return None, None
    for relative in module.get('artifacts', []):
        if not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
            continue
        path = folder/relative
        if not relative.endswith(suffix) or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(folder.resolve()):
            continue
        digest = module.get('artifact_hashes', {}).get(relative)
        if digest and sha256(path.read_bytes()).hexdigest() != digest:
            continue
        return path, module
    return None, module


def collect_testssl_ciphers(s, args, folder, stop, run_command, redact, modules=None):
    """Consume endpoint-scoped structured evidence; never infer acceptance from prose."""
    if s.get('tls_not_applicable') or stop.is_set():
        return
    p = urlsplit(s['target'])
    host, port = p.hostname, p.port or 443
    if modules is not None:
        path, module = scanner_artifact(folder, modules, 'testssl', '.json')
        if path is None:
            return
        run = module
        s['testssl_cipher_artifact'] = str(path.relative_to(folder))
    else:
        executable = shutil.which('testssl') or shutil.which('testssl.sh')
        if not executable:
            return
        endpoint = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
        path = folder / 'verification_testssl.json'
        run = run_command([executable, '--quiet', '--color', '0', '--warnings', 'batch',
                           '--nodns', 'none', '--each-cipher', '--wide', '--jsonfile', str(path), endpoint],
                          folder / 'verification_testssl_stdout.log', folder / 'verification_testssl_stderr.log',
                          args.tool_timeout, stop, redact)
    try:
        rows = json.loads(path.read_text())
        if not isinstance(rows, list):
            return
        accepted = []
        for row in rows:
            if not isinstance(row, dict) or str(row.get('port')) != str(port):
                continue
            # testssl records NODE/NODEIP; exact original host must match.
            if str(row.get('ip', '')).split('/')[0].strip('[]').lower() != host.lower():
                continue
            if not re.fullmatch(r'cipher(?:-(?:ssl2|ssl3|tls1|tls1_1|tls1_2|tls1_3))?_[0-9a-fA-Fx]+', row.get('id', '')):
                continue
            finding = row.get('finding', '')
            if 'not a/v' in finding or 'not available' in finding.lower():
                continue
            # Only positive per-suite rows from --each-cipher are emitted by default.
            match = re.search(r'(?<![A-Za-z0-9_])(?:TLS_[A-Z0-9_]+|(?:ECDHE|DHE|ADH|AECDH|AES|CAMELLIA|SEED|DES|RC4|RC2|NULL|EXP)[A-Za-z0-9_-]+)', finding)
            if match:
                accepted.append(dict(cipher=match.group(), source='testssl', observation=finding, probe_id=row['id']))
        s['testssl_ciphers'] = accepted
        s['testssl_cipher_valid'] = bool(accepted)
        s['testssl_cipher_complete'] = run['status'] == 'completed'
    except (OSError, ValueError, TypeError):
        pass


def check_tls13_disabled(s):
    name = 'TLSv1.3 Disabled'
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    status = s.get('tls13', 'unknown')
    return result(name, {'enabled': 'not_found', 'rejected': 'found'}.get(status, 'unknown'),
                  s.get('tls13_evidence', []),
                  'An explicit protocol-version rejection confirms rejection from this client vantage point; other handshake failures are inconclusive.',
                  status in ('enabled', 'rejected'))


def legacy_protocol(s, protocol, version, name):
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    evidence = [p for p in s.get('protocols', [])
                if p.get('type') == protocol and p.get('version') == version]
    accepted = [c for c in s.get('ciphers', [])
                if c.get('sslversion') == ('SSLv' if protocol == 'ssl' else 'TLSv') + version]
    if accepted or any(p.get('enabled') == '1' for p in evidence):
        return result(name, 'found', evidence + accepted,
                      'Endpoint-matched sslscan positively observed protocol acceptance.', True)
    if (evidence and all(p.get('enabled') == '0' for p in evidence)
            and s.get('cipher_scan_complete') and s.get('ciphers')):
        return result(name, 'not_found', evidence,
                      'No acceptance in this completed sslscan run; other protocols were reachable.', True)
    return result(name, 'unknown', evidence,
                  'Missing or incomplete protocol evidence is not proof the protocol is disabled.')


def check_sslv2_enabled(s):
    return legacy_protocol(s, 'ssl', '2', 'SSLv2 Enabled')


def check_sslv3_enabled(s):
    return legacy_protocol(s, 'ssl', '3', 'SSLv3 Enabled')


def check_tls10_enabled(s):
    return legacy_protocol(s, 'tls', '1.0', 'TLSv1.0 Enabled')


def check_tls11_enabled(s):
    return legacy_protocol(s, 'tls', '1.1', 'TLSv1.1 Enabled')


def check_weak_certificate_hash(s):
    name = 'SSL Certificate Using Weak Hashing Algorithm'
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    algorithm = s.get('certificate_signature', '')
    compact = re.sub(r'[^a-z0-9]', '', algorithm.lower())
    evidence = [dict(signature_algorithm=algorithm, source='sslscan leaf certificate', chain_validated=False)] if algorithm else []
    if re.search(r'md[245]|sha1(?![0-9])', compact):
        return result(name, 'found', evidence, 'Weak leaf-certificate signature digest observed; chain trust is a separate check.', True)
    if any(token in compact for token in ('sha256', 'sha384', 'sha512', 'sha3', 'ed25519', 'ed448')):
        return result(name, 'not_found', evidence, 'No listed weak digest observed in the leaf signature.', True)
    return result(name, 'unknown', evidence, 'Missing, unknown or ambiguous leaf signature digest.')


def check_expired_certificate(s):
    name = 'Expired SSL Certificate'
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    value = s.get('certificate_not_after')
    try:
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return result(name, 'unknown', note='No parseable leaf certificate expiry captured.')
    now = datetime.now(timezone.utc)
    return result(name, 'found' if expiry <= now else 'not_found',
                  [dict(not_after=expiry.isoformat(), checked_at=now.isoformat(),
                        source='leaf certificate', chain_validated=s.get('certificate_chain_validated', False))],
                  'UTC leaf-certificate expiry compared with the local clock; chain and hostname trust are separate.', True)


def check_breach(s):
    name = 'HTTP Compression Enabled (BREACH Vulnerability)'
    issue = http_response_issue(s, name)
    if issue is not None:
        return issue
    encodings = [v for k, v in s['headers'] if k.lower() == 'content-encoding']
    compressed = any(t.strip().lower() not in ('', 'identity') for v in encodings for t in v.split(','))
    return result(name, 'potential' if compressed else 'not_found', [dict(content_encoding=encodings)],
                  'Compression alone does not verify BREACH. Secret-bearing responses, attacker-controlled reflection and a usable length oracle must also be established.', False)


def check_wildcard_certificate(s):
    name = 'Wildcard SSL Certificates in Use'
    if s.get('tls_not_applicable'):
        return result(name, 'not_applicable')
    if 'certificate_names' not in s:
        return result(name, 'unknown', note=s.get('certificate_error', 'No verified peer certificate obtained.'))
    names = [n for n in s['certificate_names'] if '*' in n]
    return result(name, 'found' if names else 'not_found', names,
                  'Certificate configuration observation; wildcard use alone is not a vulnerability.', True)


def deprecated_header(s, header, name):
    r = header_check(s, header, name)
    if r['status'] == 'unknown':
        return r
    if r['status'] in ('found', 'not_found'):
        r['status'] = 'not_found' if r['status'] == 'found' else 'found'
    r['note'] = ('Header presence observed. X-Frame-Options remains useful for legacy clients; prefer CSP frame-ancestors.'
                 if header == 'x-frame-options' else 'Legacy header observed; presence alone does not establish an exploitable vulnerability.')
    return r


def check_x_frame_options(s):
    return deprecated_header(s, 'x-frame-options', 'X-Frame-Options Found (Deprecated)')


def check_x_xss_protection(s):
    return deprecated_header(s, 'x-xss-protection', 'X-XSS-Protection Found (Deprecated)')


def check_duplicate_security_headers(s):
    name = 'Duplicate HTTP Security Headers Found'
    issue = http_response_issue(s, name)
    if issue is not None:
        return issue
    counts = Counter(k.lower() for k, _ in s['headers'] if k.lower() in SECURITY_HEADERS)
    duplicates = [dict(header=k, count=n, values=[v for h, v in s['headers'] if h.lower() == k])
                  for k, n in counts.items() if n > 1]
    return result(name, 'found' if duplicates else 'not_found', duplicates,
                  'Repeated fields are observed, not automatically invalid: multiple CSP policies can be intentional.', True)


CHECKS = (check_hsts, check_csp_missing, check_x_content_type_options, check_referrer_policy,
          check_permissions_policy, check_coop, check_corp, check_coep, check_insecure_csp,
          check_weak_tls_ciphers, check_tls13_disabled,
          check_breach, check_wildcard_certificate, check_x_frame_options,
          check_x_xss_protection, check_duplicate_security_headers,
          check_sslv2_enabled, check_sslv3_enabled, check_tls10_enabled, check_tls11_enabled,
          check_weak_certificate_hash, check_expired_certificate)


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta_csp = []
        self.in_head = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'head':
            self.in_head = True
        if tag == 'meta' and self.in_head and attrs.get('http-equiv', '').lower() == 'content-security-policy' and attrs.get('content'):
            self.meta_csp.append(attrs['content'])

    def handle_endtag(self, tag):
        if tag == 'head':
            self.in_head = False


def fetch(client, url, stop, timeout):
    deadline = time.monotonic() + timeout
    with client.stream('GET', url) as response:
        body = bytearray()
        truncated = False
        for chunk in response.iter_bytes():
            if stop.is_set() or time.monotonic() >= deadline:
                raise httpx.ReadTimeout('Verification request interrupted or exceeded its time budget')
            body.extend(chunk[:MAX_BODY + 1 - len(body)])
            if len(body) > MAX_BODY:
                truncated = True
                break
        return response, bytes(body[:MAX_BODY]), truncated


def collect_http(target, args, stop):
    s = dict(target=target, headers=[])
    if stop.is_set():
        s['error'] = 'Cancelled'
        return s
    try:
        with httpx.Client(headers=dict(args.headers), timeout=args.probe_timeout,
                          verify=not args.insecure, follow_redirects=False,
                          trust_env=False) as client:
            response, body, truncated = fetch(client, target, stop, args.probe_timeout)
            s.update(headers=list(response.headers.multi_items()), http_status=response.status_code,
                     truncated=truncated, certificate_validation=not args.insecure,
                     server=response.headers.get('server') or 'Not disclosed')
            page = Page()
            if 'html' in response.headers.get('content-type', '').lower():
                page.feed(body.decode(response.encoding or 'utf-8', errors='replace'))
            s['meta_csp'] = page.meta_csp
    except (httpx.HTTPError, ValueError, UnicodeError) as exc:
        s['error'] = type(exc).__name__
    return s


def collect_tls(s, args, folder, stop, run_command, redact, modules=None):
    p = urlsplit(s['target'])
    if p.scheme != 'https':
        s['tls_not_applicable'] = True
        return
    host, port = p.hostname, p.port or 443
    if stop.is_set():
        return
    # Certificate validation remains enabled here even with --insecure. An
    # untrusted certificate must not be reported as verified endpoint identity.
    try:
        with socket.create_connection((host, port), timeout=args.probe_timeout) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as peer:
                cert = peer.getpeercert()
                s['certificate_chain_validated'] = True
                if cert.get('notAfter'):
                    s['certificate_not_after'] = cert['notAfter']
                s['certificate_names'] = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
                if not s['certificate_names']:
                    s['certificate_names'] = [v for part in cert.get('subject', []) for k, v in part if k == 'commonName']
    except (OSError, ssl.SSLError) as exc:
        s['certificate_error'] = type(exc).__name__
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, port), timeout=args.probe_timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as peer:
                s['tls13'] = 'enabled' if peer.version() == 'TLSv1.3' else 'unknown'
                s['tls13_evidence'] = [dict(protocol=peer.version(), certificate_validated=False)]
    except ssl.SSLError as exc:
        s['tls13'] = 'rejected' if exc.reason == 'TLSV1_ALERT_PROTOCOL_VERSION' else 'unknown'
        s['tls13_evidence'] = [dict(error=exc.reason)]
    except (OSError, ValueError, AttributeError) as exc:
        s['tls13_evidence'] = [dict(error=type(exc).__name__)]
    if modules is not None:
        path, run = scanner_artifact(folder, modules, 'sslscan', '.xml')
        if path is None:
            s['cipher_error'] = 'No usable registered sslscan XML; no duplicate scan was launched.'
            return
        s['cipher_artifact'] = str(path.relative_to(folder))
    else:
        executable = shutil.which('sslscan')
        if not executable or stop.is_set():
            s['cipher_error'] = 'sslscan is unavailable or the run was cancelled.'
            return
        endpoint = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
        path = folder / 'verification_tls.xml'
        run = run_command([executable, '--no-colour', '--xml=' + str(path), endpoint],
                          folder / 'verification_tls_stdout.log', folder / 'verification_tls_stderr.log',
                          args.tool_timeout, stop, redact)
    if path:
        s['cipher_scan_complete'] = run['status'] == 'completed'
        try:
            root = ET.parse(path).getroot()
            tests = root.findall('.//ssltest')
            if len(tests) != 1 or tests[0].get('host') != host or tests[0].get('port') != str(port):
                raise ValueError('Endpoint mismatch')
            s['tls_xml_valid'] = True
            s['ciphers'] = [dict(c.attrib) for c in tests[0].findall('cipher') if c.get('status', '').lower() in ('accepted', 'preferred')]
            s['protocols'] = [dict(p.attrib) for p in tests[0].findall('protocol')]
            # The default short certificate is the endpoint's leaf, not a CA
            # certificate taken from an arbitrary chain position.
            cert = tests[0].find("./certificates/certificate[@type='short']")
            if cert is None:
                cert = tests[0].find("./certificate[@type='short']")  # sslscan 1.x layout
            if cert is not None:
                s['certificate_signature'] = (cert.findtext('signature-algorithm') or '').strip()
                if not s.get('certificate_not_after'):
                    s['certificate_not_after'] = (cert.findtext('not-valid-after') or '').strip()
        except (OSError, ET.ParseError, ValueError):
            s['cipher_scan_complete'] = False
            s['cipher_error'] = 'Missing, invalid or mismatched sslscan XML.'


# Per-check context; risk ratings and remediation are intentionally omitted.
GUIDANCE = {'Strict Transport Security Not Implemented': 'HTTPS downgrade protection is absent or disabled.',
 'Content Security Policy Not Implemented': 'An enforcing content policy can reduce script-injection impact.',
 'X-Content-Type-Options Not Implemented': 'Missing or ambiguous MIME-sniffing protection.',
 'Referrer Policy Not Implemented': 'Referrer information may be disclosed more broadly than intended.',
 'Permissions Policy Not Implemented': 'Browser capabilities lack an explicit application policy.',
 'Cross-Origin-Opener-Policy (COOP) Not Implemented': 'Browsing-context isolation depends on application '
                                                      'requirements.',
 'Cross-Origin-Resource-Policy (CORP) Not Implemented': 'Resource embedding policy is not explicitly '
                                                        'constrained.',
 'Cross-Origin-Embedder-Policy (COEP) Not Implemented': 'Cross-origin isolation is contextual rather than '
                                                        'universally required.',
 'Insecure Content Security Policy (CSP)': 'Broad script permissions can weaken injection defenses; a bypass '
                                           'has not been demonstrated.',
 'Weak SSL/TLS Ciphers': 'Accepted anonymous or weak cryptographic suites can undermine TLS confidentiality '
                         'or authentication.',
 'TLSv1.3 Disabled': 'Modern protocol support is desirable; secure TLS 1.2 can remain acceptable.',
 'HTTP Compression Enabled (BREACH Vulnerability)': 'Compression alone is not proof of a secret-recovery '
                                                    'vulnerability.',
 'Wildcard SSL Certificates in Use': 'Wildcard use alone is not a vulnerability.',
 'X-Frame-Options Found (Deprecated)': 'This legacy header can still protect older clients.',
 'X-XSS-Protection Found (Deprecated)': 'Presence alone does not prove exploitability; value 0 disables the '
                                        'legacy filter.',
 'Duplicate HTTP Security Headers Found': 'Conflicting singleton headers may be ignored; repeated CSP '
                                          'policies can be intentional.',
 'SSLv2 Enabled': 'SSLv2 is obsolete and cryptographically unsafe.',
 'SSLv3 Enabled': 'SSLv3 is obsolete and susceptible to known protocol weaknesses.',
 'TLSv1.0 Enabled': 'TLS 1.0 is obsolete and lacks modern protocol protections.',
 'TLSv1.1 Enabled': 'TLS 1.1 is obsolete and lacks modern protocol protections.',
 'SSL Certificate Using Weak Hashing Algorithm': 'Weak certificate signature digests lack modern collision '
                                                 'resistance.',
 'Expired SSL Certificate': 'Expired certificates break normal authenticated TLS access.'}

GROUPS = (
    ('verified', 'Verified findings', 'The stated observation was evidenced; this does not prove exploitability.'),
    ('potential', 'Potential findings', 'Risk indicators require context or additional validation.'),
    ('unknown', 'Unknown results', 'Insufficient evidence. These results are not clean assessments.'),
    ('not_found', 'Not found', 'The specific condition was not observed within the tested scope.'),
    ('not_applicable', 'Not applicable', 'The check did not apply to the captured response or endpoint.'),
)
def enrich_finding(finding):
    finding = dict(finding)
    finding.pop('severity', None)
    finding.pop('severity_rationale', None)
    finding.pop('remediation', None)
    context = GUIDANCE.get(finding['check'], 'Review the evidence and application context.')
    status = finding['status']
    group = ('verified' if finding.get('verified') else 'potential') if status == 'found' else status
    if group not in {g[0] for g in GROUPS}:
        group = 'unknown'
    if group == 'unknown':
        context = 'Evidence is insufficient to assess this condition.'
    finding.update(group=group, context=context)
    return finding


def render_raw_link(source):
    artifact = source.get('artifact')
    if isinstance(artifact, str) and not Path(artifact).is_absolute() and '..' not in Path(artifact).parts:
        return '<a href="' + html.escape(quote(artifact, safe='/'), quote=True) + '">Open raw file</a>'
    return ''


def render_sources(sources, compact=False):
    blocks = []
    for source in sources:
        tool = html.escape(str(source.get('tool', 'Unrecorded source')))
        artifact = source.get('artifact')
        link = ''
        if isinstance(artifact, str) and not Path(artifact).is_absolute() and '..' not in Path(artifact).parts:
            link = '<a href="' + html.escape(quote(artifact, safe='/'), quote=True) + '">' + html.escape(artifact) + '</a>'
        blocks.append('<div class="tool-source"><strong>' + tool + '</strong><small>' +
                      html.escape(str(source.get('role', 'primary'))) + ' · ' +
                      html.escape(str(source.get('status', 'unavailable'))) + '</small>' + link +
                      '<small>' + html.escape(str(source.get('method', ''))) + '</small>' +
                      ('<small>Reused scanner artifact from a previous run.</small>' if source.get('reused') else '') +
                      ('<pre class="raw-evidence">' + html.escape(source['raw_output']) + '</pre>'
                       if source.get('raw_output') else '') + '</div>')
    if compact:
        candidates = [source for source in sources if source.get('raw_output', '').strip() and source.get('tool') != 'curl']
        # One viewer per tool. Prefer full testssl scanner output, then dedicated probes.
        candidates.sort(key=lambda source: (0 if source.get('tool') == 'testssl' and source.get('role') == 'supplementary scanner output' else 1 if source.get('role') == 'raw scanner output' else 2))
        selected = {}
        for source in candidates:
            selected.setdefault(source.get('tool'), source)
        raw = sorted(selected.values(), key=lambda source: (source.get('tool') != 'testssl', source.get('tool') != 'sslscan'))
        viewers = []
        for index, source in enumerate(raw):
            tool = html.escape(str(source.get('tool', 'Scanner')))
            viewers.append('<details class="evidence-viewer"' + (' open' if index == 0 else '') +
                           '><summary>' + tool + ' · Raw evidence</summary><div class="evidence-body">' +
                           '<div class="evidence-toolbar"><span>' + html.escape(str(source.get('status', 'captured'))) +
                           (' · Supplementary scanner output' if source.get('role') == 'supplementary scanner output' else '') +
                           '</span>' + render_raw_link(source) + '</div><p class="evidence-method">' + html.escape(str(source.get('method', ''))) + '</p><pre class="raw-evidence">' +
                           html.escape(source['raw_output']) + '</pre></div></details>')
        supporting = [dict(source, raw_output=source.get('raw_output', '') if source.get('tool') == 'curl' else '', method='HEAD · Redirects followed' if source.get('tool') == 'curl' else source.get('method', '')) for source in sources if not any(source is chosen for chosen in raw)]
        if supporting:
            viewers.append('<details class="evidence-viewer supporting-files"><summary>Supporting files</summary>' +
                           '<div class="evidence-body">' + render_sources(supporting) + '</div></details>')
        return ''.join(viewers)
    return ''.join(blocks) or '<span class="muted">No source recorded; evidence provenance is unavailable.</span>'


def render_report(report):
    esc = lambda value: html.escape(str(value))
    checks = [enrich_finding(finding) for finding in report['checks']
              if finding.get('status') == 'found' and finding.get('verified') is True]
    rows = []
    for f in sorted(checks, key=lambda finding: finding['check']):
        rows.append('<details class="finding" data-group="' + esc(f['group']) + '"><summary>' + esc(f['check']) +
            '</summary><div class="finding-content"><div data-field="sources"><h3>Tool / probe evidence</h3>' +
            render_sources(f.get('evidence_sources', []), compact=True) + '</div><div data-field="evidence"><h3>Evidence / limits</h3>' +
            ('' if any(source.get('raw_output') for source in f.get('evidence_sources', [])) and not any(source.get('tool') == 'WebRaptor HTTP collector (httpx)' for source in f.get('evidence_sources', [])) else
             '<pre>' + esc(json.dumps(f['evidence'], ensure_ascii=False, indent=2)) + '</pre>') + '<p>' + esc(f['note']) +
            '</p><p class="muted">' + esc(f['context']) + '</p></div></div></details>')
    body = '<section class="finding-group scanner-section" id="findings-summary"><div class="findings-header"><h2>Findings Summary <span class="finding-count" aria-label="' + str(len(checks)) + ' findings">' + str(len(checks)) + '</span></h2>'
    if rows:
        body += '<div class="finding-controls" role="group" aria-label="Finding controls"><button type="button" id="expandAll" aria-controls="findings-summary" aria-label="Expand all findings" title="Expand all findings"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 8 5-5 5 5M7 16l5 5 5-5M5 12h14"/></svg></button><button type="button" id="collapseAll" aria-controls="findings-summary" aria-label="Collapse all findings" title="Collapse all findings"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 3 5 5 5-5M7 21l5-5 5 5M5 12h14"/></svg></button></div>'
    body += '</div><p class="group-intro">Verified findings for this target, with supporting tool evidence.</p>'
    body += ''.join(rows) if rows else '<p class="muted">No findings met the found-and-verified criteria. Review the complete check record for coverage and incomplete checks.</p>'
    body += '</section>'
    from scanner_report import render_scanner_results
    body = render_scanner_results(report.get('scanner_results', [])) + body
    return page('WebRaptor Web Application Security Assessment Report', body, report['target'],
                {'Server': report.get('server', 'Not recorded'), 'HTTP response': report.get('http_status'),
                 'Checked': report.get('checked_at', 'not recorded'), 'Scope': report.get('scope')})



def redact_tree(value, redact):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_tree(item, redact) for item in value]
    if isinstance(value, dict):
        return {redact(str(key)): redact_tree(item, redact) for key, item in value.items()}
    return value


def capture_sources(snapshot, folder, redact):
    """Persist the actual collector/probe evidence, excluding unrelated headers."""
    selected = set(SECURITY_HEADERS) | {'content-type', 'content-encoding', 'server'}
    http = dict(target=snapshot['target'], method='GET', redirects_followed=False,
                http_status=snapshot.get('http_status'), server=snapshot.get('server'), error=snapshot.get('error'),
                certificate_validation=snapshot.get('certificate_validation'),
                headers=[(k, v) for k, v in snapshot['headers'] if k.lower() in selected],
                meta_csp=snapshot.get('meta_csp', []), truncated=snapshot.get('truncated'))
    tls = {key: snapshot[key] for key in ('target', 'tls13', 'tls13_evidence', 'certificate_names',
           'certificate_not_after', 'certificate_error', 'certificate_chain_validated', 'tls_not_applicable') if key in snapshot}
    for name, data in (('verification_http.json', http), ('verification_tls_probes.json', tls)):
        (folder / name).write_text(json.dumps(redact_tree(data, redact), indent=2), encoding='utf-8')


def attach_sources(finding, snapshot, folder, modules):
    from hashlib import sha256
    finding = dict(finding)
    name = finding['check']
    tls_checks = {'Weak SSL/TLS Ciphers', 'TLSv1.3 Disabled', 'Wildcard SSL Certificates in Use',
                  'SSLv2 Enabled', 'SSLv3 Enabled', 'TLSv1.0 Enabled', 'TLSv1.1 Enabled',
                  'SSL Certificate Using Weak Hashing Algorithm', 'Expired SSL Certificate'}
    is_tls = name in tls_checks
    direct_tls = name in {'TLSv1.3 Disabled', 'Wildcard SSL Certificates in Use'} or (
        name == 'Expired SSL Certificate' and snapshot.get('certificate_chain_validated'))
    if not is_tls:
        primary = dict(tool='WebRaptor HTTP collector (httpx)', artifact='verification_http.json',
                       method='GET of the exact target URL; duplicate fields preserved; no redirects.',
                       status='unavailable' if snapshot.get('error') else 'captured', role='primary')
    elif direct_tls:
        primary = dict(tool='WebRaptor TLS probe (Python ssl)', artifact='verification_tls_probes.json',
                       method='Version-restricted handshake or validated peer-certificate inspection.',
                       status='not applicable' if snapshot.get('tls_not_applicable') else
                       'captured' if (snapshot.get('tls13_evidence') if name == 'TLSv1.3 Disabled' else snapshot.get('certificate_chain_validated')) else 'unavailable', role='primary')
    else:
        primary = dict(tool='sslscan', method='Endpoint-matched protocol, accepted-cipher or leaf-certificate XML.',
                       status='not applicable' if snapshot.get('tls_not_applicable') else
                       'captured' if snapshot.get('tls_xml_valid') else 'unavailable', role='primary')
        if snapshot.get('tls_xml_valid'):
            primary['artifact'] = snapshot.get('cipher_artifact', 'verification_tls.xml')
            if not snapshot.get('cipher_scan_complete'):
                primary['status'] = 'partial'
    sources = [primary]
    if name == 'Weak SSL/TLS Ciphers' and snapshot.get('testssl_cipher_valid'):
        sources.append(dict(tool='testssl', artifact=snapshot.get('testssl_cipher_artifact', 'verification_testssl.json'), role='primary',
                            status='captured' if snapshot.get('testssl_cipher_complete') else 'partial',
                            method='Endpoint-matched accepted per-suite JSON observations.'))
    for module in modules:
        if module.get('module') not in ({'sslscan', 'testssl'} if is_tls else {'curl'}):
            continue
        for relative in module.get('artifacts', []):
            path = folder / relative
            if (not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts
                    or not path.is_file() or not path.resolve().is_relative_to(folder.resolve())):
                continue
            if not relative.endswith('_results.txt'):
                continue
            sources.append(dict(tool=module['module'], artifact=relative, status=module['status'],
                role='supplementary scanner output', reused=bool(module.get('reused_from')),
                method=('HEAD · Redirects followed'
                        if module['module'] == 'curl' else 'Scanner output; not independently correlated with this check.'),
                sha256=sha256(path.read_bytes()).hexdigest(),
                raw_output=path.read_text(encoding='utf-8', errors='replace') if is_tls or module['module'] == 'curl' else ''))
    # Embed saved, already-redacted scanner output verbatim, never reconstructed rows.
    raw_sources = []
    for tool in (('sslscan', 'testssl') if name == 'Weak SSL/TLS Ciphers' else ('sslscan',)) if is_tls else ():
        filename = 'verification_tls_stdout.log' if tool == 'sslscan' else 'verification_testssl_stdout.log'
        path = folder / filename
        if path.is_file() and path.resolve().is_relative_to(folder.resolve()):
            output = path.read_text(encoding='utf-8', errors='replace')
            if output.strip():
                raw_sources.append(dict(tool=tool, artifact=filename, role='raw scanner output',
                                        status='captured', method='Saved probe stdout, with configured secrets redacted.',
                                        raw_output=output))
    sources.extend(raw_sources)
    for source in sources:
        artifact = source.get('artifact')
        if artifact and (folder / artifact).is_file():
            source['sha256'] = sha256((folder / artifact).read_bytes()).hexdigest()
    finding['evidence_sources'] = sources
    return finding



def assess_target(target, args, folder, stop, run_command, redact, modules=()):
    """Run fresh verification inside a normal target workflow, including resume."""
    snapshot = collect_http(target, args, stop)
    collect_tls(snapshot, args, folder, stop, run_command, redact, modules)
    collect_testssl_ciphers(snapshot, args, folder, stop, run_command, redact, modules)
    for path in list(folder.glob('verification_tls*')) + list(folder.glob('verification_testssl*')):
        if path.is_file():
            path.write_text(redact(path.read_text(encoding='utf-8', errors='replace')), encoding='utf-8')
    capture_sources(snapshot, folder, redact)
    report = dict(target=target, checked_at=datetime.now(timezone.utc).isoformat(),
                  scope='Exact URL response and original TLS host/port; no redirects or cross-origin scripts.',
                  checks=[attach_sources(enrich_finding(check(snapshot)), snapshot, folder, modules) for check in CHECKS],
                  http_status=snapshot.get('http_status'),
                  server=snapshot.get('server', 'Unavailable' if snapshot.get('error') else 'Not recorded'),
                  http_certificate_validation=snapshot.get('certificate_validation'))
    from scanner_report import collect_scanner_results
    report['scanner_results'] = collect_scanner_results(modules, folder)
    report['status'] = ('cancelled' if stop.is_set() else
                        'incomplete' if any(c['status'] == 'unknown' for c in report['checks']) else 'completed')
    report = redact_tree(report, redact)
    (folder / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (folder / 'report.html').write_text(render_report(report), encoding='utf-8')
    return report
