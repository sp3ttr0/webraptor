"""Scoped Katana capture and conservative secret-exposure candidates."""
from collections import Counter
from contextlib import contextmanager
import hashlib
import html
import hmac
import http.server
import json
import math
import os
import re
import select
import socket
import threading
import time
from urllib.parse import quote, urlsplit

import httpx

MAX_BODY = 2 * 1024 * 1024
PROVIDERS = (
    ('AWS access key ID', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('Google API key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('GitHub token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{40,255}\b')),
    ('Stripe secret key', re.compile(r'\bsk_live_[A-Za-z0-9]{16,255}\b')),
    ('Slack token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{16,255}\b')),
    ('JWT token', re.compile(r'\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{16,2048}\b')),
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{16,20000}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
)
SECRET_NAME = r'(?:api[_-]?key|api[_-]?secret|api[_-]?token|client[_-]?secret|app[_-]?secret|app[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|auth[_-]?secret|refresh[_-]?token|secret[_-]?key|private[_-]?key|encryption[_-]?key|consumer[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|password|passwd|db[_-]?password|database[_-]?password|authorization)'
ASSIGNMENT = re.compile(r'''(?ix)(?<![\w-])["']?(?P<name>''' + SECRET_NAME + r''')["']?\s*(?:=|:)\s*(?:["'`](?P<quoted>[^"'`\r\n]{8,512})["'`]|(?P<bare>[^\s,;<>"'`{}&]{8,512}))''')
PLACEHOLDER = re.compile(r'(?i)(?:redacted|example|placeholder|changeme|dummy|your[_ -]|insert[_ -]|process\.env|import\.meta|\$\{|^<|^\*+$|^x+$|^test(?:[_-]|$))')


def contextual_candidate(name, value):
    if not 8 <= len(value) <= 512 or PLACEHOLDER.search(value) or len(set(value)) < 4:
        return False
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())
    return 'pass' in name.lower() or len(value) >= 16 and entropy >= 3


def contextual_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and re.fullmatch(SECRET_NAME, str(key), re.I) and contextual_candidate(str(key), item):
                yield str(key), item
            yield from contextual_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from contextual_values(item)


def secret_matches(text):
    """Return candidate spans; format matches never imply a usable credential."""
    matches = []
    for name, pattern in PROVIDERS:
        for m in pattern.finditer(text):
            if not PLACEHOLDER.search(m[0]):
                matches.append((m.start(), m.end(), name, 'format match'))
    for m in ASSIGNMENT.finditer(text):
        group = 'quoted' if m['quoted'] is not None else 'bare'
        value = m[group]
        password = 'pass' in m['name'].lower()
        if contextual_candidate(m['name'], value):
            matches.append((m.start(group), m.end(group), 'Password assignment' if password else 'Sensitive assignment', 'context match'))
    # Prefer provider-specific matches when an assignment identifies the same value.
    unique = {}
    for match in matches:
        unique.setdefault(match[:2], match)
    return list(unique.values())


class SecretMask:
    """Keep detected values only in memory and mask their encoded variants."""
    def __init__(self):
        self.lock = threading.RLock()
        self.values = set()
        self.key = os.urandom(32)

    def remember(self, value):
        with self.lock:
            self.values.update((value, quote(value, safe=''), html.escape(value), json.dumps(value)[1:-1]))
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:16]

    def clean_text(self, text):
        for start, end, _, _ in secret_matches(text):
            self.remember(text[start:end])
        with self.lock:
            values = sorted(self.values, key=len, reverse=True)
        for value in values:
            text = text.replace(value, '[REDACTED]')
        return text

    def clean_tree(self, value):
        if isinstance(value, dict):
            # Learn contextual values before cleaning sibling strings.
            for key, item in value.items():
                if isinstance(item, str) and re.fullmatch(SECRET_NAME, str(key), re.I):
                    if contextual_candidate(str(key), item):
                        self.remember(item)
            return {self.clean_text(str(k)): ('[REDACTED]' if str(k).lower() in ('authorization', 'proxy-authorization', 'cookie', 'set-cookie') else self.clean_tree(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean_tree(v) for v in value]
        return self.clean_text(value) if isinstance(value, str) else value

    def __call__(self, text):
        try:
            value = json.loads(text)
            if isinstance(value, (dict, list)):
                ending = '\r\n' if text.endswith('\r\n') else '\n' if text.endswith('\n') else '\r' if text.endswith('\r') else ''
                return json.dumps(self.clean_tree(value), ensure_ascii=True) + ending
        except RecursionError:
            return '[REDACTED: structured content exceeds parsing depth]'
        except ValueError:
            pass
        return self.clean_text(text)


def origin(url):
    try:
        p = urlsplit(url)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password or '\\' in url:
            return None
        return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)
    except ValueError:
        return None


def scope_regex(target):
    scheme, host, port = origin(target)
    authority = '[' + host + ']' if ':' in host else host
    default = port == (443 if scheme == 'https' else 80)
    return '^' + re.escape(scheme + '://' + authority) + (r'(?::' + str(port) + r')?' if default else ':' + str(port)) + r'(?:/|\?|$)'


class DiscoveryCapture:
    def __init__(self, target, redact):
        self.target, self.redact = target, redact
        self.endpoints, self.findings = {}, {}
        self.invalid = 0

    def __call__(self, line):
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            return self.redact(line)
        if not isinstance(record, dict):
            self.invalid += 1
            return self.redact(line)
        request = record.get('request') if isinstance(record.get('request'), dict) else {}
        response = record.get('response') if isinstance(record.get('response'), dict) else {}
        url = request.get('endpoint', '')
        if not isinstance(url, str):
            self.invalid += 1
            return '{"ignored":"invalid_endpoint"}'
        if origin(url) != origin(self.target):
            return '{"ignored":"out_of_scope"}'
        status = response.get('status_code')
        body = response.get('body', '')
        if not isinstance(body, str):
            body = ''
        body = body[:MAX_BODY]
        inspect = body
        candidates = [(inspect[start:end], detector, confidence, start, end) for start,end,detector,confidence in secret_matches(inspect)]
        # Detect contextual JSON values structurally, including escaped quotes.
        try:
            decoded = json.loads(body)
            for name, value in contextual_values(decoded):
                encoded = json.dumps(value, ensure_ascii=False)[1:-1]
                start = body.find(encoded)
                if start < 0:
                    encoded = json.dumps(value)[1:-1]
                    start = body.find(encoded)
                candidates.append((value, 'Password assignment' if 'pass' in name.lower() else 'Sensitive assignment', 'context match', max(0,start), max(0,start)+len(encoded)))
        except (ValueError, RecursionError):
            pass
        # Register all values first so a context never exposes a neighboring value.
        for value, *_ in candidates:
            self.redact.masker.remember(value)
        for value, detector, confidence, start, end in candidates:
            identity = self.redact.masker.remember(value)
            finding_key = (url, detector, identity)
            context = inspect[max(0, start - 60):min(len(inspect), end + 60)]
            self.findings[finding_key] = dict(
                detector=detector, confidence=confidence, status='potential', verified=False,
                source_url=self.redact(url), http_status=status,
                line=inspect.count('\n', 0, start) + 1,
                secret_id=identity, value=self.redact(value), context=self.redact(context),
                note='Candidate exposure only. Public identifiers and examples can match. Credential validity and permissions were not tested.')
        source = request.get('source', '')
        source = source if isinstance(source, str) and origin(source) == origin(self.target) else ''
        self.endpoints[url] = dict(url=self.redact(url), method=request.get('method', 'GET'),
                                  http_status=status, source=self.redact(source),
                                  tag=str(request.get('tag', '')), attribute=str(request.get('attribute', '')))
        return self.redact(line)

    def result(self):
        # A later record may introduce a value also present in an earlier context.
        return dict(
            scope='Exact target origin (scheme, hostname and port); redirects disabled.',
            endpoints=list(self.endpoints.values()), secrets=list(self.findings.values()),
            note='Potential secret exposures require review; no detected credentials were used or validated.')


@contextmanager
def guarded_proxy(target, stop, timeout=8, insecure=False):
    """Block cross-origin network access even if a crawler scope check fails.

    HTTP requests are GET/HEAD-only. HTTPS tunnels permit only the exact target
    authority; Katana itself uses GET-only discovery with no form filling.
    """
    allowed = origin(target)
    closing = threading.Event()
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Request targets can contain credentials.

        def do_CONNECT(self):
            if allowed[0] != 'https' or origin('https://' + self.path) != allowed or stop.is_set():
                self.send_error(403, 'Outside crawl scope')
                return
            upstream = None
            try:
                upstream = socket.create_connection((allowed[1], allowed[2]), timeout=timeout)
                self.send_response(200); self.end_headers()
                sockets = (self.connection, upstream)
                deadline = time.monotonic() + timeout
                while not stop.is_set() and not closing.is_set() and time.monotonic() < deadline:
                    ready, _, _ = select.select(sockets, [], [], .2)
                    for source in ready:
                        block = source.recv(65536)
                        if not block:
                            return
                        (upstream if source is self.connection else self.connection).sendall(block)
                        deadline = time.monotonic() + timeout
            except OSError:
                pass
            finally:
                if upstream is not None:
                    upstream.close()

        def do_GET(self):
            if allowed[0] != 'http' or origin(self.path) != allowed or stop.is_set():
                self.send_error(403, 'Outside crawl scope')
                return
            try:
                headers = {k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','proxy-connection','proxy-authorization','transfer-encoding','content-length')}
                with httpx.Client(trust_env=False, follow_redirects=False, verify=not insecure, timeout=timeout) as client:
                    with client.stream(self.command, self.path, headers=headers) as response:
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            if size > MAX_BODY:
                                self.send_error(502, 'Response exceeds crawl size limit')
                                return
                            chunks.append(chunk)
                        body = b''.join(chunks)
                        self.send_response(response.status_code)
                        for k,v in response.headers.multi_items():
                            if k.lower() not in ('content-length','content-encoding','transfer-encoding','connection'):
                                self.send_header(k,v)
                        self.send_header('Content-Length',str(len(body))); self.end_headers()
                        if self.command != 'HEAD':
                            self.wfile.write(body)
            except (httpx.HTTPError, OSError):
                self.send_error(502, 'Scoped upstream request failed')

        do_HEAD = do_GET
        def do_POST(self):
            self.send_error(403, 'Form submission disabled')
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
    server.daemon_threads = True
    server.handle_error = lambda request, address: None  # Never print request-derived exceptions.
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port)
    finally:
        closing.set()
        server.shutdown();server.server_close();thread.join(timeout=2)
