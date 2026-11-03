import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verification as v
import webraptor as w


def snapshot(headers=(), **extra):
    return dict(target='https://example.test/', headers=list(headers), http_status=200, **extra)


def args(**extra):
    values = dict(headers=[], insecure=False, probe_timeout=2, tool_timeout=2)
    values.update(extra)
    return SimpleNamespace(**values)


class FindingChecks(unittest.TestCase):
    def test_all_twenty_two_have_distinct_names_and_unknown_is_not_absence(self):
        results = [check(snapshot(error='ConnectError')) for check in v.CHECKS]
        self.assertEqual(len(results), 22)
        self.assertEqual(len({r['check'] for r in results}), 22)
        self.assertTrue(all(r['status'] == 'unknown' for r in results), results)
        self.assertTrue(all(not r['verified'] for r in results))

    def test_missing_and_present_headers_case_insensitive(self):
        names = ('strict-transport-security', 'content-security-policy', 'x-content-type-options',
                 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy',
                 'cross-origin-resource-policy', 'cross-origin-embedder-policy')
        values = ('max-age=31536000', "default-src 'self'", 'nosniff', 'no-referrer',
                  'camera=()', 'same-origin', 'same-origin', 'require-corp')
        present = snapshot(zip([name.upper() for name in names], values))
        for check in v.CHECKS[:8]:
            with self.subTest(check=check.__name__):
                self.assertEqual(check(snapshot())['status'], 'found')
                self.assertEqual(check(present)['status'], 'not_found')

    def test_hsts_disabled_malformed_and_http_scope(self):
        self.assertEqual(v.check_hsts(snapshot([('strict-transport-security', 'max-age=0')]))['status'], 'found')
        self.assertEqual(v.check_hsts(snapshot([('strict-transport-security', 'max-age=invalid')]))['status'], 'potential')
        s = snapshot()
        s['target'] = 'http://example.test/'
        self.assertEqual(v.check_hsts(s)['status'], 'not_applicable')

    def test_invalid_header_values_do_not_pass_as_implemented(self):
        cases = ((v.check_x_content_type_options, 'x-content-type-options', 'nosniff;garbage'),
                 (v.check_referrer_policy, 'referrer-policy', 'nonsense'),
                 (v.check_coop, 'cross-origin-opener-policy', 'unsafe-none'),
                 (v.check_corp, 'cross-origin-resource-policy', 'nonsense'),
                 (v.check_coep, 'cross-origin-embedder-policy', 'unsafe-none'))
        for check, header, value in cases:
            with self.subTest(header=header):
                self.assertEqual(check(snapshot([(header, value)]))['status'], 'potential')
        self.assertEqual(v.check_referrer_policy(snapshot([('referrer-policy', 'nonsense, no-referrer')]))['status'], 'not_found')

    def test_report_only_does_not_enforce_csp_and_meta_is_recognized(self):
        s = snapshot([('content-security-policy-report-only', "default-src 'none'")])
        self.assertEqual(v.check_csp_missing(s)['status'], 'found')
        s['meta_csp'] = ["default-src 'self'"]
        self.assertEqual(v.check_csp_missing(s)['status'], 'not_found')
        self.assertEqual(v.check_csp_missing(snapshot(truncated=True))['status'], 'unknown')

    def test_csp_risks_do_not_claim_bypass_and_nonce_fallback_is_not_flagged(self):
        for policy in ("script-src * 'unsafe-inline'", "default-src 'unsafe-eval'", 'img-src *'):
            r = v.check_insecure_csp(snapshot([('content-security-policy', policy)]))
            self.assertEqual(r['status'], 'potential')
            self.assertFalse(r['verified'])
        safe = "script-src 'nonce-abcdef' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'"
        self.assertEqual(v.check_insecure_csp(snapshot([('content-security-policy', safe)]))['status'], 'not_found')
        # The first occurrence of a repeated directive wins.
        s = snapshot([('content-security-policy', "script-src 'none'; script-src *")])
        self.assertEqual(v.check_insecure_csp(s)['status'], 'not_found')

    def test_duplicate_raw_headers_and_legacy_headers_are_observations(self):
        s = snapshot([('Content-Security-Policy', "default-src 'self'"),
                      ('content-security-policy', "script-src 'none'"),
                      ('X-Frame-Options', 'DENY'), ('X-XSS-Protection', '0')])
        r = v.check_duplicate_security_headers(s)
        self.assertEqual(r['status'], 'found')
        self.assertEqual(r['evidence'][0]['count'], 2)
        self.assertEqual(v.check_x_frame_options(s)['status'], 'found')
        self.assertEqual(v.check_x_xss_protection(s)['status'], 'found')
        self.assertEqual(v.check_x_frame_options(snapshot())['status'], 'not_found')

    def test_compression_does_not_confirm_breach(self):
        r = v.check_breach(snapshot([('content-encoding', 'gzip')]))
        self.assertEqual(r['status'], 'potential')
        self.assertFalse(r['verified'])
        self.assertEqual(v.check_breach(snapshot([('content-encoding', 'identity')]))['status'], 'not_found')

    def test_tls_positive_negative_incomplete_and_not_applicable(self):
        for name, bits in [('TLS_RSA_WITH_3DES_EDE_CBC_SHA', '112'), ('ADH-AES256-SHA', '256'), ('RC4-SHA', '128')]:
            s = snapshot(ciphers=[dict(cipher=name, bits=bits)])
            self.assertEqual(v.check_weak_tls_ciphers(s)['status'], 'found')
        self.assertEqual(v.check_weak_tls_ciphers(snapshot(ciphers=[]))['status'], 'unknown')
        s = snapshot(ciphers=[dict(cipher='TLS_AES_256_GCM_SHA384', bits='256')], cipher_scan_complete=True)
        self.assertEqual(v.check_weak_tls_ciphers(s)['status'], 'not_found')
        for state, expected in [('rejected', 'found'), ('enabled', 'not_found'), ('unknown', 'unknown')]:
            self.assertEqual(v.check_tls13_disabled(snapshot(tls13=state))['status'], expected)
        for check in (v.check_weak_tls_ciphers, v.check_tls13_disabled, v.check_wildcard_certificate):
            self.assertEqual(check(snapshot(tls_not_applicable=True))['status'], 'not_applicable')

    def test_wildcard_requires_certificate_evidence(self):
        self.assertEqual(v.check_wildcard_certificate(snapshot())['status'], 'unknown')
        s = snapshot(certificate_names=['example.test', '*.example.test'])
        self.assertEqual(v.check_wildcard_certificate(s)['evidence'], ['*.example.test'])
        self.assertEqual(v.check_wildcard_certificate(snapshot(certificate_names=['example.test']))['status'], 'not_found')

    def test_legacy_protocols_require_positive_or_complete_reachable_evidence(self):
        cases = ((v.check_sslv2_enabled, 'ssl', '2'), (v.check_sslv3_enabled, 'ssl', '3'),
                 (v.check_tls10_enabled, 'tls', '1.0'), (v.check_tls11_enabled, 'tls', '1.1'))
        for check, kind, version in cases:
            with self.subTest(protocol=version, kind=kind):
                self.assertEqual(check(snapshot())['status'], 'unknown')
                self.assertEqual(check(snapshot(tls_not_applicable=True))['status'], 'not_applicable')
                protocol = dict(type=kind, version=version, enabled='1')
                self.assertEqual(check(snapshot(protocols=[protocol], cipher_scan_complete=False))['status'], 'found')
                protocol['enabled'] = '0'
                self.assertEqual(check(snapshot(protocols=[protocol], cipher_scan_complete=True))['status'], 'unknown')
                s = snapshot(protocols=[protocol], cipher_scan_complete=True,
                             ciphers=[dict(sslversion='TLSv1.2', cipher='AES256-GCM-SHA384', bits='256')])
                self.assertEqual(check(s)['status'], 'not_found')
                s['cipher_scan_complete'] = False
                self.assertEqual(check(s)['status'], 'unknown')

    def test_weak_certificate_hash_does_not_confuse_key_or_connection_algorithms(self):
        for algorithm in ('sha1WithRSAEncryption', 'md5WithRSAEncryption', 'ecdsa-with-SHA1'):
            self.assertEqual(v.check_weak_certificate_hash(snapshot(certificate_signature=algorithm))['status'], 'found')
        for algorithm in ('sha256WithRSAEncryption', 'ecdsa-with-SHA384', 'ED25519'):
            self.assertEqual(v.check_weak_certificate_hash(snapshot(certificate_signature=algorithm))['status'], 'not_found')
        self.assertEqual(v.check_weak_certificate_hash(snapshot(certificate_signature='rsassaPss'))['status'], 'unknown')
        self.assertEqual(v.check_weak_certificate_hash(snapshot())['status'], 'unknown')
        self.assertEqual(v.check_weak_certificate_hash(snapshot(tls_not_applicable=True))['status'], 'not_applicable')

    def test_certificate_expiry_uses_utc_and_does_not_require_trust(self):
        expired = v.check_expired_certificate(snapshot(certificate_not_after='Jan  1 00:00:00 2000 GMT'))
        self.assertEqual(expired['status'], 'found')
        self.assertFalse(expired['evidence'][0]['chain_validated'])
        self.assertTrue(expired['evidence'][0]['not_after'].endswith('+00:00'))
        self.assertEqual(v.check_expired_certificate(snapshot(certificate_not_after='Jan  1 00:00:00 2099 GMT'))['status'], 'not_found')
        self.assertEqual(v.check_expired_certificate(snapshot(certificate_not_after='invalid'))['status'], 'unknown')
        self.assertEqual(v.check_expired_certificate(snapshot(tls_not_applicable=True))['status'], 'not_applicable')



    def test_report_escaping_and_redaction_before_json_escaping(self):
        secret = 'token"with\\escapes'
        report = dict(target='https://example.test/<script>', checks=[
            v.result('test', 'found', [secret, '<script>alert(1)</script>'])])
        cleaned = v.redact_tree(report, w.Redactor([('Authorization', secret)]))
        self.assertNotIn(secret, json.dumps(cleaned))
        rendered = v.render_report(cleaned)
        self.assertEqual(rendered.count('<script>'), 1)
        self.assertNotIn('<script>alert(1)</script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_report_groups_context_without_ratings_or_remediation(self):
        checks = [v.enrich_finding(check(snapshot(error='ConnectError'))) for check in v.CHECKS]
        self.assertEqual(set(v.GUIDANCE), {c['check'] for c in checks})
        self.assertTrue(all(c['group'] == 'unknown' and 'remediation' not in c for c in checks))
        self.assertTrue(all('severity' not in c and 'severity_rationale' not in c for c in checks))
        found = v.enrich_finding(dict(v.result('Weak SSL/TLS Ciphers', 'found', verified=True), severity='high', remediation='retired advice'))
        self.assertEqual(found['group'], 'verified')
        self.assertNotIn('severity', found)
        potential = v.enrich_finding(v.result('Insecure Content Security Policy (CSP)', 'potential'))
        negative = v.enrich_finding(v.result('SSLv2 Enabled', 'not_found', verified=True))
        markup = v.render_report(dict(target='https://fixture.invalid/', checks=[negative, checks[0], potential, found]))
        self.assertEqual(markup.count('class="finding-group scanner-section"'), 1)
        self.assertIn('id="findings-summary"', markup)
        self.assertIn('Findings Summary', markup)
        self.assertNotIn('aria-label="Result groups"', markup)
        for _, label, _ in v.GROUPS:
            self.assertNotIn('<h2>' + label, markup)
        self.assertNotIn('Severity', markup)
        self.assertIn('Disclaimer', markup)
        self.assertIn('themeToggle', markup)
        self.assertNotIn('Remediation', markup)
        self.assertNotIn('remediation', found)

    def test_summary_only_lists_found_and_strictly_verified_results(self):
        checks = [v.result('included', 'found', ['observed'], verified=True),
                  v.result('potential excluded', 'potential', ['suspected']),
                  v.result('unknown excluded', 'unknown'),
                  v.result('negative excluded', 'not_found', verified=True),
                  v.result('inapplicable excluded', 'not_applicable'),
                  v.result('unverified excluded', 'found', verified=False),
                  v.result('string flag excluded', 'found', verified='true')]
        report = dict(target='https://example.test/', checks=checks)
        markup = v.render_report(report)
        self.assertIn('class="finding-count" aria-label="1 findings">1</span>', markup)
        self.assertIn('<summary>included</summary>', markup)
        self.assertEqual(markup.count('<details class="finding"'), 1)
        self.assertIn('id="expandAll"', markup)
        self.assertIn('id="collapseAll"', markup)
        self.assertNotIn('Select a finding to view its evidence.', markup)
        self.assertNotRegex(markup, r'<details\b[^>]*\sopen(?:\s|=|>)')
        self.assertNotIn('data-label="Status"', markup)
        self.assertNotIn('Verified observation', markup)
        self.assertIn('<h3>Tool / probe evidence</h3>', markup)
        for check in checks[1:]:
            self.assertNotIn(check['check'], markup)
        self.assertEqual(len(report['checks']), 7)  # Rendering preserves audit data.
        empty = v.render_report(dict(target=report['target'], checks=checks[1:]))
        self.assertIn('No findings met the found-and-verified criteria', empty)
        self.assertNotIn('id="expandAll"', empty)
        self.assertNotIn('Complete check record (JSON)', empty)

    def test_theme_script_is_the_only_hash_authorized_script(self):
        import base64
        import re
        from report_ui import page
        markup = page('test', '<p>content</p>', '<script>evil</script>')
        scripts = re.findall(r'<script>(.*?)</script>', markup, flags=re.S)
        self.assertEqual(len(scripts), 1)
        digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
        self.assertIn('sha256-' + digest, markup)
        self.assertNotIn("script-src 'unsafe-inline'", markup)
        self.assertIn('&lt;script&gt;evil&lt;/script&gt;', markup)

    def test_icon_toggle_warning_and_target_details_are_escaped_and_ordered(self):
        from report_ui import page, DISCLAIMER
        markup = page('test', '<nav>Results</nav>', 'https://[::1]:8443/path',
                      {'HTTP response': 200, 'Scope': '<img src=x onerror=alert(1)>'})
        self.assertLess(len(DISCLAIMER.split()), 30)
        self.assertIn('notice disclaimer', markup)
        self.assertIn('var(--warning-bg)', markup)
        self.assertIn('class="icon-sun"', markup)
        self.assertIn('class="icon-moon"', markup)
        self.assertNotIn('button.textContent', markup)
        self.assertIn('aria-label="Switch to dark mode"', markup)
        self.assertLess(markup.index('Disclaimer</strong>'), markup.index('id="targetHeading"'))
        self.assertLess(markup.index('id="targetHeading"'), markup.index('<nav>Results'))
        self.assertIn('<dt>Host</dt><dd>::1</dd>', markup)
        self.assertIn('<dt>Port</dt><dd>8443</dd>', markup)
        self.assertIn('<dt>HTTP response</dt><dd>200</dd>', markup)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', markup)
        self.assertNotIn('<img src=x', markup)

    def test_target_timestamp_is_readable_precise_and_wraps_only_between_parts(self):
        from report_ui import target_section, timestamp_markup, STYLE
        original = '2026-10-28T00:50:42.840456+00:00'
        markup = target_section('https://example.test/', {'Checked': original})
        self.assertIn('<div class="target-field wide"><dt>Checked</dt>', markup)
        self.assertIn('datetime="' + original + '"', markup)
        self.assertIn('<span>28 Oct 2026</span><span>00:50:42 UTC</span>', markup)
        self.assertIn('white-space:nowrap', STYLE)
        self.assertIn('flex-wrap:wrap', STYLE)
        self.assertIn('00:50:42 UTC', timestamp_markup('2026-10-28T08:50:42+08:00'))
        self.assertIn('Time zone not recorded', timestamp_markup('2026-10-28T08:50:42'))
        self.assertEqual(timestamp_markup('<invalid>'), '&lt;invalid&gt;')

    def test_target_server_replaces_assessment_and_is_escaped(self):
        report = dict(target='https://example.test/', checks=[], status='completed', server='<script>server</script>')
        markup = v.render_report(report)
        self.assertIn('<dt>Server</dt><dd>&lt;script&gt;server&lt;/script&gt;</dd>', markup)
        self.assertNotIn('<dt>Assessment</dt>', markup)
        self.assertIn('Not recorded', v.render_report(dict(target=report['target'], checks=[])))

    def test_report_title_and_footer_use_recorded_assessment_date(self):
        report = dict(target='https://example.test/', checks=[], checked_at='2026-10-28T00:50:42+00:00')
        markup = v.render_report(report)
        self.assertIn('<title>WebRaptor Web Application Security Assessment Report</title>', markup)
        self.assertIn('<h1>WebRaptor Web Application Security Assessment Report</h1>', markup)
        self.assertIn('Generated by WebRaptor · For authorized security assessments only · Assessment date: 28 Oct 2026 (UTC)', markup)

    def test_sources_record_actual_collectors_and_supplementary_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            s = snapshot([('x-frame-options', 'DENY'), ('set-cookie', 'not-for-report')])
            v.capture_sources(s, folder, lambda x: x)
            artifact = folder / 'curl_results.txt'
            artifact.write_text('HEAD response')
            c = v.attach_sources(v.enrich_finding(v.check_x_frame_options(s)), s, folder,
                [dict(module='curl', status='completed', artifacts=[artifact.name])])
            sources = c['evidence_sources']
            self.assertEqual(sources[0]['tool'], 'WebRaptor HTTP collector (httpx)')
            self.assertEqual(sources[1]['role'], 'supplementary scanner output')
            self.assertNotIn('not-for-report', (folder/'verification_http.json').read_text())
            for source in sources:
                self.assertEqual(source['sha256'], hashlib.sha256((folder/source['artifact']).read_bytes()).hexdigest())
            self.assertNotIn('../', v.render_sources([dict(tool='test', artifact='../escape.txt')]))



class CollectionTests(unittest.TestCase):
    def test_http_duplicate_headers_script_scope_and_no_redirect_credentials(self):
        calls = []
        data = b'/* library */'
        def handler(request):
            calls.append((str(request.url), request.headers.get('authorization')))
            if request.url.path == '/':
                return httpx.Response(200, headers=[('content-type', 'text/html'), ('x-frame-options', 'DENY'),
                    ('X-Frame-Options', 'SAMEORIGIN')], content=b'''<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head>
                    <script src="/library.js"></script><script src="https://other.test/evil.js"></script>
                    <script src="/redirect.js"></script>''')
            if request.url.path == '/redirect.js':
                return httpx.Response(302, headers={'location': 'https://other.test/evil.js'})
            return httpx.Response(200, content=data)
        real_client = httpx.Client
        with patch.object(v.httpx, 'Client', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)):
            s = v.collect_http('https://example.test/', args(headers=[('Authorization', 'secret')]), threading.Event())
        self.assertEqual(len(calls), 1)
        self.assertEqual(s['server'], 'Not disclosed')
        self.assertTrue(all(url.startswith('https://example.test/') for url, _ in calls))
        self.assertEqual(v.check_duplicate_security_headers(s)['status'], 'found')
        self.assertEqual(v.check_csp_missing(s)['status'], 'not_found')

    def test_failed_http_produces_unknown_and_body_limit_is_enforced(self):
        real_client = httpx.Client
        def fail(request):
            raise httpx.ConnectError('test', request=request)
        with patch.object(v.httpx, 'Client', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(fail), **kw)):
            s = v.collect_http('https://example.test/', args(), threading.Event())
        self.assertEqual(v.check_coop(s)['status'], 'unknown')
        with real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'a' * 100))) as client:
            with patch.object(v, 'MAX_BODY', 10):
                _, body, cut = v.fetch(client, 'https://example.test/', threading.Event(), 2)
        self.assertEqual(len(body), 10)
        self.assertTrue(cut)

    def test_tls_failure_is_unknown_and_xml_must_match_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            def runner(cmd, *unused):
                path = Path(next(t[6:] for t in cmd if t.startswith('--xml=')))
                path.write_text('<document><ssltest host="other.test" port="443"><cipher status="accepted" cipher="RC4" bits="128"/></ssltest></document>')
                return dict(status='completed')
            with patch.object(v.socket, 'create_connection', side_effect=OSError()), patch.object(v.shutil, 'which', return_value='sslscan'):
                s = snapshot()
                v.collect_tls(s, args(), folder, threading.Event(), runner, lambda x: x)
            self.assertEqual(v.check_tls13_disabled(s)['status'], 'unknown')
            self.assertEqual(v.check_wildcard_certificate(s)['status'], 'unknown')
            self.assertEqual(v.check_weak_tls_ciphers(s)['status'], 'unknown')

    def test_sslscan_partial_positive_and_rejected_ciphers(self):
        with tempfile.TemporaryDirectory() as temp:
            def runner(cmd, *unused):
                path = Path(next(t[6:] for t in cmd if t.startswith('--xml=')))
                path.write_text('<document><ssltest host="example.test" port="443">'
                    '<protocol type="ssl" version="3" enabled="1"/>'
                    '<cipher status="rejected" cipher="RC4" bits="128"/>'
                    '<cipher status="accepted" cipher="DES-CBC3-SHA" bits="112"/>'
                    '<certificates><certificate type="short"><signature-algorithm>sha1WithRSAEncryption</signature-algorithm>'
                    '<not-valid-after>Jan  1 00:00:00 2000 GMT</not-valid-after></certificate></certificates></ssltest></document>')
                return dict(status='timed_out')
            with patch.object(v.socket, 'create_connection', side_effect=OSError()), patch.object(v.shutil, 'which', return_value='sslscan'):
                s = snapshot()
                v.collect_tls(s, args(), Path(temp), threading.Event(), runner, lambda x: x)
            self.assertEqual(len(s['ciphers']), 1)
            self.assertEqual(v.check_weak_tls_ciphers(s)['status'], 'found')
            self.assertFalse(s['cipher_scan_complete'])
            self.assertEqual(v.check_sslv3_enabled(s)['status'], 'found')
            self.assertEqual(v.check_weak_certificate_hash(s)['status'], 'found')
            self.assertEqual(v.check_expired_certificate(s)['status'], 'found')

    def test_tls13_explicit_rejection_is_distinguished_from_handshake_failure(self):
        for reason, expected in [('TLSV1_ALERT_PROTOCOL_VERSION', 'found'), ('SSLV3_ALERT_HANDSHAKE_FAILURE', 'unknown')]:
            context = Mock()
            error = ssl.SSLError('test')
            error.reason = reason
            context.wrap_socket.side_effect = error
            connection = Mock()
            connection.__enter__ = Mock(return_value=connection)
            connection.__exit__ = Mock(return_value=False)
            with tempfile.TemporaryDirectory() as temp, patch.object(v.ssl, 'create_default_context', side_effect=OSError()), patch.object(v.ssl, 'SSLContext', return_value=context), patch.object(v.socket, 'create_connection', return_value=connection), patch.object(v.shutil, 'which', return_value=None):
                s = snapshot()
                v.collect_tls(s, args(), Path(temp), threading.Event(), Mock(), lambda x: x)
            self.assertEqual(v.check_tls13_disabled(s)['status'], expected)

    def test_verification_cli_loopback_reports_and_exit_status(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/javascript' if self.path == '/lib.js' else 'text/html')
                self.send_header('X-Frame-Options', 'DENY')
                self.end_headers()
                self.wfile.write(b'fixture-library' if self.path == '/lib.js' else
                    b'<html><head></head><body><script src="/lib.js"></script></body></html>')
            def log_message(self, *unused):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def complete_scanner(module, target, folder, *unused):
            artifact = folder / 'curl_results.txt'
            artifact.write_text('fixture scanner output')
            return dict(module='curl', status='completed', findings=[], artifacts=[artifact.name],
                        artifact_hashes={artifact.name: w.file_digest(artifact)},
                        findings_status='not_parsed', duration_seconds=0)
        try:
            with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
                with patch.object(w, 'tool_executable', return_value='/fake/curl'), patch.object(w, 'execute_module', side_effect=complete_scanner):
                    code = w.main(['http://127.0.0.1:' + str(server.server_port), '--modules', 'curl', '--no-progress', '--output-dir', temp])
                self.assertEqual(code, 0)
                paths = list(Path(temp).rglob('verification.json'))
                self.assertEqual(len(paths), 1)
                report = json.loads(paths[0].read_text())
                self.assertTrue(report['server'].startswith('BaseHTTP/'))
                self.assertEqual(len(report['checks']), 22)
                self.assertEqual(report['checks'][0]['status'], 'not_applicable')
                self.assertEqual(report['checks'][1]['status'], 'found')
                self.assertTrue((paths[0].parent.parent / 'report.html').exists())
                summary = json.loads(paths[0].with_name('summary.json').read_text())
                self.assertEqual(len(summary['verification']['checks']), 22)
                self.assertNotIn('Vulnerable Javascript Libraries', {c['check'] for c in report['checks']})
                manifest = Path(temp) / '_runs' / paths[0].parent.parent.name / 'run.json'
                with patch.object(w, 'tool_executable', side_effect=AssertionError('Completed scanner is reusable')), patch.object(v, 'collect_http', return_value=dict(target=report['target'], headers=[], error='ConnectError')):
                    self.assertEqual(w.main(['--resume', str(manifest), '--no-progress']), 1)
                resumed = next(path for path in Path(temp).rglob('verification.json') if path != paths[0])
                data = json.loads(resumed.with_name('summary.json').read_text())
                self.assertIn('reused_from', data['modules'][0])
                self.assertEqual(data['verification']['status'], 'incomplete')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @unittest.skipUnless(shutil.which('openssl') and ssl.HAS_TLSv1_3, 'Requires OpenSSL CLI and TLS 1.3 client support')
    def test_real_tls12_server_rejects_tls13_without_verifying_self_signed_certificate(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            key, cert = folder / 'key.pem', folder / 'cert.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=localhost'], check=True, capture_output=True, timeout=15)
            server = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                s = snapshot()
                s['target'] = 'https://127.0.0.1:' + str(server.server_port)
                with patch.object(v.shutil, 'which', return_value=None):
                    v.collect_tls(s, args(), folder, threading.Event(), Mock(), lambda x: x)
                self.assertEqual(v.check_tls13_disabled(s)['status'], 'found', s)
                self.assertEqual(v.check_wildcard_certificate(s)['status'], 'unknown')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_invalid_mode_combinations(self):
        for flags in (['--verify-findings', '--check-tools'], ['--verify-findings', '--resume', 'missing'],
                      ['example.test', '--js-advisories', 'missing']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                w.parse_args(flags)
