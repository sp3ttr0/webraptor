import tempfile
import unittest
from pathlib import Path
from scanner_report import collect_scanner_results, render_scanner_results
from verification import render_report


class ScannerReportTests(unittest.TestCase):
    def test_output_is_bounded_and_escaped_and_paths_are_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'output.txt').write_text('<script>alert(1)</script>' + 'x' * 70000)
            result = collect_scanner_results([dict(module='whatweb', status='completed',
                artifacts=['../outside', 'output.txt'])], folder)
            self.assertTrue(result[0]['truncated'])
            self.assertEqual(result[0]['artifacts'], ['output.txt'])
            markup = render_scanner_results(result)
            self.assertNotIn('<script>', markup)
            self.assertIn('&lt;script&gt;', markup)
            self.assertIn('64 KiB', markup)

    def test_sections_precede_findings_and_missing_is_explicit(self):
        markup = render_report(dict(target='https://example.invalid', checks=[]))
        for name in ('whatweb', 'nikto', 'waybackurls', 'dirsearch', 'nuclei'):
            self.assertLess(markup.index('id="scanner-' + name + '"'), markup.index('id="findings-summary"'))
        self.assertEqual(markup.count('This scanner was not run'), 5)

    def test_archives_and_matches_are_not_verified_findings(self):
        markup = render_scanner_results([
            dict(module='waybackurls', status='completed', output='https://example.invalid/a\nhttps://example.invalid/a'),
            dict(module='nuclei', status='failed', findings=[dict(name='<img>', template_id='test', matched_at='javascript:alert(1)')])])
        self.assertIn('1 archived URL entries', markup)
        self.assertIn('&lt;img&gt;', markup)
        self.assertNotIn('href="javascript:', markup)
        self.assertIn('requiring independent validation', markup)

    def test_structured_rows_and_raw_evidence(self):
        from scanner_report import structured_output
        self.assertIn('Technology', structured_output('whatweb', 'Title : Demo\n[ Apache ]\n Version : 2.4\nHTTP Headers:\n'))
        self.assertIn('Scanner observation', structured_output('nikto', '+ [12345] /: missing header'))
        self.assertIn('Response code', structured_output('dirsearch', '200 54B http://localhost/backup.txt (4ms)'))
        markup = render_scanner_results([dict(module='nikto', status='completed', output='+ [12345] /: <script>')])
        self.assertIn('Evidence — raw output', markup)
        self.assertNotIn('completed', markup)
        self.assertNotIn('<script>', markup)

    def test_all_status_codes_and_new_tab_links(self):
        from scanner_report import structured_output
        output = '\n'.join(f'{code} 12B http://localhost/path{code}' for code in (200,301,403,404,500))
        markup = structured_output('dirsearch', output)
        for code in (200,301,403,404,500):
            self.assertIn(f'path{code}', markup)
        self.assertEqual(markup.count('target="_blank"'), 5)
        self.assertEqual(markup.count('rel="noopener noreferrer"'), 5)
        self.assertIn('scanner-disclosure', render_scanner_results([]))

    def test_response_codes_sorted_and_colored(self):
        from scanner_report import structured_output
        markup = structured_output('dirsearch', '\n'.join(f'{code} 12B http://localhost/status{code}' for code in (500,301,404,200,403)))
        positions = [markup.index(f'/status{code}') for code in (200,301,403,404,500)]
        self.assertEqual(positions, sorted(positions))
        for family in (2,3,4,5):
            self.assertIn(f'response-{family}xx', markup)

    def test_archive_links_open_new_tabs_and_reject_unsafe_schemes(self):
        markup = render_scanner_results([dict(module='waybackurls', status='completed', output='https://example.invalid/a?x=1&y=2\nhttp://example.invalid/b\njavascript:alert(1)')])
        self.assertEqual(markup.count('target="_blank"'), 2)
        self.assertEqual(markup.count('rel="noopener noreferrer"'), 2)
        self.assertNotIn('href="javascript:', markup)
        self.assertIn('x=1&amp;y=2', markup)
