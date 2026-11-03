import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from output_layout import organize_output

class OutputLayoutTests(unittest.TestCase):
    def test_main_report_paths_hashes_and_idempotence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'curl_results.txt').write_text('Server: demo')
            (root/'scan.log').write_text('done')
            digest=hashlib.sha256((root/'curl_results.txt').read_bytes()).hexdigest()
            report=dict(target='http://example.invalid',checks=[],scanner_results=[dict(module='whatweb',status='completed',output='Title : Demo',artifacts=['curl_results.txt'])])
            summary=dict(target=report['target'],status='completed',verification=report,modules=[dict(module='curl',artifacts=['curl_results.txt'],artifact_hashes={'curl_results.txt':digest})])
            (root/'verification.json').write_text(json.dumps(report))
            (root/'report.html').write_text('old report')
            updated=organize_output(root,summary)
            self.assertEqual({p.name for p in root.iterdir()}, {'report.html','data','logs','evidence'})
            artifact=updated['modules'][0]['artifacts'][0]
            self.assertEqual(artifact,'evidence/scanners/curl_results.txt')
            self.assertEqual(updated['modules'][0]['artifact_hashes'][artifact],digest)
            self.assertIn('href="evidence/scanners/curl_results.txt"',(root/'report.html').read_text())
            self.assertEqual(organize_output(root,updated),updated)

    def test_legacy_summary_remains_resumable(self):
        from types import SimpleNamespace
        from webraptor import reusable_results, target_key
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);target='https://example.invalid/';run='legacy'
            folder=base/target_key(target)/run;folder.mkdir(parents=True)
            (folder/'curl_results.txt').write_text('legacy evidence')
            digest=hashlib.sha256((folder/'curl_results.txt').read_bytes()).hexdigest()
            (folder/'summary.json').write_text(json.dumps(dict(target=target,modules=[dict(module='curl',status='completed',artifacts=['curl_results.txt'],artifact_hashes={'curl_results.txt':digest})])))
            args=SimpleNamespace(resume_data=dict(base=base,run_id=run),modules=['curl'])
            self.assertIn('curl',reusable_results(target,args))
