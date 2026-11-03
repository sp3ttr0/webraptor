"""Keep the target's main report separate from its supporting evidence."""
import json
from pathlib import Path
import shutil


def organize_output(folder, summary):
    from verification import render_report
    folder = Path(folder)
    mapping = {}
    for path in list(folder.iterdir()):
        if path.name in {'verification.html', 'report.html', 'summary.json', 'verification.json', 'evidence', 'logs', 'data'}:
            continue
        if path.is_dir():
            destination = folder/'evidence'/path.name
            for child in path.rglob('*'):
                if child.is_file():
                    mapping[str(child.relative_to(folder))] = str((destination/child.relative_to(path)).relative_to(folder))
        elif path.suffix == '.log':
            destination = folder/'logs'/path.name
            mapping[path.name] = str(destination.relative_to(folder))
        else:
            destination = folder/'evidence'/('verification' if path.name.startswith('verification_') else 'scanners')/path.name
            mapping[path.name] = str(destination.relative_to(folder))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(destination))

    def rewrite(value, key=None):
        if isinstance(value, dict):
            return {(mapping.get(k,k) if key == 'artifact_hashes' else k): rewrite(v,k) for k,v in value.items()}
        if isinstance(value, list):
            return [mapping.get(v,v) if key=='artifacts' and isinstance(v,str) else rewrite(v) for v in value]
        if key=='artifact' and isinstance(value,str):
            return mapping.get(value,value)
        return value

    summary = rewrite(summary)
    verification_path = folder/'verification.json'
    verification = rewrite(json.loads(verification_path.read_text())) if verification_path.exists() else summary.get('verification')
    if verification is None:
        verification = dict(target=summary['target'], checks=[], status=summary['status'])
    verification.setdefault('target', summary['target'])
    verification.setdefault('checks', [])
    if 'scanner_results' not in verification:
        from scanner_report import collect_scanner_results
        verification['scanner_results'] = collect_scanner_results(summary.get('modules', []), folder)
    if 'verification' in summary:
        summary['verification'] = verification
    (folder/'data').mkdir(exist_ok=True)
    (folder/'data/verification.json').write_text(json.dumps(verification,indent=2),encoding='utf-8')
    (folder/'data/summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    (folder/'report.html').write_text(render_report(verification),encoding='utf-8')
    for name in ('summary.json','verification.json','verification.html'):
        (folder/name).unlink(missing_ok=True)
    return summary
