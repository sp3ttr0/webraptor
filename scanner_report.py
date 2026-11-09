"""Bounded, escaped scanner output for offline reports."""
import html
import json
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

TOOLS = (
    ('whatweb', 'WhatWeb', 'Web technologies and server fingerprints'),
    ('nikto', 'Nikto', 'Web server observations and scanner output'),
    ('waybackurls', 'Waybackurls', 'Historical URLs collected from public archives'),
    ('dirsearch', 'Dirsearch', 'Discovered paths and HTTP response details'),
    ('nuclei', 'Nuclei', 'Template matches requiring independent validation'),
)
LIMIT = 65536


def whatweb_http_200(output):
    """Require an explicit success status from WhatWeb's verbose report."""
    clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    statuses = re.findall(r'^\s*Status\s*:\s*(\d{3})\b', clean, re.M)
    return bool(statuses) and all(code == '200' for code in statuses)


def collect_scanner_results(modules, folder):
    results = []
    for key, _, _ in TOOLS:
        module = next((m for m in modules if m.get('module') == key), None)
        if not module:
            results.append({'module': key, 'status': 'not_run', 'output': '', 'artifacts': []})
            continue
        item = {k: module[k] for k in ('module', 'status', 'error', 'duration_seconds', 'reused', 'findings', 'findings_status') if k in module}
        item['artifacts'] = []
        output = ''
        artifacts = module.get('artifacts', [])
        if key == 'nuclei':
            artifacts = sorted(artifacts, key=lambda name: not str(name).endswith('nuclei_results.txt'))
        for relative in artifacts:
            path = Path(relative)
            if path.is_absolute() or '..' in path.parts:
                continue
            candidate = folder / path
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(folder.resolve()) or not candidate.is_file():
                continue
            item['artifacts'].append(relative)
            if not output and not relative.endswith(('_stderr.txt', '_stderr.log')):
                with candidate.open('rb') as stream:
                    data = stream.read() if key == 'dirsearch' else stream.read(LIMIT + 1)
                output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', (data if key == 'dirsearch' else data[:LIMIT]).decode('utf-8', errors='replace'))
                item['truncated'] = key != 'dirsearch' and len(data) > LIMIT
        if key == 'whatweb' and item.get('status') == 'completed' and not whatweb_http_200(output):
            item.update(status='incomplete', error='WhatWeb requires HTTP 200; technology observations are inconclusive. Raw evidence retained.')
        item['output'] = output
        results.append(item)
    return results


def structured_output(key, output):
    """Extract display fields conservatively; preserve the full capture as evidence."""
    esc = lambda value: html.escape(str(value), quote=True)
    def table(labels, rows):
        return '<div class="scanner-table"><table><thead><tr>' + ''.join('<th>' + esc(label) + '</th>' for label in labels) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td data-label="' + esc(label) + '">' + esc(value) + '</td>' for label, value in zip(labels, row)) + '</tr>' for row in rows) + '</tbody></table></div>'
    if key == 'whatweb':
        if not whatweb_http_200(output):
            return '<p class="muted">HTTP 200 is required for WhatWeb results. See raw evidence below.</p>'
        fields = re.findall(r'^(Status|Title|IP|Country|Summary)\s*:\s*(.+)$', output, re.M)
        plugins = []
        for match in re.finditer(r'^\[ ([^\n]+?) \]\s*\n(.*?)(?=^\[ |^HTTP Headers:|\Z)', output, re.M | re.S):
            details = re.findall(r'^\s*(Version|String)\s*:\s*(.+)$', match[2], re.M)
            plugins.append((match[1], '; '.join(k + ': ' + v for k, v in details) or 'Detected by WhatWeb'))
        return (table(('Property', 'Value'), fields) if fields else '') + (table(('Technology', 'Detected details'), plugins) if plugins else '')
    if key == 'nikto':
        rows = []
        for line in output.splitlines():
            match = re.match(r'^\+ \[(\d+)\] (.+)', line)
            if match:
                rows.append((match[1], match[2]))
        return table(('Check ID', 'Scanner observation'), rows) if rows else ''
    if key == 'dirsearch':
        rows = []
        for line in output.splitlines():
            match = re.match(r'^\s*(\d{3})\s+(\S+)\s+(https?://\S+)(?:\s+(.*))?$', line)
            if match:
                rows.append((match[1], match[2], match[3], match[4] or ''))
        return ('<div class="dirsearch-list" role="list" aria-label="Dirsearch results"><div class="dirsearch-line dirsearch-labels" aria-hidden="true"><span>Response code</span><span>Size</span><span>URL</span></div>' + ''.join(
            '<div class="dirsearch-line" role="listitem"><span aria-label="Response code">' + '<span class="response-code response-' + code[0] + 'xx">' + esc(code) + '</span></span><span aria-label="Size">' + esc(size) + '</span><a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a></div>'
            for code, size, url, _ in sorted(rows, key=lambda row: (int(row[0]), row[2]))) + '</div>') if rows else ''
    return ''


def render_nuclei_evidence(output, captured_findings=None):
    """Display JSONL as ordinary evidence lines; keep the original file downloadable."""
    esc = lambda value: html.escape(str(value), quote=True)
    def values(value):
        if isinstance(value, dict):
            for nested in value.values():
                yield from values(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from values(nested)
        elif value is not None:
            yield str(value)
    def text_or_link(value):
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() in ('http', 'https') and parsed.netloc and not any(c.isspace() for c in value):
                return '<a href="' + esc(value) + '" target="_blank" rel="noopener noreferrer">' + esc(value) + '</a>'
        except ValueError:
            pass
        return esc(value)
    entries = []
    ranks = {severity: i for i, severity in enumerate(('critical', 'high', 'medium', 'low', 'info'))}
    records = [dict(f.get('evidence', {}), template_id=f.get('template_id'), name=f.get('name'), severity=f.get('severity'), matched_at=f.get('matched_at')) for f in captured_findings] if captured_findings is not None else output.splitlines()
    for line in records:
        if isinstance(line, str) and not line.strip():
            continue
        try:
            record = line if isinstance(line, dict) else json.loads(line)
            if not isinstance(record, dict):
                raise ValueError('Not a match record')
        except (ValueError, TypeError):
            entries.append((6, '<li class="nuclei-evidence-item"><p class="muted">Incomplete evidence entry. See the original file under Source artifacts.</p></li>'))
            continue
        info = record.get('info') if isinstance(record.get('info'), dict) else record
        severity = str(info.get('severity', 'unknown')).lower()
        tone = severity if severity in ranks else 'unknown'
        name = info.get('name') or record.get('template-id') or record.get('template_id') or 'Scanner match'
        title = '<div class="nuclei-match-title"><span class="nuclei-severity severity-' + tone + '">' + esc(severity) + '</span><strong>' + esc(name) + '</strong></div>'
        fields = [('Template', record.get('template-id') or record.get('template_id')),
                  ('URL', record.get('matched-at') or record.get('matched_at') or record.get('url')),
                  ('Matcher', record.get('matcher-name')), ('Match recorded', record.get('matcher-status')),
                  ('Extracted evidence', record.get('extracted-results')), ('Matched line', record.get('matched-line')),
                  ('Captured request', record.get('request')), ('Captured response', record.get('response')),
                  ('Reproduction command', record.get('curl-command')), ('Captured at', record.get('timestamp'))]
        details = []
        for label, value in fields:
            for entry in values(value):
                if entry.strip():
                    details.append('<li><span class="evidence-label">' + label + ':</span> ' + ('<pre>' + esc(entry) + '</pre>' if label in ('Captured request', 'Captured response') else '<span class="evidence-value">' + text_or_link(entry) + '</span>') + '</li>')
        if not any(record.get(key) for key in ('request','response','extracted-results','matched-line')):
            details.append('<li class="muted">No request/response or extracted proof was saved for this match. The reproduction command alone is not captured proof.</li>')
        entries.append((ranks.get(severity, 5), '<li class="nuclei-evidence-item">' + title + '<ul class="nuclei-evidence-lines">' + ''.join(details) + '</ul></li>'))
    return '<ol class="nuclei-evidence-list" aria-label="Nuclei evidence entries">' + ''.join(markup for _, markup in sorted(entries, key=lambda entry: entry[0])) + '</ol>'



def render_scanner_results(results):
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for key, title, description in TOOLS:
        item = next((r for r in results if r.get('module') == key), {})
        status = item.get('status', 'not_run')
        output = item.get('output', '')
        links = []
        for artifact in item.get('artifacts', []):
            path = Path(artifact)
            if not path.is_absolute() and '..' not in path.parts:
                links.append('<a href="' + esc(quote(artifact, safe='/')) + '">' + esc(artifact) + '</a>')
        content = ''
        if key == 'nuclei' and item.get('findings'):
            entries = []
            severity_order = {name: rank for rank, name in enumerate(('critical', 'high', 'medium', 'low', 'info'))}
            for finding in sorted(item['findings'], key=lambda match: severity_order.get(str(match.get('severity', 'unknown')).lower(), 5)):
                url = str(finding.get('matched_at', ''))
                parsed = urlsplit(url)
                target = ('<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>'
                          if parsed.scheme.lower() in ('http', 'https') and parsed.netloc else '<span>' + esc(url) + '</span>')
                severity = str(finding.get('severity', 'unknown')).lower()
                severity_class = severity if severity in ('critical', 'high', 'medium', 'low', 'info', 'unknown') else 'unknown'
                entries.append('<li><div class="nuclei-match-title"><span class="nuclei-severity severity-' + severity_class + '">' + esc(severity) + '</span><strong>' + esc(finding.get('name', 'Unnamed match')) +
                               '</strong><code>' + esc(finding.get('template_id', '')) + '</code></div>' + target + '</li>')
            content = '<ul class="nuclei-results" aria-label="Nuclei matches">' + ''.join(entries) + '</ul>'
        elif key == 'waybackurls' and output.strip():
            urls = list(dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()))
            content = '<p class="muted">' + str(len(urls)) + ' archived URL entries shown; historical URLs may no longer exist.</p><ol class="scanner-urls">' + ''.join('<li>' + ('<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>' if urlsplit(url).scheme.lower() in ('http', 'https') and urlsplit(url).netloc else '<span>' + esc(url) + '</span>') + '</li>' for url in urls) + '</ol>'
        elif output.strip():
            content = structured_output(key, output) or '<p class="muted">No structured entries could be extracted. See Evidence for the captured output.</p>'
        else:
            message = ('This scanner was not run for this assessment.' if status == 'not_run' else
                       'No output was captured. This does not establish that the target is free of issues.' if status != 'completed' else
                       'No scanner matches were recorded.' if key == 'nuclei' and item.get('findings_status') == 'complete' else 'No output was recorded.')
            content = '<p class="scanner-empty">' + message + '</p>'
        if item.get('error'):
            content += '<p class="muted">' + esc(item['error']) + '</p>'
        if item.get('truncated'):
            content += '<p class="muted">Output preview limited to 64 KiB. See the complete source artifacts below.</p>'
        if output.strip():
            content += ('<details class="scanner-evidence"><summary>Evidence — Nuclei output</summary>' + ('<ul class="nuclei-console-list" aria-label="Nuclei scanner output">' + ''.join('<li><code>' + esc(line) + '</code></li>' for line in output.splitlines() if line.strip()) + '</ul>' if not output.lstrip().startswith('{') else render_nuclei_evidence(output, item['findings'] if item.get('findings') and all('evidence' in f for f in item['findings']) else None)) + '</details>' if key == 'nuclei' else '<details class="scanner-evidence"><summary>Evidence — raw output</summary><pre>' + esc(output) + '</pre></details>')
        meta = status.replace('_', ' ')
        if item.get('duration_seconds') is not None:
            meta += ' · ' + str(item['duration_seconds']) + ' seconds'
        if item.get('reused'):
            meta += ' · reused output'
        sections.append('<section class="scanner-section scanner-collapsible" id="scanner-' + key + '"><details class="scanner-disclosure"><summary><div class="scanner-heading"><div><h2>' + title + '</h2><p>' + description + '</p></div>' + ('<span class="chip">' + esc(meta) + '</span>' if status != 'completed' else '') + '</div></summary><div class="scanner-body">' + content + ('<details class="scanner-artifacts"><summary>Source artifacts</summary><div>' + '<br>'.join(links) + '</div></details>' if links else '') + '</div></details></section>')
    return '<div class="scanner-results"><p class="muted">Scanner output is shown as collected and is separate from the verified findings below.</p>' + ''.join(sections) + '</div>'
