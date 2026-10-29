"""Bounded, escaped scanner output for offline reports."""
import html
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
        for relative in module.get('artifacts', []):
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
        item['output'] = output
        results.append(item)
    return results


def structured_output(key, output):
    """Extract display fields conservatively; preserve the full capture as evidence."""
    esc = lambda value: html.escape(str(value), quote=True)
    def table(labels, rows):
        return '<div class="scanner-table"><table><thead><tr>' + ''.join('<th>' + esc(label) + '</th>' for label in labels) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td data-label="' + esc(label) + '">' + esc(value) + '</td>' for label, value in zip(labels, row)) + '</tr>' for row in rows) + '</tbody></table></div>'
    if key == 'whatweb':
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
            content = '<div class="scanner-matches">' + ''.join(
                '<article><strong>' + esc(f.get('name', 'Unnamed match')) + '</strong><small>' +
                esc(f.get('template_id', '')) + '</small><p>' + esc(f.get('matched_at', '')) + '</p></article>'
                for f in item['findings']) + '</div>'
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
            content += '<details class="scanner-evidence"><summary>Evidence — raw output</summary><pre>' + esc(output) + '</pre></details>'
        meta = status.replace('_', ' ')
        if item.get('duration_seconds') is not None:
            meta += ' · ' + str(item['duration_seconds']) + ' seconds'
        if item.get('reused'):
            meta += ' · reused output'
        sections.append('<section class="scanner-section scanner-collapsible" id="scanner-' + key + '"><details class="scanner-disclosure"><summary><div class="scanner-heading"><div><h2>' + title + '</h2><p>' + description + '</p></div>' + ('<span class="chip">' + esc(meta) + '</span>' if status != 'completed' else '') + '</div></summary><div class="scanner-body">' + content + ('<details class="scanner-artifacts"><summary>Source artifacts</summary><div>' + '<br>'.join(links) + '</div></details>' if links else '') + '</div></details></section>')
    return '<div class="scanner-results"><p class="muted">Scanner output is shown as collected and is separate from the verified findings below.</p>' + ''.join(sections) + '</div>'
