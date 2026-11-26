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
    ('ffuf', 'ffuf', 'Discovered paths and HTTP response details'),
    ('katana', 'Katana', 'JavaScript endpoints and response sources'),
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
        if key == 'ffuf' and not module:
            # Saved reports retain their actual scanner identity.
            module = next((m for m in modules if m.get('module') == 'dirsearch'), None)
        if not module:
            results.append({'module': key, 'status': 'not_run', 'output': '', 'artifacts': []})
            continue
        item = {k: module[k] for k in ('module', 'status', 'error', 'duration_seconds', 'reused', 'findings', 'findings_status') if k in module}
        if key == 'katana':
            item['discovery'] = module.get('discovery', {})
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
                    data = stream.read() if key in ('ffuf', 'waybackurls', 'nuclei') else stream.read(LIMIT + 1)
                output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', (data if key in ('ffuf', 'waybackurls', 'nuclei') else data[:LIMIT]).decode('utf-8', errors='replace'))
                item['truncated'] = key not in ('ffuf', 'waybackurls', 'nuclei') and len(data) > LIMIT
            if key == 'ffuf' and relative.endswith('ffuf_stdout.log'):
                item['raw_output'] = candidate.read_text(encoding='utf-8', errors='replace')[:LIMIT]
        if key == 'whatweb' and item.get('status') == 'completed' and not whatweb_http_200(output):
            item.update(status='incomplete', error='WhatWeb requires HTTP 200; technology observations are inconclusive. Raw evidence retained.')
        item['output'] = output
        results.append(item)
    return results


def paginate_content(content, group, label):
    """Keep complete offline evidence with synchronized controls at both ends."""
    esc = lambda value: html.escape(str(value), quote=True)
    def controls(position):
        select_id = group + '-page-size-' + position
        return ('<nav class="secret-pagination" data-page-controls aria-label="' + esc(label + ' pagination (' + position + ')') + '" hidden>'
                '<label for="' + esc(select_id) + '">Items per page <select data-page-size id="' + esc(select_id) + '">'
                '<option value="10">10</option><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label>'
                '<span data-page-status role="status" aria-live="polite" aria-atomic="true"></span><div class="secret-page-buttons">' +
                ''.join('<button type="button" data-page-action="' + action + '" aria-controls="' + esc(group) + '" aria-label="' + esc(title + ' page of ' + label.lower()) + '">' + title + '</button>'
                        for action, title in (('first', 'First'), ('previous', 'Previous'), ('next', 'Next'), ('last', 'Last'))) + '</div></nav>')
    return '<div data-paginated>' + controls('top') + '<div id="' + esc(group) + '">' + content + '</div>' + controls('bottom') + '</div>'


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
    if key in ('ffuf', 'dirsearch'):
        rows = []
        if key == 'ffuf':
            try:
                records = json.loads(output)['results']
                for record in records:
                    url, code, size = record.get('url', ''), record.get('status'), record.get('length')
                    if (isinstance(url, str) and urlsplit(url).scheme in ('http', 'https')
                            and urlsplit(url).netloc and type(code) is int and 100 <= code <= 599
                            and type(size) is int and size >= 0):
                        rows.append((str(code), str(size) + ' B', url, ''))
            except (ValueError, KeyError, TypeError, AttributeError):
                return ''
        else:
            for line in output.splitlines():
                match = re.match(r'^\s*(\d{3})\s+(\S+)\s+(https?://\S+)(?:\s+(.*))?$', line)
                if match:
                    rows.append((match[1], match[2], match[3], match[4] or ''))
        content = ('<div class="discovery-list" role="list" aria-label="Discovered paths"><div class="discovery-line discovery-labels" aria-hidden="true"><span>Response code</span><span>Size</span><span>URL</span></div>' + ''.join(
            '<div class="discovery-line" data-page-item role="listitem"><span aria-label="Response code">' + '<span class="response-code response-' + code[0] + 'xx">' + esc(code) + '</span></span><span aria-label="Size">' + esc(size) + '</span><a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a></div>'
            for code, size, url, _ in sorted(rows, key=lambda row: (int(row[0]), row[2]))) + '</div>') if rows else ''
        return paginate_content(content, key + '-endpoint-list', 'ffuf results' if key == 'ffuf' else 'Saved Dirsearch results') if rows else ''
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



def render_nuclei_text_list(output, label='Nuclei scanner output', pagination_group=None):
    """Use identical native scanner lines in both the results and evidence views."""
    esc = lambda value: html.escape(str(value), quote=True)
    ranks = {level: rank for rank, level in enumerate(('critical', 'high', 'medium', 'low', 'info', 'unknown'))}
    severity_pattern = re.compile(r'\[(critical|high|medium|low|info|unknown)\]', re.I)
    token_pattern = re.compile(r"\[(?:critical|high|medium|low|info|unknown)\]|https?://[^\s<>\"']+", re.I)
    def rank(line):
        match = severity_pattern.search(line)
        return ranks.get(match.group(1).lower(), 6) if match else 6
    entries = []
    for line in sorted((line for line in output.splitlines() if line.strip()), key=rank):
        pieces, cursor = [], 0
        for match in token_pattern.finditer(line):
            pieces.append(esc(line[cursor:match.start()]))
            token = match.group()
            severity = severity_pattern.fullmatch(token)
            if severity:
                pieces.append('<span class="nuclei-severity nuclei-output-severity severity-' + severity.group(1).lower() + '">' + esc(token) + '</span>')
            else:
                try:
                    valid_url = bool(urlsplit(token).netloc)
                except ValueError:
                    valid_url = False
                pieces.append('<a href="' + esc(token) + '" target="_blank" rel="noopener noreferrer">' + esc(token) + '</a>' if valid_url else esc(token))
            cursor = match.end()
        pieces.append(esc(line[cursor:]))
        entries.append('<li' + (' data-page-item' if pagination_group else '') + '><code>' + ''.join(pieces) + '</code></li>')
    content = '<ul class="nuclei-console-list" aria-label="' + esc(label) + '">' + ''.join(entries) + '</ul>'
    return paginate_content(content, pagination_group, label) if pagination_group and entries else content


def render_discovery(data):
    """Show discovery and candidate exposures separately from verified findings."""
    esc = lambda value: html.escape(str(value), quote=True)
    def link(url):
        try:
            p = urlsplit(str(url))
            if p.scheme in ('http', 'https') and p.netloc:
                return '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>'
        except ValueError:
            pass
        return esc(url)
    endpoints = data.get('endpoints', [])
    body = '<p class="muted">Exact target origin only; redirects and credential validation disabled. Results are bounded by crawl depth, duration, and page limits.</p>'
    body += '<h3>Discovered Endpoints (' + str(len(endpoints)) + ')</h3>'
    if endpoints:
        table = '<div class="scanner-table"><table><thead><tr><th>Method</th><th>HTTP response</th><th>URL</th><th>Source</th></tr></thead><tbody>'
        for entry in endpoints:
            code = str(entry.get('http_status') or 'Not recorded')
            badge = '<span class="response-code response-' + code[0] + 'xx">' + esc(code) + '</span>' if re.fullmatch('[1-5][0-9]{2}', code) else esc(code)
            table += '<tr data-page-item><td data-label="Method">' + esc(entry.get('method', 'GET')) + '</td><td data-label="HTTP response">' + badge + '</td><td data-label="URL">' + link(entry.get('url', '')) + '</td><td data-label="Source">' + link(entry.get('source', '')) + '</td></tr>'
        table += '</tbody></table></div>'
        body += paginate_content(table, 'katana-endpoint-list', 'Katana endpoints')
    else:
        body += '<p class="muted">No in-scope endpoints were captured.</p>'
    return body


def render_secret_exposures(results):
    """Keep unverified secret candidates after the verified Findings Summary."""
    item = next((r for r in results if r.get('module') == 'katana'), None)
    if not item or item.get('status') == 'not_run':
        return ''
    secrets = item.get('discovery', {}).get('secrets', [])
    esc = lambda value: html.escape(str(value), quote=True)
    def link(url):
        try:
            p = urlsplit(str(url))
            if p.scheme in ('http', 'https') and p.netloc:
                return '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>'
        except ValueError:
            pass
        return esc(url)
    body = '<section class="scanner-section" id="potential-secret-exposures"><h2>Potential Secret Exposures <span class="finding-count" aria-label="' + str(len(secrets)) + ' candidates">' + str(len(secrets)) + '</span></h2>'
    body += '<p class="muted">Searches fetched content for:</p><ul><li>API keys and cloud access key IDs</li><li>Authentication tokens, access tokens, and JWTs</li><li>Passwords and database credentials</li><li>Application and client secrets</li><li>Private keys</li></ul><p class="muted">Results may be false positives, including public identifiers, examples, or inactive credentials. Always double-check the source and validate each result before reporting it as an exposure. Credential validity and permissions have not been tested.</p>'
    entries = ''
    for entry in secrets:
        entries += '<details class="scanner-evidence secret-item" data-page-item><summary>' + esc(entry.get('detector', 'Secret candidate')) + ' · ' + esc(entry.get('confidence', 'candidate')) + '</summary><p>Source: ' + link(entry.get('source_url', '')) + ' · Line: ' + esc(entry.get('line', '')) + ' · HTTP response: ' + esc(entry.get('http_status', '')) + '</p><p>Value: <code>' + esc(entry.get('value', '')) + '</code></p><pre>' + esc(entry.get('context', '')) + '</pre></details>'
    if secrets:
        body += paginate_content(entries, 'secret-exposure-list', 'Secret exposures')
    if not secrets:
        body += '<p class="muted">No candidates matched the current detectors. This does not establish that no secrets are exposed.</p>'
    return body + '</section>'


def render_scanner_results(results):
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for key, title, description in TOOLS:
        item = next((r for r in results if r.get('module') == key), {})
        if key == 'ffuf' and not item:
            item = next((r for r in results if r.get('module') == 'dirsearch'), {})
            if item:
                key, title = 'dirsearch', 'Dirsearch (saved scan)'
        status = item.get('status', 'not_run')
        output = item.get('output', '')
        links = []
        for artifact in item.get('artifacts', []):
            path = Path(artifact)
            if not path.is_absolute() and '..' not in path.parts:
                links.append('<a href="' + esc(quote(artifact, safe='/')) + '">' + esc(artifact) + '</a>')
        content = ''
        if key == 'katana':
            content = render_discovery(item.get('discovery', {}))
        elif key == 'nuclei' and output.strip() and not output.lstrip().startswith('{'):
            content = render_nuclei_text_list(output, 'Nuclei matches', 'nuclei-result-list')
        elif key == 'nuclei' and item.get('findings'):
            entries = []
            severity_order = {name: rank for rank, name in enumerate(('critical', 'high', 'medium', 'low', 'info'))}
            for finding in sorted(item['findings'], key=lambda match: severity_order.get(str(match.get('severity', 'unknown')).lower(), 5)):
                url = str(finding.get('matched_at', ''))
                parsed = urlsplit(url)
                target = ('<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>'
                          if parsed.scheme.lower() in ('http', 'https') and parsed.netloc else '<span>' + esc(url) + '</span>')
                severity = str(finding.get('severity', 'unknown')).lower()
                severity_class = severity if severity in ('critical', 'high', 'medium', 'low', 'info', 'unknown') else 'unknown'
                entries.append('<li data-page-item><div class="nuclei-match-title"><span class="nuclei-severity severity-' + severity_class + '">' + esc(severity) + '</span><strong>' + esc(finding.get('name', 'Unnamed match')) +
                               '</strong><code>' + esc(finding.get('template_id', '')) + '</code></div>' + target + '</li>')
            content = paginate_content('<ul class="nuclei-results" aria-label="Nuclei matches">' + ''.join(entries) + '</ul>', 'nuclei-result-list', 'Nuclei matches')
        elif key == 'waybackurls' and output.strip():
            urls = list(dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()))
            content = '<p class="muted">' + str(len(urls)) + ' archived URL entries shown; historical URLs may no longer exist.</p>' + paginate_content('<ol class="scanner-urls">' + ''.join('<li data-page-item value="' + str(index) + '">' + ('<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>' if urlsplit(url).scheme.lower() in ('http', 'https') and urlsplit(url).netloc else '<span>' + esc(url) + '</span>') + '</li>' for index, url in enumerate(urls, 1)) + '</ol>', 'waybackurls-result-list', 'Waybackurls results')
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
            content += ('<details class="scanner-evidence"><summary>Evidence — Nuclei output</summary>' + (render_nuclei_text_list(output) if not output.lstrip().startswith('{') else render_nuclei_evidence(output, item['findings'] if item.get('findings') and all('evidence' in f for f in item['findings']) else None)) + '</details>' if key == 'nuclei' else '<details class="scanner-evidence"><summary>Evidence — raw output</summary><pre>' + esc(item.get('raw_output', 'See Source artifacts for raw ffuf output.' if key == 'ffuf' else output)) + '</pre></details>')
        meta = status.replace('_', ' ')
        if item.get('duration_seconds') is not None:
            meta += ' · ' + str(item['duration_seconds']) + ' seconds'
        if item.get('reused'):
            meta += ' · reused output'
        sections.append('<section class="scanner-section scanner-collapsible" id="scanner-' + key + '"><details class="scanner-disclosure"><summary><div class="scanner-heading"><div><h2>' + title + '</h2><p>' + description + '</p></div>' + ('<span class="chip">' + esc(meta) + '</span>' if status != 'completed' else '') + '</div></summary><div class="scanner-body">' + content + ('<details class="scanner-artifacts"><summary>Source artifacts</summary><div>' + '<br>'.join(links) + '</div></details>' if links else '') + '</div></details></section>')
    return '<div class="scanner-results">' + ''.join(sections) + '</div>'
