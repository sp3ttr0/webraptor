"""Shared offline report shell using Pencil's plum-purple design language."""
import base64
import hashlib
import html
from datetime import datetime, timezone
from urllib.parse import urlsplit

RAPTOR_LOGO = '''<svg class="raptor-logo" viewBox="0 0 144 116" role="img" aria-label="WebRaptor copper velociraptor head logo" xmlns="http://www.w3.org/2000/svg">
<title>Copper velociraptor with a slender snout and feathered neck</title>
<path fill="#9f5135" stroke="#e7bc88" stroke-width="1.8" stroke-linejoin="round" d="M19 107 25 85 17 90 24 72 14 77 23 57 20 51 32 36Q44 22 61 24L78 29 89 37 125 43Q136 45 137 51L133 59 105 64 86 61 75 69 91 79 119 69 125 73 112 86 92 94 70 84 59 94 57 108Z"/>
<path fill="#d18c56" d="M24 55 35 37Q46 27 60 28L76 33 86 40 124 46 131 50 105 53 83 51 64 48 45 59 32 78 26 97 29 75Z"/>
<path fill="#edc991" d="m38 42 13-11 12-1 13 5-17-1-12 8-9 12-8 8Z"/>
<path fill="#522c2a" d="m43 47 12-11 20 3-13 11-13 1Z"/>
<path fill="#e8b64d" d="m51 44 9-5 7 1-8 7-7 1Z"/>
<path fill="#201c25" d="m58 40 3-1-2 8-3 1Z"/>
<path fill="none" stroke="#f0cf9d" stroke-width="2" stroke-linecap="round" d="m46 37 12-5 17 4"/>
<path fill="#281e26" d="m78 57 27-2 27-4-2 7-25 5-18-4-12 9 18 13 26-9-10 10-18 7-22-12-3-9Z"/>
<path fill="#fff0cf" d="m91 57 5 1-3 6Zm10 0 5-1-2 7Zm11-2 5-1-2 7Zm10-2 5-1-3 6Z"/>
<path fill="#e6b77e" d="m76 78 16 9 19-7-5 6-14 5-18-9Z"/>
<path fill="#713b30" d="m40 61-9 19-2 22 8-8 6-20 10-11-4-4Z"/>
<path fill="#e0ac72" d="m52 71 10 9-8 10-2 13-10 2 4-13Z"/>
<path fill="none" stroke="#713b30" stroke-width="2" stroke-linecap="round" d="m28 67 8-10m-7 24 8-14m-5 29 7-13"/>
<ellipse cx="125" cy="47" rx="2.4" ry="1.3" fill="#522c2a"/>
</svg>'''


DISCLAIMER = (
    'Automated results may be incomplete or inaccurate. Verified means observed, not exploited. '
    'Validate findings before acting. Authorized testing only.'
)
THEME_SCRIPT = """(() => {
  const root = document.documentElement;
  const button = document.getElementById('themeToggle');
  let saved = null;
  try { saved = localStorage.getItem('webraptor-theme'); } catch (_) {}
  const preferred = 'dark';
  function apply(theme) {
    root.dataset.theme = theme;
    button.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    button.setAttribute('aria-pressed', String(theme === 'dark'));
    try { localStorage.setItem('webraptor-theme', theme); } catch (_) {}
  }
  apply(saved === 'dark' || saved === 'light' ? saved : preferred);
  button.addEventListener('click', () => apply(root.dataset.theme === 'dark' ? 'light' : 'dark'));
  const findings = document.getElementById('findings-summary');
  if (findings) {
    for (const [id, open] of [['expandAll', true], ['collapseAll', false]]) {
      const control = document.getElementById(id);
      if (control) control.addEventListener('click', () => {
        findings.querySelectorAll('details.finding').forEach(item => { item.open = open; });
      });
    }
  }
})();"""
SCRIPT_HASH = base64.b64encode(hashlib.sha256(THEME_SCRIPT.encode()).digest()).decode()
STYLE = """
:root{color-scheme:light;--bg:#f2edf7;--bg-accent:#f2edf7;--panel:#fcf9ff;--text:#24192f;--muted:#6c5b7b;--line:#d6c9e3;--accent:#694a9d;--accent-2:#765391;--chip:#e9dff2;--chip-text:#563671;--code-bg:#eee6f4;--code-text:#24192f;--warning-bg:#fff6e6;--warning-line:#c08a35;--warning-text:#714400;--shadow:none}
[data-theme=dark]{color-scheme:dark;--bg:#0c0a13;--bg-accent:#090710;--panel:#14101f;--text:#e9e7ef;--muted:#aaa0ba;--line:#30283f;--accent:#b09acb;--accent-2:#9276ce;--chip:#1c142b;--chip-text:#d4c4ed;--code-bg:#090710;--code-text:#e9e7ef;--shadow:none}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,var(--bg),var(--bg-accent));color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh}
main{max-width:1320px;margin:0 auto;padding:36px 28px}header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:28px;padding-bottom:26px;border-bottom:1px solid var(--line)}.brand{display:flex;gap:16px;align-items:flex-start}.mark{display:grid;place-items:center;flex-shrink:0;width:84px;height:76px;border-radius:18px;background:transparent;color:var(--text);font-weight:800;letter-spacing:1px;font-size:20px}h1{font-size:clamp(22px,2.8vw,32px);font-weight:600;letter-spacing:-.8px;line-height:1.2;margin:0 0 8px}h2{font-size:21px;font-weight:600;letter-spacing:-.5px}p{overflow-wrap:anywhere}a{color:var(--accent)}small,.muted{color:var(--muted)}.subtitle{font:12px/1.6 ui-monospace,SFMono-Regular,monospace;margin:0;color:var(--muted);overflow-wrap:anywhere}
button{border:1px solid var(--line);border-radius:4px;background:var(--panel);color:var(--text);padding:11px 15px;font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}button:hover{border-color:var(--accent);background:linear-gradient(110deg,var(--chip),var(--panel))}button:focus-visible,a:focus-visible{outline:3px solid var(--accent-2);outline-offset:3px}
.findings-header{display:flex;align-items:center;justify-content:space-between;gap:16px}.findings-header h2{display:flex;align-items:center;gap:8px;margin:0;line-height:1.2}.finding-count{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border-radius:50%;background:var(--chip);color:var(--chip-text);border:1px solid var(--line);font-size:11px;line-height:1;font-weight:700;font-variant-numeric:tabular-nums;flex-shrink:0;align-self:center}.finding-controls{display:flex;gap:8px;flex-shrink:0;margin:0}.findings-header+.group-intro{margin-top:12px}.finding-controls button{display:grid;place-items:center;width:40px;height:40px;padding:9px}.finding-controls svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
[data-theme=dark]{--warning-bg:#2c2415;--warning-line:#b78025;--warning-text:#ffdda0}
#themeToggle{width:44px;height:44px;display:grid;place-items:center;padding:10px;flex-shrink:0}#themeToggle svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.icon-sun{display:none}[data-theme=dark] .icon-sun{display:block}[data-theme=dark] .icon-moon{display:none}
.brand{min-width:0;flex:1;display:grid;grid-template-columns:auto minmax(0,1fr);align-items:center;column-gap:16px;row-gap:8px}.brand>div:last-child{display:contents}.brand .mark{grid-column:1;grid-row:1}.brand h1{grid-column:2;grid-row:1;margin:0}.brand .subtitle{grid-column:2;grid-row:2}header{flex-wrap:nowrap!important}
.mark .raptor-logo{display:block;width:100%;height:100%;overflow:visible}
.notice.disclaimer{background:var(--warning-bg);border-color:var(--warning-line);border-left-color:var(--warning-line);color:var(--warning-text)}.notice.disclaimer p{color:var(--warning-text)}.warning-icon{margin-right:8px}
.target-card{padding:20px;background:var(--panel);border:1px solid var(--line);border-top:2px solid var(--accent-2);border-radius:6px;box-shadow:var(--shadow);margin:22px 0}.target-card h2{margin:0 0 16px}.target-card dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin:0}.target-field{min-width:0}.target-field.wide{grid-column:1/-1}.target-card dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.target-card dd{margin:4px 0 0;overflow-wrap:anywhere;font-weight:500}@media(max-width:700px){.target-card dl{grid-template-columns:repeat(2,minmax(0,1fr))}.target-card{padding:16px}}
.report-timestamp{display:flex;flex-wrap:wrap;gap:4px 14px;font-variant-numeric:tabular-nums;overflow-wrap:normal}.report-timestamp span{white-space:nowrap}
.notice{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--accent-2);border-radius:6px;padding:16px 20px;box-shadow:var(--shadow);margin:20px 0}.notice p{margin:5px 0 0;color:var(--muted)}
nav{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}nav a{display:flex;align-items:center;gap:20px;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 18px;text-decoration:none;box-shadow:var(--shadow)}nav strong{display:inline-grid;place-items:center;min-width:28px;height:28px;border-radius:4px;background:var(--chip);color:var(--chip-text)}
section.finding-group{margin:32px 0;scroll-margin-top:20px}.group-intro{color:var(--muted)}.panel,.scroll{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow-x:auto;box-shadow:var(--shadow);margin:18px 0}
table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;background:var(--chip)}tr:last-child td{border-bottom:0}td:first-child{font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,SFMono-Regular,monospace;background:var(--code-bg);color:var(--code-text);padding:14px;border-radius:4px;max-height:480px;overflow:auto}.nuclei-output-severity{text-transform:none;margin-right:2px}.nuclei-console-list{list-style:none;padding:0;margin:14px 0;background:var(--code-bg);border:1px solid var(--line);border-radius:4px}.nuclei-console-list li{padding:10px 14px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.nuclei-console-list li:last-child{border-bottom:0}.nuclei-console-list code{white-space:pre-wrap;color:var(--code-text);font:12px/1.6 ui-monospace,monospace}.nuclei-evidence-list{list-style:none;margin:14px 0;padding:0}.nuclei-evidence-list>li{margin:8px 0;border:1px solid var(--line);border-radius:4px;overflow:hidden}.nuclei-evidence-item{padding:14px}.nuclei-evidence-lines{list-style:none;margin:8px 0 0;padding:0}.nuclei-evidence-lines li{margin:5px 0;overflow-wrap:anywhere}.evidence-label{color:var(--muted);font-weight:600}.evidence-value{white-space:pre-wrap;overflow-wrap:anywhere}.nuclei-results{list-style:none;margin:0;padding:0}.nuclei-results li{padding:12px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.nuclei-results li:last-child{border-bottom:0}.nuclei-match-title{display:flex;align-items:baseline;flex-wrap:wrap;gap:8px 14px;margin-bottom:5px}.nuclei-severity{display:inline-block;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700;text-transform:uppercase;background:var(--chip);color:var(--muted)}.severity-critical{background:#7f1d1d;color:#fff}.severity-high{background:#fee2e2;color:#991b1b}.severity-medium{background:#fef3c7;color:#92400e}.severity-low{background:#dbeafe;color:#1e40af}.severity-info{background:#e0e7ff;color:#3730a3}.nuclei-match-title code{font-size:12px;color:var(--muted)}.tool-source{padding:10px 0;border-bottom:1px solid var(--line)}.tool-source:last-child{border:0}.tool-source small{display:block}.chip{display:inline-block;background:var(--chip);color:var(--chip-text);padding:3px 8px;border-radius:5px;font-size:12px;font-weight:600}footer{text-align:center;font:11px/1.6 ui-monospace,SFMono-Regular,monospace;color:var(--muted);margin-top:36px;border-top:1px solid var(--line);padding-top:18px}
@media(max-width:1050px){header{align-items:flex-start;flex-wrap:wrap}main{padding:24px 16px}h1{font-size:24px}table,tbody,tr,td{display:block}thead{display:none}.panel,.scroll{background:transparent;border:0;box-shadow:none;overflow:visible}tr{background:var(--panel);margin:16px 0;border:1px solid var(--line);border-radius:6px;overflow:hidden;box-shadow:var(--shadow)}td{border:0;padding:10px 14px}td:first-child{background:var(--chip);padding:14px}td:not(:first-child)::before{content:attr(data-label) ': ';font-weight:600;color:var(--muted)}td:nth-child(n+4)::before{display:block;margin-bottom:6px}nav a{flex:1 1 150px;justify-content:space-between}.brand{column-gap:12px;row-gap:8px}.mark{width:72px;height:65px;border-radius:15px}.notice{padding:14px}pre{max-height:360px}}
.finding{margin:12px 0;border:1px solid var(--line);border-radius:6px;background:var(--panel);box-shadow:var(--shadow);overflow:hidden}.finding>summary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 18px;font-weight:600;cursor:pointer;list-style:none}.finding>summary::-webkit-details-marker{display:none}.finding>summary::after{content:'+';color:var(--accent);font-size:22px;font-weight:400;flex-shrink:0}.finding[open]>summary::after{content:'−'}.finding[open]>summary{border-bottom:1px solid var(--line);background:var(--chip)}.finding>summary:hover{background:var(--chip)}.finding>summary:focus-visible{outline:3px solid var(--accent-2);outline-offset:-3px}.finding-content{display:grid;grid-template-columns:minmax(0,1fr);gap:20px;padding:18px}.finding-content>div{min-width:0}.evidence-viewer{border:1px solid var(--line);border-radius:4px;margin:10px 0;overflow:hidden}.evidence-viewer>summary{cursor:pointer;padding:12px 14px;background:var(--chip);font-weight:600;color:var(--text)}.evidence-body{padding:14px;min-width:0}.evidence-toolbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;font-size:12px;color:var(--muted);margin-bottom:12px}.evidence-method{font-size:12px;line-height:1.6;color:var(--muted);margin:0 0 12px}.evidence-toolbar a{color:var(--accent)}.evidence-body .tool-source{border:0}.raw-evidence{white-space:pre;overflow-wrap:normal;max-height:440px;overflow:auto;margin-bottom:0}.tool-source a{overflow-wrap:anywhere}.finding-content h3{margin:0 0 10px;font-size:13px;color:var(--muted)}@media(max-width:700px){.finding-content{grid-template-columns:minmax(0,1fr);gap:20px}.finding>summary{padding:14px 16px}}
.scanner-section{margin:22px 0;padding:22px;border:1px solid var(--line);border-top:2px solid var(--accent-2);border-radius:6px;background:var(--panel);box-shadow:var(--shadow);min-width:0}.scanner-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}.scanner-heading h2{margin:0}.scanner-heading p{margin:5px 0 14px;color:var(--muted)}.scanner-heading .chip{white-space:normal}.scanner-collapsible{padding:0}.scanner-disclosure>summary{padding:20px 22px;cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:16px}.scanner-disclosure>summary::-webkit-details-marker{display:none}.scanner-disclosure>summary::after{content:'+';font-size:24px;color:var(--accent)}.scanner-disclosure[open]>summary::after{content:'−'}.scanner-disclosure>summary .scanner-heading{flex:1}.scanner-disclosure>summary p{margin-bottom:0}.scanner-body{padding:0 22px 22px}.dirsearch-list{margin:16px 0;border:1px solid var(--line);border-radius:4px;overflow:hidden}.dirsearch-line{display:grid;grid-template-columns:100px 70px minmax(0,1fr);gap:12px;padding:9px 12px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums}.response-code{display:inline-block;min-width:38px;text-align:center;padding:1px 6px;border-radius:5px;font-weight:700}.response-2xx{background:#dcfce7;color:#166534}.response-3xx{background:#dbeafe;color:#1e40af}.response-4xx{background:#fef3c7;color:#92400e}.response-5xx{background:#fee2e2;color:#991b1b}.response-1xx{background:#ede9fe;color:#5b21b6}[data-theme=dark] .response-2xx{background:#153e2d;color:#86efac}[data-theme=dark] .response-3xx{background:#1e365e;color:#93c5fd}[data-theme=dark] .response-4xx{background:#493514;color:#fcd34d}[data-theme=dark] .response-5xx{background:#4c2028;color:#fca5a5}[data-theme=dark] .response-1xx{background:#352452;color:#c4b5fd}.dirsearch-line:last-child{border:0}.dirsearch-labels{font-size:12px;color:var(--muted);background:var(--chip);font-weight:600}.dirsearch-line a{overflow-wrap:anywhere}@media(max-width:700px){.dirsearch-line{grid-template-columns:70px 45px minmax(0,1fr);gap:8px;padding:9px 8px;font-size:12px}.scanner-disclosure>summary{padding:16px}.scanner-body{padding:0 16px 16px}.scanner-section.scanner-collapsible{padding:0}}
.scanner-table{margin:14px 0;overflow-x:auto;border:1px solid var(--line);border-radius:4px}.scanner-table table{table-layout:auto}.scanner-table th:first-child{width:15%}.scanner-evidence{margin-top:18px;border-top:1px solid var(--line);padding-top:14px}.scanner-evidence summary{cursor:pointer;color:var(--accent);font-weight:600}.scanner-empty{padding:16px;background:var(--chip);border-radius:4px;color:var(--muted)}.scanner-urls{max-height:360px;overflow:auto;padding:0;list-style:none;border:1px solid var(--line);border-radius:4px}.scanner-urls li{padding:9px 12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.scanner-matches{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:12px;margin:14px 0}.scanner-matches article{border:1px solid var(--line);border-radius:4px;padding:16px;border-left:3px solid var(--accent)}.scanner-matches small{display:block}.scanner-artifacts{margin-top:14px;border-top:1px solid var(--line);padding-top:12px}.scanner-artifacts summary{cursor:pointer;color:var(--accent)}.scanner-artifacts a{overflow-wrap:anywhere}@media(max-width:700px){.scanner-section{padding:16px}}
.batch-toc{margin:28px 0;border:1px solid var(--line);border-top:2px solid var(--accent-2);border-radius:6px;background:var(--panel);overflow:hidden}.toc-heading{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:24px}.toc-eyebrow{font:11px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.12em;color:var(--accent)}.toc-heading h2{display:flex;align-items:center;gap:10px;margin:6px 0}.toc-heading p{color:var(--muted);margin:0}.toc-total{text-align:right;flex-shrink:0}.toc-total strong{display:block;font:24px ui-monospace,monospace;color:var(--accent)}.toc-total span{font-size:12px;color:var(--muted)}.toc-list{list-style:none;padding:0;margin:0 24px}.toc-list li{border-top:1px solid var(--line)}.toc-link{display:flex;align-items:center;gap:16px;padding:18px 8px;text-decoration:none;color:var(--text)}.toc-link:hover{background:var(--chip)}.toc-number{font:12px ui-monospace,monospace;color:var(--accent);min-width:24px}.toc-target{overflow-wrap:anywhere;min-width:0;font-weight:500}.toc-leader{flex:1;min-width:20px;border-bottom:1px dotted var(--line)}.toc-status{flex-shrink:0;font-size:11px;padding:3px 9px;border:1px solid var(--line);border-radius:4px;background:var(--chip);color:var(--muted)}.toc-status-completed{background:var(--success-bg,#dcfce7);color:#166534}.toc-status-incomplete,.toc-status-cancelled{background:var(--warning-bg);color:var(--warning-text);border-color:var(--warning-line)}.toc-status-failed{background:#fee2e2;color:#991b1b}.toc-arrow{color:var(--accent)}[data-theme=dark] .toc-status-completed{background:#153e2d;color:#86efac}[data-theme=dark] .toc-status-failed{background:#4c2028;color:#fca5a5}.toc-footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:16px 24px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}@media(max-width:600px){.toc-heading{padding:18px;align-items:flex-start;flex-direction:column;gap:14px}.toc-total{text-align:left;display:flex;align-items:baseline;gap:8px}.toc-total strong{font-size:18px}.toc-list{margin:0 12px}.toc-link{display:grid;grid-template-columns:24px minmax(0,1fr) auto;gap:8px 12px;padding:14px 6px}.toc-target{grid-column:2;grid-row:1}.toc-status{grid-column:2;grid-row:2;justify-self:start}.toc-arrow{grid-column:3;grid-row:1}.toc-leader{display:none}.toc-footer{padding:14px 18px}}
@media print{body{background:white;color:black}main{padding:0;max-width:none}button,nav{display:none}.notice,.panel,.scroll,tr{box-shadow:none}tr,.toc-list li{break-inside:avoid}pre{max-height:none;background:#f0f0f0;color:black}a{color:inherit}}
"""


def timestamp_markup(value):
    """Readable UTC display with the original precision retained in markup."""
    esc = lambda text: html.escape(str(text), quote=True)
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return esc(value)
    zone = 'Time zone not recorded'
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
        zone = 'UTC'
    return ('<time class="report-timestamp" datetime="' + esc(value) + '" title="' + esc(value) +
            '"><span>' + parsed.strftime('%d %b %Y') + '</span><span>' +
            parsed.strftime('%H:%M:%S') + ' ' + zone + '</span></time>')


def target_section(target, details=None):
    esc = lambda value: html.escape(str(value), quote=True)
    try:
        parsed = urlsplit(target)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return ''
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    except ValueError:
        return ''
    fields = [('URL', target), ('Host', parsed.hostname), ('Port', port), ('Scheme', parsed.scheme.upper())]
    fields.extend((key, value) for key, value in (details or {}).items() if value is not None and value != '')
    timestamp_keys = {'Checked', 'Started', 'Finished', 'Generated'}
    rows = ''.join('<div class="target-field' + (' wide' if key in {'URL', 'Scope'} | timestamp_keys else '') +
                   '"><dt>' + esc(key) + '</dt><dd>' +
                   (timestamp_markup(value) if key in timestamp_keys else esc(value)) + '</dd></div>' for key, value in fields)
    return '<section class="target-card" aria-labelledby="targetHeading"><h2 id="targetHeading">Target Details</h2><dl>' + rows + '</dl></section>'


def page(title, body, subtitle='', target_details=None):
    esc = lambda value: html.escape(str(value), quote=True)
    recorded = (target_details or {}).get('Checked') or (target_details or {}).get('Started')
    try:
        footer_date = datetime.fromisoformat(str(recorded).replace('Z', '+00:00')) if recorded else datetime.now(timezone.utc)
        zone = 'UTC' if footer_date.tzinfo is not None else 'time zone not recorded'
        if footer_date.tzinfo is not None:
            footer_date = footer_date.astimezone(timezone.utc)
        date_label = footer_date.strftime('%d %b %Y') + ' (' + zone + ')'
    except ValueError:
        date_label = 'Date not recorded'
    csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + SCRIPT_HASH + "'; base-uri 'none'; form-action 'none'"
    return ('<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + esc(csp) + '">'
            '<title>' + esc(title) + '</title><style>' + STYLE + '</style></head><body><main>'
            '<header><div class="brand"><div class="mark">' + RAPTOR_LOGO + '</div><div><h1>' + esc(title) +
            '</h1><p class="subtitle">' + esc(subtitle) + '</p></div></div>'
            '<button id="themeToggle" type="button" aria-label="Switch to dark mode" title="Switch to dark mode" aria-pressed="false">'
            '<svg class="icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 13A9 9 0 0 1 11 3.5 9 9 0 1 0 20.5 13Z"/></svg>'
            '<svg class="icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/></svg></button></header>'
            '<aside class="notice disclaimer"><strong><span class="warning-icon" aria-hidden="true">⚠</span>Disclaimer</strong><p>' + esc(DISCLAIMER) + '</p></aside>' +
            target_section(subtitle, target_details) + body +
            '<footer>Generated by WebRaptor · For authorized security assessments only · Assessment date: ' + esc(date_label) + '</footer>'
            '</main><script>' + THEME_SCRIPT + '</script></body></html>')
