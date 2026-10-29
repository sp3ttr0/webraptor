"""Validate Ghostcat loot and its provenance; never trust a console marker alone."""
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
FAIL = re.compile(r'unable to read file|auxiliary failed|exception|timed out|connection refused|error:', re.I)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def xml_valid(data):
    try:
        return ET.fromstring(data).tag.split('}')[-1] == 'web-app'
    except (ET.ParseError, ValueError):
        return False


def scoped(path):
    return {str(ipaddress.ip_address(x.strip())) for x in path.read_text().splitlines() if x.strip()}


def collect(result, scope):
    allowed = scoped(scope)
    raw = result.read_text(errors='replace')
    lines = ANSI.sub('', raw).splitlines()
    blocks = []
    host, block, start = None, [], 0
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r'RHOST => (\S+)', line)
        if match:
            if host:
                blocks.append((host, block, start))
            host, block, start = match[1], [], number
        elif host:
            block.append((number, line))
    if host:
        blocks.append((host, block, start))
    records = []
    sources = set()
    for host, block, start in blocks:
        if host not in allowed or any(FAIL.search(line) for _, line in block):
            continue
        for number, line in block:
            match = re.fullmatch(r'\[\+\] (?:([^ ]+) - )?File contents save to: (.+)', line)
            if not match:
                continue
            endpoint = f'[{host}]:8009' if ':' in host else f'{host}:8009'
            if match[1] and match[1] != endpoint:
                continue
            source = Path(match[2])
            # Metasploit names each loot file using the originating host.
            if not re.search(r'(?<![0-9a-fA-F:.])' + re.escape(host) + r'(?![0-9:])', source.name) or source.is_symlink() or not source.is_file():
                continue
            if source.resolve() in sources:
                continue
            data = source.read_bytes()
            if not data or not xml_valid(data):
                continue
            # Require the retrieved descriptor in this host's console block too.
            body = '\n'.join(text for nr, text in block if nr < number)
            begin = body.find('<?xml')
            if begin < 0:
                begin = body.find('<web-app')
            end = body.rfind('</web-app>')
            if begin < 0 or end < 0:
                continue
            evidence_xml = body[begin:end + len('</web-app>')]
            if not xml_valid(evidence_xml):
                continue
            if ET.tostring(ET.fromstring(evidence_xml)) != ET.tostring(ET.fromstring(data)):
                continue
            loot_dir = result.parent.parent / 'loot'
            loot_dir.mkdir(exist_ok=True)
            dest = loot_dir / f'ghostcat_{host.replace(":", "_")}_8009_web.xml'
            if dest.is_symlink():
                continue
            dest.write_bytes(data)
            dest.chmod(0o600)
            sources.add(source.resolve())
            records.append(dict(host=host, port=8009, loot=str(dest), sha256=digest(dest), line=number))
    manifest = Path(str(result) + '.verified.json')
    manifest.write_text(json.dumps(dict(evidence_sha256=digest(result), records=records), indent=2))
    manifest.chmod(0o600)


def read(result, scope, mode):
    allowed = scoped(scope)
    manifest = json.loads(Path(str(result) + '.verified.json').read_text())
    if manifest['evidence_sha256'] != digest(result):
        return
    lines = ANSI.sub('', result.read_text(errors='replace')).splitlines()
    for row in manifest['records']:
        host, port, loot = row['host'], row['port'], Path(row['loot'])
        if host not in allowed or port != 8009 or loot.is_symlink() or not loot.is_file():
            continue
        expected = result.parent.parent / 'loot' / f'ghostcat_{host.replace(":", "_")}_8009_web.xml'
        if loot.resolve() != expected.resolve() or digest(loot) != row['sha256'] or not xml_valid(loot.read_bytes()):
            continue
        endpoint = f'[{host}]:8009' if ':' in host else f'{host}:8009'
        number = row['line']
        if not 1 <= number <= len(lines):
            continue
        evidence = html.escape(lines[number - 1], quote=True)
        if mode == 'endpoints':
            print(endpoint)
        elif mode == 'paths':
            print(loot)
        elif mode == 'rows':
            print(f'{endpoint}\034{number}\034{evidence}')
        else:
            print(evidence)


if __name__ == '__main__':
    try:
        action, result, scope, *rest = sys.argv[1:]
        if action == 'collect':
            collect(Path(result), Path(scope))
        else:
            read(Path(result), Path(scope), rest[0] if rest else 'evidence')
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError):
        if sys.argv[1] == 'collect':
            sys.exit(1)
