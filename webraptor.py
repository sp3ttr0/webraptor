#!/usr/bin/env python3

# ===============================================================
# webraptor - Automated Web App Scanning Script
# ---------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# ===============================================================

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit, urlunsplit
import uuid

from colorama import Fore, Style, init as colorama_init
import httpx

colorama_init(autoreset=True)


def print_banner():
    banner = fr"""
        ⣠⣶⣶⠶⠖⠒⠒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⢠⠞⠁⠙⠏⢀⣀⣠⣤⣤⢬⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⡰⠃⠀⠐⠒⠉⠉⠉⠉⠉⠉⣩⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
    ⢀⠃⠀⠀⠀⠀⠀⠀⣀⣀⠤⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠒⣉⠥⠄⠀⠩⠽⢶⣤⣀⠀⠀⠀
    ⢸⠀⠀⠀⠀⣼⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢋⡴⠋⠀⠀⠀⠀⠀⠀⠀⠈⠙⠳⢦⡀
    ⠘⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠊⢠⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⡇⠀⠀⠀⠀⠑⢤⣀⣀⣀⣠⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠂⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠤⠒⠁⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠘⣷⠀⠀⠀⠀⠀⠀⠠⣀⠀⠀⠀⠀⠀⠀⠈⠉⠒⠒⠒⠒⠒⠂⠉⠁⠀⠀⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠹⣆⠀⠀⣄⠀⠀⠀⠈⠑⢄⠀⠀⠀⡴⠀⠀⠀⢄⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠙⢦⡀⠈⠑⠢⢤⡤⠄⠀⢱⠀⢰⠁⠀⠀⠀⠈⢆⠀⠀⣀⡠⠔⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⢰⠏⢹⣶⠒⣋⡥⣤⡄⠊⠁⠀⢸⡆⠀⠀⠀⠀⣸⠶⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⢿⣿⣿⣿⡀⠘⣿⣶⡷⢤⢄⣀⠀⡇⠀⠀⠀⠀⢼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠙⠻⠿⢧⠱⣤⡼⣧⡞⠀⢾⡉⠻⢦⡀⠀⠀⠈⠓⠲⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠈⠒⠛⢿⡁⠀⠀⠠⡇⠀⠀⠙⣄⠀⠀⠀⠀⠈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠢⣄⠀⠑⢄⠀⠀⠈⠓⠤⢄⣀⣀⡀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⢀⠼⠀⠀⠀⠀⠀⠀⠀⠀⠹⡀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡤⢋⣍⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢰⣟⢻⠋⢿⠭⠋⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⣿⣰⠀⡎⠣⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠈⣉⡙⠒⢚⣒⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⡧⠻⠤⠿⡷⠀ {Style.BRIGHT} by sp3ttr0⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
        webraptor 🦖 — Hunt Smarter, Not Harder
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")


MODULES = ('curl', 'whatweb', 'nikto', 'waybackurls', 'dirsearch', 'nuclei', 'testssl', 'sslscan')
TLS_MODULES = {'testssl', 'sslscan'}
AUTH_MODULES = {'testssl', 'curl', 'whatweb', 'nikto', 'dirsearch', 'nuclei'}
STOP = threading.Event()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('must be a finite positive number')
    return number


def normalize_target(raw):
    """Return a normalized URL and whether its scheme was explicitly supplied."""
    raw = raw.strip()
    explicit = '://' in raw
    try:
        if not raw or any(ord(c) <= 32 or ord(c) == 127 for c in raw):
            raise ValueError()
        parsed = urlsplit(raw if explicit else 'https://' + raw)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or '\\' in raw):
            raise ValueError()
        host = parsed.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        if ':' in host:
            host = '[' + str(ipaddress.IPv6Address(host)) + ']'
        elif not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                     for label in host.split('.')):
            raise ValueError()
        port = parsed.port
        if port == 0:
            raise ValueError()
        if port and (parsed.scheme, port) not in (('http', 80), ('https', 443)):
            host += ':' + str(port)
        return urlunsplit((parsed.scheme, host, parsed.path or '/', parsed.query, '')), explicit
    except (ValueError, UnicodeError):
        raise ValueError('Expected a domain or HTTP(S) URL without credentials, whitespace, or fragments') from None


def target_key(url):
    parsed = urlsplit(url)
    slug = re.sub(r'[^a-zA-Z0-9.-]', '_', parsed.netloc)[:80]
    return slug + '-' + hashlib.sha256(url.encode()).hexdigest()[:12]


class Redactor:
    def __init__(self, headers=()):
        secrets = set()
        for name, value in headers:
            secrets.add(value)
            if name.lower() in ('authorization', 'proxy-authorization'):
                secrets.add(value.split(' ', 1)[-1])
            if name.lower() == 'cookie':
                secrets.update(part.partition('=')[2].strip() for part in value.split(';'))
        self.secrets = sorted((s for s in secrets if s), key=len, reverse=True)
        variants = set(self.secrets)
        for value in self.secrets:
            variants.update((quote(value, safe=''), html.escape(value),
                             json.dumps(value)[1:-1]))
        self.pattern = re.compile('|'.join(re.escape(s) for s in sorted(variants, key=len, reverse=True))) if variants else None

    def __call__(self, text):
        text = str(text)
        if self.pattern:
            text = self.pattern.sub('[REDACTED]', text)
        # Also redact newly issued cookies and authorization lines in tool output.
        return re.sub(r'(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+',
                      r'\1[REDACTED]', text)


def read_headers(args):
    lines = list(args.header)
    if args.headers_file:
        lines.extend(Path(args.headers_file).read_text(encoding='utf-8').splitlines())
    if args.cookie:
        lines.append('Cookie: ' + args.cookie)
    if args.cookie_file:
        lines.append('Cookie: ' + Path(args.cookie_file).read_text(encoding='utf-8').strip())
    headers = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, separator, value = line.partition(':')
        name, value = name.strip(), value.strip()
        if (not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not value or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ValueError('Invalid header: use one ASCII Name: value per line')
        if name.lower() in headers:
            raise ValueError('Duplicate header names are not supported')
        headers[name.lower()] = (name, value)
    return list(headers.values())


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='WebRaptor — web application scanning workflow', allow_abbrev=False)
    parser.add_argument('target', nargs='?', help='Domain or HTTP(S) URL')
    parser.add_argument('-l', '--targets-file', help='One target per line; # comments allowed')
    parser.add_argument('--check-tools', action='store_true', help='Check versions and required CLI flags without scanning')
    parser.add_argument('--verify-findings', action='store_true', help=argparse.SUPPRESS)  # Legacy no-op; verification is automatic.
    parser.add_argument('--resume', help='Previous batch directory or run.json; writes a new run')
    parser.add_argument('--no-progress', action='store_true', help='Disable live scanner output and progress on stderr')
    parser.add_argument('--output-dir', default='results')
    parser.add_argument('--modules', default=','.join(MODULES), help='Comma-separated module names')
    parser.add_argument('--exclude', action='append', default=[], help='Comma-separated modules to omit; repeatable, applied after --modules')
    parser.add_argument('--threads', type=positive_int, default=6, help='Global maximum active scanner processes (default: 6)')
    parser.add_argument('--target-concurrency', type=positive_int, default=1, help='Concurrent target workflows (default: 1)')
    parser.add_argument('--tool-timeout', type=positive_float, default=1800, help='Wall-clock seconds per module (default: 1800)')
    parser.add_argument('--probe-timeout', type=positive_float, default=8, help='HTTP probe timeout in seconds (default: 8)')
    parser.add_argument('--allow-scheme-fallback', action='store_true', help='Allow explicit URLs to try the other scheme')
    parser.add_argument('--insecure', action='store_true', help='Disable certificate verification for the reachability probe and curl')
    parser.add_argument('--nuclei-template')
    parser.add_argument('--wordlist')
    parser.add_argument('--nuclei-rate', type=positive_int, default=20, help='Nuclei requests/sec per process (default: 20)')
    parser.add_argument('--dirsearch-rate', type=positive_int, default=10, help='Dirsearch requests/sec per process (default: 10)')
    parser.add_argument('--dirsearch-threads', type=positive_int, default=10)
    parser.add_argument('--whatweb-wait', type=positive_int, default=1, help='Seconds between WhatWeb connections (default: 1)')
    parser.add_argument('--nikto-pause', type=positive_float, default=1, help='Seconds between Nikto requests (default: 1)')
    parser.add_argument('-H', '--header', action='append', default=[], help='HTTP header; repeatable')
    parser.add_argument('--headers-file', help='File of HTTP headers, one Name: value per line')
    cookie = parser.add_mutually_exclusive_group()
    cookie.add_argument('--cookie', help='Cookie header value')
    cookie.add_argument('--cookie-file', help='File containing a Cookie header value')
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(tokens)
    if args.verify_findings and (args.resume or args.check_tools):
        parser.error('--verify-findings cannot be combined with --resume or --check-tools')
    supplied = {token.split('=', 1)[0] for token in tokens if token.startswith('-')}
    args.resume_data = None
    if args.resume:
        if args.target or args.targets_file or args.check_tools:
            parser.error('--resume cannot be combined with targets or --check-tools')
        try:
            args.resume_data = load_resume(args.resume)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            parser.error('Invalid or unsupported resume manifest; use a batch run.json from this version')
        for key, value in args.resume_data['settings'].items():
            option = '--' + key.replace('_', '-')
            if option in supplied and key not in ('threads', 'target_concurrency', 'tool_timeout', 'probe_timeout', 'modules'):
                parser.error(option + ' cannot be changed when resuming; start a new scan instead')
            if option not in supplied:
                setattr(args, key, ','.join(value) if key == 'modules' else value)
        if '--output-dir' not in supplied:
            args.output_dir = str(args.resume_data['base'])
    elif not args.check_tools and bool(args.target) == bool(args.targets_file):
        parser.error('Provide either target or --targets-file')
    elif args.check_tools and (args.target or args.targets_file):
        parser.error('--check-tools does not take a target')
    args.modules = list(dict.fromkeys(s.strip() for s in args.modules.split(',')))
    if not args.modules or any(m not in MODULES for m in args.modules):
        parser.error('--modules must contain names from: ' + ','.join(MODULES))
    excluded = {name.strip() for group in args.exclude for name in group.split(',')}
    if any(name not in MODULES for name in excluded):
        parser.error('--exclude must contain names from: ' + ','.join(MODULES))
    args.modules = [name for name in args.modules if name not in excluded]
    if not args.modules:
        parser.error('No modules remain after --exclude')
    try:
        for option in ('nuclei_template', 'wordlist', 'headers_file', 'cookie_file', 'targets_file'):
            value = getattr(args, option)
            if value:
                path = Path(value).expanduser().resolve()
                if not path.exists() or (option != 'nuclei_template' and not path.is_file()):
                    raise ValueError('Invalid --' + option.replace('_', '-') + ' path')
                setattr(args, option, str(path))
        args.headers = read_headers(args)
        lines = Path(args.targets_file).read_text(encoding='utf-8').splitlines() if args.targets_file else ([args.target] if args.target else [])
        targets = {}
        for line in lines:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            url, explicit = normalize_target(line)
            # Explicit scheme wins if both the bare domain and its HTTPS URL occur.
            targets[url] = targets.get(url, False) or explicit
        if args.resume_data:
            targets = dict(args.resume_data['targets'])
            expected = set(args.resume_data['header_names'])
            if expected != {name.lower() for name, _ in args.headers}:
                raise ValueError('Resume requires the original header names; resupply headers/cookies (values are never saved)')
            if any(m not in args.resume_data['settings']['modules'] for m in args.modules):
                raise ValueError('Resume can only select modules from the original run')
        if not targets and not args.check_tools:
            raise ValueError('Target list is empty')
        args.targets = list(targets.items())
        if args.headers and len({urlsplit(u).netloc for u in targets}) > 1:
            raise ValueError('Use separate runs for authenticated targets on different hosts or ports')
    except (ValueError, OSError, UnicodeError) as exc:
        # Do not echo arguments or file contents that may contain credentials.
        parser.error(str(exc) if isinstance(exc, ValueError) else 'Could not read input file')
    return args


# Scan settings are persisted without authentication values or input-file contents.
SAVED_SETTINGS = ('modules', 'threads', 'target_concurrency', 'tool_timeout', 'probe_timeout',
                  'allow_scheme_fallback', 'insecure', 'nuclei_template', 'wordlist',
                  'nuclei_rate', 'dirsearch_rate', 'dirsearch_threads', 'whatweb_wait', 'nikto_pause')


def load_resume(location):
    manifest = Path(location).expanduser().resolve()
    if manifest.is_dir():
        manifest /= 'run.json'
    data = json.loads(manifest.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1 or data.get('kind') != 'webraptor-run':
        raise ValueError('Unknown manifest')
    if manifest.parent.parent.name != '_runs' or data['run_id'] != manifest.parent.name:
        raise ValueError('Manifest must remain in its original batch layout')
    data['settings'].pop('js_advisories', None)  # Ignore the retired JavaScript-advisory setting in older v1 runs.
    if set(data['settings']) != set(SAVED_SETTINGS):
        raise ValueError('Incomplete settings')
    settings = data['settings']
    if (not isinstance(settings['modules'], list) or not settings['modules']
            or any(m not in MODULES for m in settings['modules'])):
        raise ValueError('Invalid modules')
    for key in ('threads', 'target_concurrency', 'nuclei_rate', 'dirsearch_rate', 'dirsearch_threads', 'whatweb_wait'):
        if type(settings[key]) is not int or settings[key] < 1:
            raise ValueError('Invalid numeric settings')
    for key in ('tool_timeout', 'probe_timeout', 'nikto_pause'):
        if type(settings[key]) not in (int, float) or not math.isfinite(settings[key]) or settings[key] <= 0:
            raise ValueError('Invalid timeout settings')
    for key in ('insecure', 'allow_scheme_fallback'):
        if type(settings[key]) is not bool:
            raise ValueError('Invalid boolean setting')
    for key in ('wordlist', 'nuclei_template'):
        if settings[key] is not None and not isinstance(settings[key], str):
            raise ValueError('Invalid path setting')
    if not isinstance(data['header_names'], list) or not all(isinstance(n, str) for n in data['header_names']):
        raise ValueError('Invalid headers')
    if not isinstance(data['targets'], list) or not data['targets']:
        raise ValueError('Invalid targets')
    for target, explicit in data['targets']:
        if '[REDACTED]' in target or normalize_target(target)[0] != target or type(explicit) is not bool:
            raise ValueError('Target unavailable for resume')
    data['base'] = manifest.parent.parent.parent
    return data


def file_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def reusable_results(target, args):
    if not args.resume_data:
        return {}
    data = args.resume_data
    folder = data['base'] / target_key(target) / data['run_id']
    try:
        summary_path = folder / 'data' / 'summary.json'
        if not summary_path.exists():
            summary_path = folder / 'summary.json'  # Pre-layout runs remain resumable.
        summary = json.loads(summary_path.read_text(encoding='utf-8'))
        if summary['target'] != target:
            return {}
        reusable = {}
        for result in summary['modules']:
            module = result['module']
            if module not in args.modules or result['status'] not in ('completed', 'not_applicable'):
                continue
            valid = True
            artifacts = result['artifacts']
            if result['status'] == 'completed' and not artifacts:
                continue
            for relative in artifacts:
                if not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
                    valid = False
                    break
                path = (folder / relative).resolve()
                if (not path.is_relative_to(folder.resolve()) or not path.is_file()
                        or result.get('artifact_hashes', {}).get(relative) != file_digest(path)):
                    valid = False
                    break
            if valid:
                reusable[module] = (folder, result)
        return reusable
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


class Progress:
    def __init__(self, targets, modules, enabled=True, interval=2.0):
        self.enabled, self.interval = enabled, interval
        self.lock, self.finished = threading.Lock(), threading.Event()
        self.started = time.monotonic()
        self.states = {(target_key(t), m): ('queued', self.started) for t, _ in targets for m in modules}
        self.worker = None
        self.tty = sys.stderr.isatty()
        self.last_counts = None
        self.multiple = len(targets) > 1

    def output(self, target, module, text):
        if not self.enabled:
            return
        with self.lock:
            print(text, file=sys.stderr, flush=True)

    def update(self, target, module, status):
        if not self.enabled:
            return
        with self.lock:
            key = (target_key(target), module)
            old, since = self.states.get(key, ('queued', time.monotonic()))
            self.states[key] = (status, time.monotonic())
            elapsed = time.monotonic() - since if old == 'running' else 0
            label = {'whatweb': 'WhatWeb', 'nikto': 'Nikto', 'dirsearch': 'Dirsearch',
                     'nuclei': 'Nuclei', 'waybackurls': 'Waybackurls',
                     'verification': 'Finding Verification'}.get(module, module)
            if self.multiple:
                label += ' (' + urlsplit(target).netloc + ')'
            if status == 'running':
                message, color = f'Running {label}', Fore.CYAN
            else:
                outcome = {'completed': 'Finished', 'failed': 'Failed', 'timed_out': 'Timed Out',
                           'cancelled': 'Cancelled', 'skipped': 'Skipped',
                           'not_applicable': 'Not Applicable'}.get(status, status)
                message = f'{label}: {outcome} ({elapsed:.1f}s)'
                color = Fore.GREEN if status == 'completed' else Fore.YELLOW
            print((color if self.tty else '') + message + (Style.RESET_ALL if self.tty else ''),
                  file=sys.stderr, flush=True)

    def render(self):
        # Tool lifecycle messages replace the former periodic progress summaries.
        return

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.finished.set()


def probe_target(url, explicit, args, stop):
    candidates = [url]
    if not explicit or args.allow_scheme_fallback:
        parsed = urlsplit(url)
        candidates.append(urlunsplit(parsed._replace(scheme='http' if parsed.scheme == 'https' else 'https')))
    errors = []
    for candidate in candidates:
        if stop.is_set():
            break
        try:
            with httpx.Client(timeout=args.probe_timeout, verify=not args.insecure,
                              follow_redirects=False, headers=dict(args.headers)) as client:
                # Reading just headers avoids waiting for large/streaming bodies.
                with client.stream('GET', candidate) as response:
                    return candidate, {'status': 'reachable', 'http_status': response.status_code,
                                       'scheme_changed': candidate != url}
        except httpx.RequestError as exc:
            errors.append(type(exc).__name__)
    return None, {'status': 'cancelled' if stop.is_set() else 'unreachable', 'errors': errors}


def terminate_group(proc, grace=1.0):
    """Terminate the whole process group, even if its original leader exited."""
    def signal_group(sig):
        try:
            os.killpg(proc.pid, sig)
        except PermissionError as exc:
            # Darwin may return EPERM for a group whose only member became a
            # zombie after poll(). Reap that leader and retry: an empty group
            # then reports ESRCH. Keep genuine permission failures visible.
            if sys.platform != 'darwin':
                raise
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                raise exc
            os.killpg(proc.pid, sig)

    try:
        signal_group(signal.SIGTERM)
    except ProcessLookupError:
        proc.wait()
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        proc.poll()  # Reap leader before checking whether descendants remain.
        try:
            signal_group(0)
        except ProcessLookupError:
            proc.wait()
            return
        time.sleep(0.05)
    try:
        signal_group(signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def copy_redacted(source, destination, redact):
    source.seek(0)
    with destination.open('w', encoding='utf-8') as output:
        for line in source:
            output.write(redact(line.decode('utf-8', errors='replace')))


def run_command(cmd, stdout_path, stderr_path, timeout, stop, redact, on_output=None):
    started = time.monotonic()
    result = {'status': 'cancelled', 'exit_code': None, 'duration_seconds': 0.0}
    if stop.is_set():
        return result
    # Anonymous temporary streams prevent credentials echoed by a scanner from
    # appearing in persistent console logs before redaction.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = None
        offsets, pending, dropping = [0, 0], [b'', b''], [False, False]
        def emit(data):
            text = data.decode('utf-8', errors='replace')
            text = re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)', '', text)
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
            text = ''.join(c for c in text if c == '\t' or ord(c) >= 32 and ord(c) != 127)
            if text.strip():
                on_output(redact(text))
        def stream_output(final=False):
            if on_output is None:
                return
            for index, source in enumerate((out, err)):
                # Independent offsets avoid disturbing the child's file writes.
                while True:
                    block = os.pread(source.fileno(), 65536, offsets[index])
                    if not block:
                        break
                    offsets[index] += len(block)
                    parts = re.split(rb'[\r\n]', pending[index] + block)
                    pending[index] = parts.pop()
                    for part in parts:
                        if not dropping[index]:
                            emit(part)
                        dropping[index] = False
                    # Never publish incomplete lines or a fragment of a secret.
                    if len(pending[index]) > 65536:
                        pending[index], dropping[index] = b'', True
                if final and pending[index] and not dropping[index]:
                    emit(pending[index])
                    pending[index] = b''
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=err, start_new_session=True)
            while True:
                stream_output()
                if stop.is_set():
                    result['status'] = 'cancelled'
                    terminate_group(proc)
                    break
                if time.monotonic() - started >= timeout:
                    result['status'] = 'timed_out'
                    terminate_group(proc)
                    break
                code = proc.poll()
                if code is not None:
                    result.update(status='completed' if code == 0 else 'failed', exit_code=code)
                    # Clean up any scanner descendants still alive after exit.
                    terminate_group(proc)
                    break
                stop.wait(0.05)
        except OSError as exc:
            result.update(status='failed', error=type(exc).__name__)
        finally:
            if proc is not None and proc.poll() is None:
                terminate_group(proc)
            stream_output(final=True)
            copy_redacted(out, stdout_path, redact)
            copy_redacted(err, stderr_path, redact)
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    return result


def tool_executable(module):
    if module == 'testssl':
        return shutil.which('testssl') or shutil.which('testssl.sh')
    return shutil.which(module)


# Help probes have no targets and never execute scanner tests.
TOOL_CHECKS = {
    'curl': (['--disable', '--version'], ['--disable', '--help', 'all'], ['--head', '--silent', '--show-error', '--url', '--disable', '--location', '--max-redirs', '--proto-redir']),
    'whatweb': (['--version'], ['--help'], ['--color', '--max-threads', '--wait', '--follow-redirect', '-v']),
    'nikto': (['-Version'], ['-Help'], ['-Cgidirs', '-host', '-Pause', '-ask', '-nointeractive']),
    'waybackurls': (None, ['-h'], ['-dates', '-no-subs']),
    'dirsearch': (['--version'], ['--help-all'], ['-u', '-e', '--random-agent', '-t', '--max-rate', '--output-formats', '-o']),
    'nuclei': (['-version'], ['-h'], ['-u', '-jsonl', '-omit-raw', '-no-color', '-disable-redirects', '-rate-limit', '-o']),
    'testssl': (['--version'], ['--help'], ['--quiet', '--color', '--warnings']),
    'sslscan': (['--version'], ['--help'], ['--no-colour']),
}


def check_tools(args):
    """Inspect local version/help output, not target connectivity."""
    failed = False
    for module in args.modules:
        executable = tool_executable(module)
        if not executable:
            print(f'{module}: MISSING')
            failed = True
            continue
        version_args, help_args, base_flags = TOOL_CHECKS[module]
        flags = list(base_flags)
        if module in AUTH_MODULES:
            flags.append({'nikto': '-Add-header', 'testssl': '--reqheader'}.get(module, '-H'))
        if module == 'curl':
            flags.append('--insecure')
        if module == 'dirsearch':
            flags.append('-w')
        if module == 'nuclei':
            flags.append('-t')
        with tempfile.TemporaryDirectory(prefix='webraptor-check-') as temp:
            folder = Path(temp)
            def probe(arguments):
                result = run_command([executable] + arguments, folder / 'out', folder / 'err',
                                     10, threading.Event(), Redactor())
                output = ''.join(p.read_text() for p in (folder / 'out', folder / 'err') if p.exists())
                return result, re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)
            help_result, help_text = probe(help_args)
            # Released dirsearch versions may expose their full CLI through --help.
            if module == 'dirsearch' and help_result['status'] == 'failed':
                help_result, help_text = probe(['--help'])
            missing = [flag for flag in flags if not re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', help_text)]
            version = 'not exposed by upstream; executable SHA256 ' + file_digest(Path(executable))[:16]
            version_ok = True
            if version_args:
                version_result, version_text = probe(version_args)
                lines = [line.strip() for line in version_text.splitlines() if line.strip()]
                version = next((line for line in lines if re.search(r'\d+\.\d+', line)), lines[0] if lines else 'unavailable')[:180]
                version_ok = version_result['status'] == 'completed' and bool(lines)
            # Several CLIs return 1 after printing valid help; that alone is not a failure.
            help_ok = help_result['exit_code'] in (0, 1, 2) and bool(help_text) and not missing
            ok = help_ok and version_ok
            failed |= not ok
            print(f'{module}: {"OK" if ok else "INCOMPATIBLE/UNVERIFIED"} | {version} | {executable}')
            if missing:
                print('  Missing required flags: ' + ', '.join(missing))
            if not version_ok or help_result['status'] in ('timed_out', 'cancelled'):
                print('  Version/help probe failed or timed out (10-second limit per command).')
    return 1 if failed else 0


def tls_endpoint(target):
    parsed = urlsplit(target)
    host = parsed.hostname
    if ':' in host:
        host = '[' + host + ']'
    return host + ':' + str(parsed.port or 443)


def build_command(module, target, folder, args):
    """Tool outputs are relative to the target run, with separate console logs."""
    artifact = folder / (module + '_results.txt')
    if module == 'curl':
        cmd = ['curl', '--disable', '--head', '--silent', '--show-error', '--url', target, '--location', '--max-redirs', '10', '--proto-redir', '=http,https']
        if args.insecure:
            cmd.append('--insecure')
    elif module == 'testssl':
        cmd = [tool_executable('testssl') or 'testssl', '--quiet', '--color', '0', '--warnings', 'batch']
    elif module == 'sslscan':
        cmd = ['sslscan', '--no-colour', tls_endpoint(target)]
    elif module == 'whatweb':
        cmd = ['whatweb', '-v', '--color=never', '--max-threads=1',
               '--wait=' + str(args.whatweb_wait), '--follow-redirect=never', target]
    elif module == 'nikto':
        cmd = ['nikto', '-C', 'all', '-host', target, '-Pause', str(args.nikto_pause), '-ask', 'no', '-nointeractive']
    elif module == 'waybackurls':
        artifact = folder / 'wayback_results' / 'urls.txt'
        cmd = ['waybackurls', urlsplit(target).hostname]
    elif module == 'dirsearch':
        artifact = folder / 'dirsearch_results' / 'results.txt'
        cmd = ['dirsearch', '-u', target, '-e', 'php,asp,aspx,jsp,html,js,json',
               '--random-agent', '-t', str(args.dirsearch_threads),
               '--max-rate', str(args.dirsearch_rate), '--output-formats', 'plain', '-o', str(artifact)]
        if args.wordlist:
            cmd += ['-w', args.wordlist]
    else:
        artifact = folder / 'nuclei_results.jsonl'
        cmd = ['nuclei', '-u', target, '-jsonl', '-omit-raw', '-no-color',
               '-disable-redirects', '-rate-limit', str(args.nuclei_rate), '-o', str(artifact)]
        if args.nuclei_template:
            cmd += ['-t', args.nuclei_template]
    if module in AUTH_MODULES:
        flag = {'nikto': '-Add-header', 'testssl': '--reqheader'}.get(module, '-H')
        for name, value in args.headers:
            cmd += [flag, name + ': ' + value]
    if module == 'testssl':
        cmd.append(tls_endpoint(target))  # testssl requires the endpoint last.
    artifact.parent.mkdir(parents=True, exist_ok=True)
    return cmd, artifact


def redact_artifact(path, redact):
    """Redact supplied secrets from UTF-8 tool reports; do not follow symlinks."""
    paths = path.rglob('*') if path.is_dir() else [path]
    for item in paths:
        if item.is_symlink() or not item.is_file():
            continue
        try:
            text = item.read_text(encoding='utf-8')
        except UnicodeError:
            continue  # Screenshots/databases are raw evidence, not console logs.
        cleaned = redact(text)
        if cleaned != text:
            item.write_text(cleaned, encoding='utf-8')


def nuclei_findings(path, status, redact):
    findings, bad_lines = [], 0
    if not path.exists():
        return findings, 'output_missing'
    with path.open(encoding='utf-8', errors='replace') as source:
        for line in source:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                info = item.get('info', {})
                if not isinstance(info, dict) or not item.get('template-id'):
                    raise ValueError()
                findings.append({key: redact(value) for key, value in {
                    'template_id': item['template-id'], 'name': info.get('name', ''),
                    'severity': info.get('severity', 'unknown'),
                    'matched_at': item.get('matched-at', item.get('host', ''))}.items()})
            except (ValueError, AttributeError, TypeError):
                bad_lines += 1
    if bad_lines:
        return findings, 'invalid_output'
    return findings, 'complete' if status == 'completed' else 'partial'


def execute_module(module, target, folder, args, slots, stop, redact, progress_target=None):
    result = {'module': module, 'status': 'cancelled', 'duration_seconds': 0,
              'exit_code': None, 'findings': [], 'findings_status': 'not_parsed', 'artifacts': []}
    if module in TLS_MODULES and urlsplit(target).scheme != 'https':
        result.update(status='not_applicable', error='TLS checks require an HTTPS target; HTTP targets are not redirected to a different port')
        return result
    while not stop.is_set():
        if slots.acquire(timeout=0.1):
            break
    else:
        return result
    try:
        if stop.is_set():
            return result
        progress = getattr(args, 'progress', None)
        if progress:
            progress.update(progress_target or target, module, 'running')
        cmd, artifact = build_command(module, target, folder, args)
        stdout = artifact if module in ('curl', 'whatweb', 'nikto', 'waybackurls', 'testssl', 'sslscan') else folder / (module + '_stdout.log')
        stderr = folder / (module + '_stderr.log')
        result['started_at'] = timestamp()
        result['authentication'] = 'not_applicable' if module in ('waybackurls', 'sslscan') else ('headers_supplied' if args.headers else 'none')
        callback = (lambda text: progress.output(progress_target or target, module, text)) if progress and progress.enabled else None
        result.update(run_command(cmd, stdout, stderr, args.tool_timeout, stop, redact, on_output=callback))
        redact_artifact(artifact, redact)
        if module == 'nuclei':
            result['findings'], result['findings_status'] = nuclei_findings(artifact, result['status'], redact)
            if result['status'] == 'completed' and result['findings_status'] != 'complete':
                result.update(status='failed', error='Nuclei output missing or invalid; findings may be incomplete')
        elif module == 'dirsearch' and result['status'] == 'completed' and not artifact.exists():
            result.update(status='failed', error='Expected scanner output is missing')
        result['artifacts'] = list(dict.fromkeys(str(p.relative_to(folder)) for p in (artifact, stdout, stderr) if p.exists()))
        result['artifact_hashes'] = {p: file_digest(folder / p) for p in result['artifacts'] if (folder / p).is_file()}
        return result
    except Exception as exc:
        # Exception messages may embed subprocess arguments; keep only the type.
        result.update(status='failed', error=type(exc).__name__)
        return result
    finally:
        slots.release()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    temporary.replace(path)


def report_html(summary):
    from report_ui import page
    esc = lambda value: html.escape(str(value), quote=True)
    rows, findings = [], []
    for module in summary['modules']:
        count = str(len(module['findings'])) if module['findings_status'] == 'complete' else module['findings_status'].replace('_', ' ')
        links = ' · '.join('<a href="' + quote(p, safe='/') + '">' + esc(p) + '</a>' for p in module['artifacts'])
        values = (esc(module['module']), esc(module['status']), esc(module['duration_seconds']), esc(count), esc(module.get('error', '')), links)
        labels = ('Module', 'Status', 'Seconds', 'Findings', 'Details', 'Tool evidence')
        rows.append('<tr>' + ''.join('<td data-label="' + label + '">' + value + '</td>' for label, value in zip(labels, values)) + '</tr>')
        for finding in module['findings']:
            findings.append('<tr><td data-label="Tool">Nuclei</td>' + ''.join('<td data-label="' + label + '">' + esc(finding[key]) + '</td>'
                for key, label in (('template_id', 'Template'), ('name', 'Name'), ('matched_at', 'Location'))) + '</tr>')
    verification = summary.get('verification', {})
    verification_html = ('<h2>Finding verification</h2><p>Status: ' + esc(verification.get('status', 'unavailable')) +
                         ' · <a href="report.html">Verified findings and cited evidence</a> · '
                         '<a href="verification.json">JSON</a></p>') if verification else ''
    body = '<p>Status: <strong>' + esc(summary['status']) + '</strong> · Started: ' + esc(summary['started_at']) + '</p>' + verification_html
    body += '<h2>Scanner modules and source artifacts</h2><div class="panel"><table><thead><tr><th>Module</th><th>Status</th><th>Seconds</th><th>Findings</th><th>Details</th><th>Tool evidence</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
    body += '<h2>Nuclei scanner matches</h2><p class="muted">Scanner matches require validation. Tool-provided risk ratings remain in raw source data; this report assigns no risk ratings.</p><div class="panel"><table><thead><tr><th>Tool</th><th>Template</th><th>Name</th><th>Location</th></tr></thead><tbody>' + ''.join(findings) + '</tbody></table></div>'
    body += '<p><a href="summary.json">JSON summary</a> · <a href="scan.log">Scan log</a></p>'
    return page('WebRaptor Web Application Security Assessment Report', body, summary['target'],
                {'Server': verification.get('server', 'Not recorded'), 'Started': summary['started_at'],
                 'HTTP response': summary.get('probe', {}).get('http_status'),
                 'Effective URL': summary.get('effective_target')})


def verify_target(target, args, folder, slots, stop, redact, modules=()):
    from verification import assess_target
    # Verification's scanner shares the same global process budget.
    while not stop.is_set():
        if slots.acquire(timeout=0.1):
            try:
                return assess_target(target, args, folder, stop, run_command, redact, modules)
            finally:
                slots.release()
    return assess_target(target, args, folder, stop, run_command, redact, modules)


def scan_target(target, explicit, args, batch_id, slots, stop, redact):
    started = time.monotonic()
    folder = Path(args.output_dir).resolve() / target_key(target) / batch_id
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    reusable = reusable_results(target, args)
    summary = {'schema_version': 1, 'target': redact(target), 'started_at': timestamp(),
               'status': 'running', 'modules': [], 'probe': {}, 'run_directory': str(folder)}
    with (folder / 'scan.log').open('w', encoding='utf-8') as log:
        def record(message):
            log.write(timestamp() + ' ' + redact(message) + '\n')
            log.flush()
        record('Target workflow started')
        write_json(folder / 'summary.json', summary)
        try:
            pending = [m for m in args.modules if m not in reusable]
            if not pending or set(pending) <= TLS_MODULES:
                canonical, summary['probe'] = None, {'status': 'not_required'}
            else:
                canonical, summary['probe'] = probe_target(target, explicit, args, stop)
            if canonical:
                summary['effective_target'] = redact(canonical)
                record('Probe succeeded; scheme changed: ' + str(canonical != target))
            else:
                record('Probe ' + summary['probe']['status'])
            # Archive and TLS modules do not require a successful HTTP probe.
            with ThreadPoolExecutor(max_workers=min(args.threads, len(args.modules))) as pool:
                jobs = {}
                for module in args.modules:
                    if module in reusable:
                        old_folder, previous = reusable[module]
                        result = copy.deepcopy(previous)
                        for relative in result['artifacts']:
                            destination = folder / relative
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(old_folder / relative, destination)
                        result['reused_from'] = str(old_folder)
                        summary['modules'].append(result)
                        if getattr(args, 'progress', None):
                            args.progress.update(target, module, 'reused')
                        record(module + ': reused completed result')
                        write_json(folder / 'summary.json', summary)
                        continue
                    if (not canonical and module not in TLS_MODULES | {'waybackurls'}) or stop.is_set():
                        summary['modules'].append({'module': module, 'status': 'cancelled' if stop.is_set() else 'skipped',
                            'error': 'Target probe did not complete successfully', 'duration_seconds': 0,
                            'exit_code': None, 'findings': [], 'findings_status': 'not_parsed', 'artifacts': []})
                        if getattr(args, 'progress', None):
                            args.progress.update(target, module, summary['modules'][-1]['status'])
                    else:
                        jobs[pool.submit(execute_module, module, target if module in TLS_MODULES else (canonical or target), folder, args, slots, stop, redact, target)] = module
                for future in as_completed(jobs):
                    result = future.result()
                    summary['modules'].append(result)
                    if getattr(args, 'progress', None):
                        args.progress.update(target, result['module'], result['status'])
                    record(result['module'] + ': ' + result['status'])
                    write_json(folder / 'summary.json', summary)
            summary['modules'].sort(key=lambda m: args.modules.index(m['module']))
            record('Finding verification started')
            if getattr(args, 'progress', None):
                args.progress.update(target, 'verification', 'running')
            try:
                summary['verification'] = verify_target(target, args, folder, slots, stop, redact, summary['modules'])
            except Exception as exc:
                from verification import CHECKS, render_report, enrich_finding
                verification = {'target': redact(target), 'status': 'failed',
                                'checks': [enrich_finding(check({'target': target, 'headers': [], 'error': type(exc).__name__})) for check in CHECKS]}
                write_json(folder / 'verification.json', verification)
                (folder / 'report.html').write_text(render_report(verification), encoding='utf-8')
                summary['verification'] = verification
            record('Finding verification ' + summary['verification']['status'])
            if getattr(args, 'progress', None):
                args.progress.update(target, 'verification', summary['verification']['status'])
            summary['status'] = ('cancelled' if stop.is_set() else
                                 'completed' if (all(m['status'] in ('completed', 'not_applicable') for m in summary['modules'])
                                                 and summary['verification']['status'] == 'completed') else 'incomplete')
        except Exception as exc:
            summary.update(status='failed', error=type(exc).__name__)
            record('Workflow failed: ' + type(exc).__name__)
        summary['duration_seconds'] = round(time.monotonic() - started, 3)
        summary['finished_at'] = timestamp()
        record('Workflow ' + summary['status'])
    write_json(folder / 'summary.json', summary)
    from output_layout import organize_output
    summary = organize_output(folder, summary)
    print('[' + summary['status'] + '] Report: ' + str(folder / 'report.html'))
    return summary


def write_batch(folder, batch_id, results):
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    summary = {'schema_version': 1, 'run_id': batch_id, 'targets': results}
    write_json(folder / 'summary.json', summary)
    rows = []
    for result in results:
        path = os.path.relpath(Path(result['run_directory']) / 'report.html', folder)
        rows.append('<li><a href="' + quote(path, safe='/') + '">' + html.escape(result['target']) +
                    '</a> — ' + html.escape(result['status']) + '</li>')
    from report_ui import page
    (folder / 'report.html').write_text(page('WebRaptor Web Application Security Assessment Report', '<section class="notice"><h2>Targets</h2><ul>' +
        ''.join(rows) + '</ul><p><a href="summary.json">JSON summary</a></p></section>', batch_id), encoding='utf-8')


def main(argv=None):
    args = parse_args(argv)
    if os.name != 'posix':
        print('WebRaptor currently requires Linux or macOS.', file=sys.stderr)
        return 1
    if args.check_tools:
        return check_tools(args)
    needed = {m for target, _ in args.targets for m in args.modules if m not in reusable_results(target, args)}
    missing = [m for m in args.modules if m in needed and not tool_executable(m)]
    if missing:
        print('Missing selected tools: ' + ', '.join(missing), file=sys.stderr)
        return 1
    STOP.clear()
    def handle_signal(signum, frame):
        STOP.set()
    previous = {sig: signal.signal(sig, handle_signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    old_umask = os.umask(0o077)
    try:
        print_banner()
        batch_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '-' + uuid.uuid4().hex[:8]
        batch_folder = Path(args.output_dir).resolve() / '_runs' / batch_id
        slots = threading.BoundedSemaphore(args.threads)
        redact = Redactor(args.headers)
        results = []
        batch_folder.mkdir(parents=True, exist_ok=False, mode=0o700)
        write_json(batch_folder / 'run.json', {
            'kind': 'webraptor-run', 'schema_version': 1, 'run_id': batch_id,
            'targets': [[redact(t), explicit] for t, explicit in args.targets],
            'settings': {key: getattr(args, key) for key in SAVED_SETTINGS},
            'header_names': [name.lower() for name, _ in args.headers],
        })
        print('Resume manifest: ' + str(batch_folder / 'run.json'), flush=True)
        with Progress(args.targets, args.modules + ['verification'], not args.no_progress) as progress, ThreadPoolExecutor(max_workers=min(args.target_concurrency, len(args.targets))) as pool:
            args.progress = progress
            futures = [pool.submit(scan_target, target, explicit, args, batch_id, slots, STOP, redact)
                       for target, explicit in args.targets]
            for future in as_completed(futures):
                results.append(future.result())
                write_batch(batch_folder, batch_id, results)
        print('Batch report: ' + str(batch_folder / 'report.html'))
        return 130 if STOP.is_set() else (0 if all(r['status'] == 'completed' for r in results) else 1)
    except OSError as exc:
        print('Output/process error: ' + type(exc).__name__, file=sys.stderr)
        return 1
    finally:
        os.umask(old_umask)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    sys.exit(main())
