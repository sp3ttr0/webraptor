"""Local test double; never makes a network request."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

name = Path(sys.argv[0]).name
args = sys.argv[1:]
if '--fake-child' in args:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(args[-1]).write_text(str(os.getpid()))
    while True:
        time.sleep(.1)

mode = os.environ.get('WEBRAPTOR_TEST_MODE', 'success')
if args and args[-1] in ('--version', '-version', '-Version'):
    print(name + ' 1.2.3')
    sys.exit(0)
if args and args[-1] in ('--help', '--help-all', '-h', '-Help', 'all'):
    print('Usage: scanner [options]')
    print('--location --max-redirs --proto-redir --head --silent --show-error --url --disable --insecure --color --max-threads --wait --follow-redirect -v -H -Cgidirs -host -Pause -ask -nointeractive -Add-header -dates -no-subs -u -e --random-agent -t --max-rate --output-formats -o -w -jsonl -omit-raw -no-color -disable-redirects -stats -rate-limit --quiet --warnings --reqheader --no-colour' if os.environ.get('WEBRAPTOR_TEST_HELP') != 'missing' else '--unrelated')
    sys.exit(0)
events = os.environ.get('WEBRAPTOR_TEST_EVENTS')
def event(kind):
    if events:
        descriptor = os.open(events, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.write(descriptor, (json.dumps({'event': kind, 'module': name, 'pid': os.getpid(), 'time': time.monotonic()}) + '\n').encode())
        os.close(descriptor)

event('start')
print('diagnostic ' + ' '.join(args), file=sys.stderr, flush=True)
print('partial output', flush=True)
if mode in ('hang', 'child'):
    if mode == 'child':
        child = subprocess.Popen([sys.executable, __file__, '--fake-child', os.environ['WEBRAPTOR_TEST_CHILD_PID']])
        # Record the PID at spawn, independent of child interpreter startup time.
        Path(os.environ['WEBRAPTOR_TEST_CHILD_PID']).write_text(str(child.pid))
    while True:
        time.sleep(.1)
if mode == 'fail' or name == os.environ.get('WEBRAPTOR_TEST_FAIL_MODULE'):
    event('end')
    sys.exit(7)
if mode == 'slow':
    time.sleep(.2)
if name == 'nuclei' and mode != 'missing':
    out = Path(args[args.index('-o') + 1])
    if mode == 'invalid':
        out.write_text('{broken JSON\n')
    elif mode == 'empty':
        out.write_text('')
    else:
        out.write_text(json.dumps({'template-id': 'test-template', 'info': {'name': '<script>alert(1)</script>', 'severity': 'medium'}, 'matched-at': 'http://local.test/?x=<img>'}) + '\n')
elif name == 'dirsearch':
    Path(args[args.index('-o') + 1]).write_text('/admin 403\n')
event('end')
