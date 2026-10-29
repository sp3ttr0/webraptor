const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../lib/report.sh'), 'utf8');
const script = source.split('// COPY_TARGETS_START')[1].split('// COPY_TARGETS_END')[0];

async function test({ table = false, clipboard = 'success', fallback = true, empty = false }) {
  const status = { textContent: '' };
  const values = empty ? [] : ['192.0.2.1:445', '192.0.2.2:445', '192.0.2.1:445'];
  const expected = empty ? '' : '192.0.2.1:445\n192.0.2.2:445';
  let copiedText;
  let removed = false;
  let focused = false;
  let field;
  const document = {
    querySelectorAll: () => [],
    createElement: () => (field = {
      style: {}, setAttribute() {}, select() {}, remove() { removed = true; }
    }),
    body: { appendChild() {} },
    execCommand: command => {
      assert.equal(command, 'copy');
      copiedText = field.value;
      return fallback;
    }
  };
  const navigator = clipboard === 'absent' ? {} : {
    clipboard: { async writeText(text) {
      if (clipboard === 'denied') throw new Error('clipboard denied');
      copiedText = text;
    } }
  };
  const container = {
    querySelector: selector => selector === '.copy-targets-status' ? status
      : table ? null : { textContent: values.join('\n') + '\n' },
    querySelectorAll: () => values.map(value => ({ cells: [
      { textContent: value }, { textContent: 'cipher names must not be copied' }
    ] }))
  };
  const button = { closest: () => container, focus() { focused = true; } };
  const copy = new Function('document', 'navigator', script + '\nreturn copyAffectedTargets;')(document, navigator);
  await copy(button);
  if (empty) {
    assert.equal(status.textContent, 'No targets to copy.');
    assert.equal(copiedText, undefined);
  } else {
    assert.equal(copiedText, expected);
    assert.equal(status.textContent, clipboard === 'success' || fallback
      ? 'Copied 2 hosts.'
      : 'Copy unavailable. Select the Host:Port values and copy manually.');
    if (clipboard !== 'success') assert.ok(removed && focused);
  }
}

async function testCredentials(mode, unknownOnly = false) {
  const status = { textContent: '' };
  let copied;
  const rows = unknownOnly ? [['', 'username: unknown']] : [
    ['192.0.2.10:3306', 'username: alice'],
    ['192.0.2.10:3306', 'username: root'],
    ['192.0.2.10:3306', 'username: alice'],
    ['192.0.2.11:2222', 'password: spaces & <symbols>!'],
    ['', 'username: unknown']
  ];
  const section = {
    querySelector: () => status,
    querySelectorAll: () => rows.map(([endpoint, value]) => ({
      querySelector: selector => selector === '.credential-endpoint'
        ? { textContent: endpoint, dataset: { verified: String(Boolean(endpoint)) } }
        : { textContent: value }
    }))
  };
  const document = { querySelectorAll: () => [] };
  const navigator = { clipboard: { async writeText(text) { copied = text; } } };
  const button = { closest: () => section, dataset: { copyMode: mode } };
  const copy = new Function('document', 'navigator', script + '\nreturn copyCredentialEntries;')(document, navigator);
  await copy(button);
  if (unknownOnly) {
    assert.equal(copied, undefined);
    assert.equal(status.textContent, 'No verified Host:Port values to copy.');
  } else if (mode === 'targets') {
    assert.equal(copied, '192.0.2.10:3306\n192.0.2.11:2222');
    assert.equal(status.textContent, 'Copied 2 hosts.');
  } else {
    assert.equal(copied, '192.0.2.10:3306\tusername: alice\n192.0.2.10:3306\tusername: root\n192.0.2.11:2222\tpassword: spaces & <symbols>!\nNot identified\tusername: unknown');
    assert.equal(status.textContent, 'Copied 4 entries.');
  }
}

(async () => {
  await test({});
  await test({ table: true });
  await test({ clipboard: 'denied' });
  await test({ table: true, clipboard: 'absent' });
  await test({ clipboard: 'denied', fallback: false });
  await test({ empty: true });
  await testCredentials('entries');
  await testCredentials('targets');
  await testCredentials('targets', true);
  console.log('Copy hosts checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
