'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { scan, ScanError } = require('../scanner');

// Load the same samples the website uses. They are only ever read as text.
const win = {};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/samples.js'), 'utf8'), { window: win });
const S = win.SAMPLES;
const ids = (r) => r.findings.map((f) => f.ruleId);

test('vulnerable JavaScript sample triggers the expected rules', () => {
  const r = scan({ code: S['js-vulnerable'].code, filename: 'a.js' });
  for (const id of ['sql-injection', 'xss-sink', 'command-injection', 'path-traversal', 'weak-crypto', 'insecure-random', 'code-eval']) {
    assert.ok(ids(r).includes('codecook.js.' + id), 'missing ' + id);
  }
  assert.ok(ids(r).includes('codecook.secret.hardcoded'));
});

test('secure JavaScript counterpart has no findings', () => {
  const r = scan({ code: S['js-secure'].code, filename: 'b.js' });
  assert.deepEqual(r.findings.map((f) => f.ruleId + ':' + f.line), []);
});

test('vulnerable Python sample triggers the expected rules', () => {
  const r = scan({ code: S['py-vulnerable'].code, filename: 'a.py' });
  for (const id of ['sql-injection', 'xss-sink', 'command-injection', 'insecure-deserialization', 'tls-verification-disabled', 'path-traversal', 'weak-crypto', 'insecure-random', 'debug-enabled']) {
    assert.ok(ids(r).includes('codecook.py.' + id), 'missing ' + id);
  }
  assert.ok(ids(r).includes('codecook.secret.hardcoded'));
});

test('secure Python counterpart has no findings', () => {
  const r = scan({ code: S['py-secure'].code, filename: 'b.py' });
  assert.deepEqual(r.findings.map((f) => f.ruleId + ':' + f.line), []);
});

test('findings carry severity, evidence, line and fix guidance; results are repeatable', () => {
  const a = scan({ code: S['py-vulnerable'].code, filename: 'a.py' });
  const b = scan({ code: S['py-vulnerable'].code, filename: 'a.py' });
  assert.deepEqual(a.findings, b.findings);
  for (const f of a.findings) {
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
    assert.ok(f.evidence && f.line > 0 && f.fix.secureExample && f.explanation.howToFix && f.ruleId);
  }
});

test('secrets are masked in evidence and snippets', () => {
  const r = scan({ code: 'const password = "SuperSecretValue123";\n', filename: 'x.js' });
  const f = r.findings[0];
  assert.ok(!f.evidence.includes('SuperSecretValue123'));
  assert.ok(!JSON.stringify(f.snippet).includes('SuperSecretValue123'));
});

test('placeholders and environment lookups are not flagged as secrets', () => {
  const r = scan({ code: 'const password = "changeme-placeholder";\nconst token = process.env.TOKEN_VALUE_X;\n', filename: 'x.js' });
  assert.equal(r.findings.length, 0);
});

test('submitted code is never executed', () => {
  globalThis.__codecook_ran = false;
  scan({ code: 'globalThis.__codecook_ran = true;\neval("globalThis.__codecook_ran = true");\n', filename: 'x.js' });
  assert.equal(globalThis.__codecook_ran, false);
});

test('invalid input is rejected safely', () => {
  const bad = (input, status) => assert.throws(() => scan(input), (e) => e instanceof ScanError && e.status === status);
  bad({ code: 123 }, 400);
  bad({ code: '   \n' }, 400);
  bad({ code: 'a\0b', filename: 'x.js' }, 415);
  bad({ code: 'x', filename: 'photo.png' }, 415);
  bad({ code: 'x'.repeat(512 * 1024 + 1), filename: 'x.js' }, 413);
  bad({ code: 'hello world', language: 'auto' }, 422);
});

test('language detection works for pasted code without a file name', () => {
  assert.equal(scan({ code: 'def f(x):\n    return x\n' }).language, 'python');
  assert.equal(scan({ code: 'const a = () => 1;\nconsole.log(a());\n' }).language, 'javascript');
});

test('very long lines do not hang the scanner', () => {
  const t = Date.now();
  scan({ code: 'SELECT ' + 'a '.repeat(100000) + '+ x', filename: 'x.js' });
  assert.ok(Date.now() - t < 4000);
});
