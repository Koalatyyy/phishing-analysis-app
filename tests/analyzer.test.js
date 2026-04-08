const assert = require('assert');
const A = require('../analyzer.js');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ok ${name}`); passed++; }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); failed++; }
}

// splitEmail
test('splitEmail: splits on CRLF blank line', () => {
  const { headerText, bodyText } = A.splitEmail('From: a@b.com\r\nSubject: Hi\r\n\r\nBody text');
  assert.ok(headerText.includes('From: a@b.com'));
  assert.strictEqual(bodyText, 'Body text');
});
test('splitEmail: works with LF-only endings', () => {
  const { headerText, bodyText } = A.splitEmail('From: a@b.com\n\nBody');
  assert.ok(headerText.includes('From: a@b.com'));
  assert.strictEqual(bodyText, 'Body');
});
test('splitEmail: no body returns empty string', () => {
  assert.strictEqual(A.splitEmail('From: a@b.com').bodyText, '');
});

// parseHeaders
test('parseHeaders: builds lowercase key map', () => {
  const h = A.parseHeaders('From: test@example.com\r\nSubject: Hello');
  assert.ok(h.has('from') && h.has('subject'));
});
test('parseHeaders: folds continuation lines', () => {
  const raw = 'Received: from mail.a.com\r\n  (mail.a.com [1.2.3.4])\r\nFrom: x@y.com';
  assert.ok(A.parseHeaders(raw).get('received')[0].includes('1.2.3.4'));
});
test('parseHeaders: collects multiple values for repeated headers', () => {
  assert.strictEqual(A.parseHeaders('Received: hop1\r\nReceived: hop2\r\nReceived: hop3').get('received').length, 3);
});
test('parseHeaders: returns empty map for empty string', () => {
  assert.strictEqual(A.parseHeaders('').size, 0);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
