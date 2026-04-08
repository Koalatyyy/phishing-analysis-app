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

// extractDomain
test('extractDomain: angle-bracket format', () => {
  assert.strictEqual(A.extractDomain('"PayPal" <security@paypal.com>'), 'paypal.com');
});
test('extractDomain: bare email', () => {
  assert.strictEqual(A.extractDomain('user@example.com'), 'example.com');
});
test('extractDomain: returns null for non-email', () => {
  assert.strictEqual(A.extractDomain('not an email'), null);
});

// checkSPF
test('checkSPF: pass', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: pass (permitted)')).status, 'pass');
});
test('checkSPF: warn on softfail', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: softfail')).status, 'warn');
});
test('checkSPF: warn on neutral', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: neutral')).status, 'warn');
});
test('checkSPF: fail on fail', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: fail (not permitted)')).status, 'fail');
});
test('checkSPF: fail on permerror', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: permerror')).status, 'fail');
});
test('checkSPF: fail on temperror', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('Received-SPF: temperror')).status, 'fail');
});
test('checkSPF: na when missing', () => {
  assert.strictEqual(A.checkSPF(A.parseHeaders('From: x@y.com')).status, 'na');
});

// checkDKIM
test('checkDKIM: pass from authentication-results', () => {
  assert.strictEqual(A.checkDKIM(A.parseHeaders('Authentication-Results: mx; dkim=pass')).status, 'pass');
});
test('checkDKIM: fail from authentication-results', () => {
  assert.strictEqual(A.checkDKIM(A.parseHeaders('Authentication-Results: mx; dkim=fail')).status, 'fail');
});
test('checkDKIM: pass from DKIM-Signature presence', () => {
  assert.strictEqual(A.checkDKIM(A.parseHeaders('DKIM-Signature: v=1; a=rsa-sha256')).status, 'pass');
});
test('checkDKIM: na when neither present', () => {
  assert.strictEqual(A.checkDKIM(A.parseHeaders('From: x@y.com')).status, 'na');
});

// checkDMARC
test('checkDMARC: pass', () => {
  assert.strictEqual(A.checkDMARC(A.parseHeaders('Authentication-Results: mx; dmarc=pass')).status, 'pass');
});
test('checkDMARC: fail', () => {
  assert.strictEqual(A.checkDMARC(A.parseHeaders('Authentication-Results: mx; dmarc=fail')).status, 'fail');
});
test('checkDMARC: na when missing', () => {
  assert.strictEqual(A.checkDMARC(A.parseHeaders('From: x@y.com')).status, 'na');
});

// checkReplyTo
test('checkReplyTo: pass when absent', () => {
  assert.strictEqual(A.checkReplyTo(A.parseHeaders('From: a@paypal.com')).status, 'pass');
});
test('checkReplyTo: pass when domains match', () => {
  assert.strictEqual(A.checkReplyTo(A.parseHeaders('From: a@paypal.com\r\nReply-To: b@paypal.com')).status, 'pass');
});
test('checkReplyTo: warn when domains differ', () => {
  assert.strictEqual(A.checkReplyTo(A.parseHeaders('From: a@paypal.com\r\nReply-To: b@evil.com')).status, 'warn');
});

// checkReturnPath
test('checkReturnPath: na when absent', () => {
  assert.strictEqual(A.checkReturnPath(A.parseHeaders('From: a@paypal.com')).status, 'na');
});
test('checkReturnPath: pass when domains match', () => {
  assert.strictEqual(A.checkReturnPath(A.parseHeaders('From: a@paypal.com\r\nReturn-Path: <bounce@paypal.com>')).status, 'pass');
});
test('checkReturnPath: warn when domains differ', () => {
  assert.strictEqual(A.checkReturnPath(A.parseHeaders('From: a@paypal.com\r\nReturn-Path: <bounce@evil.com>')).status, 'warn');
});

// checkDisplayName
test('checkDisplayName: pass when no display name', () => {
  assert.strictEqual(A.checkDisplayName(A.parseHeaders('From: user@paypal.com')).status, 'pass');
});
test('checkDisplayName: pass when name has no domain string', () => {
  assert.strictEqual(A.checkDisplayName(A.parseHeaders('From: "PayPal Security" <user@paypal.com>')).status, 'pass');
});
test('checkDisplayName: warn when name contains different domain', () => {
  assert.strictEqual(A.checkDisplayName(A.parseHeaders('From: "support@paypal.com" <user@evil.com>')).status, 'warn');
});
test('checkDisplayName: pass when name domain matches From domain', () => {
  assert.strictEqual(A.checkDisplayName(A.parseHeaders('From: "paypal.com Support" <user@paypal.com>')).status, 'pass');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
