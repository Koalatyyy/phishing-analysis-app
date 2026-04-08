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

// checkMessageId
test('checkMessageId: pass when well-formed', () => {
  assert.strictEqual(A.checkMessageId(A.parseHeaders('Message-ID: <abc@mail.example.com>')).status, 'pass');
});
test('checkMessageId: warn when missing', () => {
  assert.strictEqual(A.checkMessageId(A.parseHeaders('From: x@y.com')).status, 'warn');
});
test('checkMessageId: warn when malformed', () => {
  assert.strictEqual(A.checkMessageId(A.parseHeaders('Message-ID: notvalid')).status, 'warn');
});

// checkReceivedHops
test('checkReceivedHops: pass for 1 hop', () => {
  assert.strictEqual(A.checkReceivedHops(A.parseHeaders('Received: from a by b')).status, 'pass');
});
test('checkReceivedHops: pass for 5 hops', () => {
  const raw = Array(5).fill('Received: from a by b').join('\r\n');
  assert.strictEqual(A.checkReceivedHops(A.parseHeaders(raw)).status, 'pass');
});
test('checkReceivedHops: warn for 6 hops', () => {
  const raw = Array(6).fill('Received: from a by b').join('\r\n');
  assert.strictEqual(A.checkReceivedHops(A.parseHeaders(raw)).status, 'warn');
});
test('checkReceivedHops: fail for 11 hops', () => {
  const raw = Array(11).fill('Received: from a by b').join('\r\n');
  assert.strictEqual(A.checkReceivedHops(A.parseHeaders(raw)).status, 'fail');
});
test('checkReceivedHops: na when no Received headers', () => {
  assert.strictEqual(A.checkReceivedHops(A.parseHeaders('From: x@y.com')).status, 'na');
});

// extractUrls
test('extractUrls: finds plain-text URLs', () => {
  const urls = A.extractUrls('Visit https://evil.com/login and https://good.com');
  assert.strictEqual(urls.length, 2);
  assert.ok(urls.some(u => u.url === 'https://evil.com/login'));
});
test('extractUrls: returns empty for no URLs', () => {
  assert.deepStrictEqual(A.extractUrls('no links here'), []);
});
test('extractUrls: uses parseHtml for anchor hrefs', () => {
  const stub = () => [{ href: 'https://evil.com', text: 'Click here' }];
  const urls = A.extractUrls('<a href="https://evil.com">Click</a>', stub);
  assert.ok(urls.some(u => u.url === 'https://evil.com' && u.anchorText === 'Click here'));
});
test('extractUrls: deduplicates -- anchor enriches plain-text entry', () => {
  const stub = () => [{ href: 'https://evil.com', text: 'link' }];
  const urls = A.extractUrls('https://evil.com <a>', stub);
  assert.strictEqual(urls.filter(u => u.url === 'https://evil.com').length, 1);
  assert.strictEqual(urls.find(u => u.url === 'https://evil.com').anchorText, 'link');
});

// flagUrl
test('flagUrl: IP address hostname', () => {
  assert.ok(A.flagUrl({ url: 'http://192.168.1.1/login', anchorText: null }).some(f => f.includes('IP address')));
});
test('flagUrl: known URL shortener', () => {
  assert.ok(A.flagUrl({ url: 'https://bit.ly/abc123', anchorText: null }).some(f => f.includes('shortener')));
});
test('flagUrl: punycode hostname', () => {
  assert.ok(A.flagUrl({ url: 'https://xn--pypal-4ve.com', anchorText: null }).some(f => f.includes('homograph')));
});
test('flagUrl: excessive subdomains (5 parts)', () => {
  assert.ok(A.flagUrl({ url: 'https://a.b.c.evil.com', anchorText: null }).some(f => f.includes('subdomain')));
});
test('flagUrl: brand lookalike', () => {
  assert.ok(A.flagUrl({ url: 'https://paypal-login.evil.com', anchorText: null }).some(f => f.includes('paypal')));
});
test('flagUrl: anchor text mismatch', () => {
  const flags = A.flagUrl({ url: 'https://evil.com', anchorText: 'https://paypal.com go here' });
  assert.ok(flags.some(f => f.includes('paypal.com')));
});
test('flagUrl: clean URL returns no flags', () => {
  assert.deepStrictEqual(A.flagUrl({ url: 'https://paypal.com/pay', anchorText: null }), []);
});

// calculateVerdict
test('calculateVerdict: 0 score = Likely Legitimate (green)', () => {
  const v = A.calculateVerdict([{ status: 'pass' }, { status: 'na' }]);
  assert.strictEqual(v.label, 'Likely Legitimate');
  assert.strictEqual(v.color, 'green');
});
test('calculateVerdict: 1 warn = Likely Legitimate', () => {
  assert.strictEqual(A.calculateVerdict([{ status: 'warn' }]).label, 'Likely Legitimate');
});
test('calculateVerdict: 2 warns = Suspicious (amber)', () => {
  const v = A.calculateVerdict([{ status: 'warn' }, { status: 'warn' }]);
  assert.strictEqual(v.label, 'Suspicious');
  assert.strictEqual(v.color, 'amber');
});
test('calculateVerdict: 2 fails = Likely Phishing (red)', () => {
  const v = A.calculateVerdict([{ status: 'fail' }, { status: 'fail' }]);
  assert.strictEqual(v.label, 'Likely Phishing');
  assert.strictEqual(v.color, 'red');
});
test('calculateVerdict: counts correctly', () => {
  const v = A.calculateVerdict([{ status: 'fail' }, { status: 'warn' }, { status: 'pass' }]);
  assert.strictEqual(v.failCount, 1);
  assert.strictEqual(v.warnCount, 1);
  assert.strictEqual(v.score, 3);
});

// runAnalysis
test('runAnalysis: 8 checks for paste input', () => {
  const r = A.runAnalysis('From: x@y.com\r\nReceived: from a by b', { isEml: false });
  assert.strictEqual(r.checks.length, 8);
  assert.ok(r.checks.every(c => ['pass','warn','fail','na'].includes(c.status)));
});
test('runAnalysis: verdict has label, color, score', () => {
  const r = A.runAnalysis('From: x@y.com', { isEml: false });
  assert.ok(r.verdict.label);
  assert.ok(['red','amber','green'].includes(r.verdict.color));
});
test('runAnalysis: urlResults null for paste input', () => {
  assert.strictEqual(A.runAnalysis('From: x@y.com', { isEml: false }).urlResults, null);
});
test('runAnalysis: 9 checks and urlResults array for eml with URLs', () => {
  const eml = 'From: x@y.com\r\nReceived: from a by b\r\n\r\nVisit https://bit.ly/abc for info.';
  const r = A.runAnalysis(eml, { isEml: true });
  assert.ok(Array.isArray(r.urlResults));
  assert.strictEqual(r.checks.length, 9);
});
test('runAnalysis: returns error for unrecognizable input', () => {
  assert.ok(A.runAnalysis('hello world', { isEml: false }).error);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
