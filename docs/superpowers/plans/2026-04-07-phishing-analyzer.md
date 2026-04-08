# Phishing Header Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone browser-based tool that accepts dropped .eml files or pasted email headers and analyzes them for phishing indicators, outputting a color-coded verdict and per-check breakdown.

**Architecture:** Three files, no build step -- `index.html` (shell + DOM events + rendering), `style.css` (dark GitHub-inspired theme), `analyzer.js` (all pure analysis functions). A Node.js test file at `tests/analyzer.test.js` covers the pure functions. `analyzer.js` exports via `module.exports` in Node.js and attaches to `window.Analyzer` in the browser.

**Tech Stack:** Vanilla HTML/CSS/JS. Inter + JetBrains Mono via Google Fonts CDN. Node.js built-in `assert` for tests. No npm, no build step.

---

## File Map

| File | Responsibility |
|---|---|
| `index.html` | Page shell, intro section, input area, results container, drag-and-drop/paste event handlers, DOM rendering functions |
| `style.css` | Dark security-tool theme, all layout and component styles |
| `analyzer.js` | `splitEmail`, `parseHeaders`, `extractDomain`, 9 check functions, `calculateVerdict`, `runAnalysis`, `extractUrls`, `flagUrl` |
| `tests/analyzer.test.js` | Unit tests for all `analyzer.js` functions, run with `node tests/analyzer.test.js` |

---

## Task 1: Scaffold

**Files:**
- Create: `index.html`
- Create: `style.css`
- Create: `analyzer.js`
- Create: `tests/analyzer.test.js`

- [ ] **Step 1: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing Header Analyzer</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div id="app"><p>Loading...</p></div>
  <script src="analyzer.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create style.css**

```css
/* placeholder */
body { font-family: sans-serif; background: #0d1117; color: #c9d1d9; }
```

- [ ] **Step 3: Create analyzer.js**

```js
(function (exports) {

  function parseHeaders(text) {
    return new Map();
  }

  exports.parseHeaders = parseHeaders;

})(typeof module !== 'undefined' ? module.exports : (window.Analyzer = {}));
```

- [ ] **Step 4: Create tests/analyzer.test.js**

```js
const assert = require('assert');
const A = require('../analyzer.js');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ok ${name}`); passed++; }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); failed++; }
}

test('placeholder', () => { assert.ok(true); });

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
```

- [ ] **Step 5: Run**

```
node tests/analyzer.test.js
```

Expected: `1 passed, 0 failed`

- [ ] **Step 6: Commit**

```bash
git add index.html style.css analyzer.js tests/analyzer.test.js
git commit -m "Feat: scaffold phishing analyzer"
```

---

## Task 2: CSS Dark Theme

**Files:**
- Modify: `style.css`
- Modify: `index.html` (temporary test markup)

- [ ] **Step 1: Replace style.css**

```css
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:          #0d1117;
  --bg-surface:  #161b22;
  --bg-surface-2:#21262d;
  --border:      #30363d;
  --text:        #c9d1d9;
  --text-muted:  #8b949e;
  --blue:        #58a6ff;
  --green:       #3fb950;
  --amber:       #d29922;
  --red:         #f85149;
  --green-dim:   #3fb95020;
  --amber-dim:   #d2992220;
  --red-dim:     #f8514920;
  --font-ui:     'Inter', system-ui, sans-serif;
  --font-mono:   'JetBrains Mono', 'Fira Code', monospace;
}

body {
  background: var(--bg); color: var(--text);
  font-family: var(--font-ui); font-size: 15px; line-height: 1.5; min-height: 100vh;
}

#app { max-width: 760px; margin: 0 auto; padding: 40px 24px 80px; }

.page-header { margin-bottom: 32px; }
.page-header h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.01em; }
.page-header .tagline { font-size: 0.875rem; color: var(--text-muted); margin-top: 4px; }

.collapsible { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
.collapsible summary {
  padding: 12px 16px; cursor: pointer; font-size: 0.875rem; font-weight: 500;
  color: var(--text-muted); background: var(--bg-surface); list-style: none;
  user-select: none; display: flex; align-items: center; gap: 8px;
}
.collapsible summary::before { content: '\25B6'; font-size: 0.65rem; transition: transform 0.15s; }
.collapsible[open] summary::before { transform: rotate(90deg); }
.collapsible summary:hover { color: var(--text); }
.collapsible-body {
  padding: 16px; border-top: 1px solid var(--border);
  font-size: 0.875rem; color: var(--text-muted); background: var(--bg);
}
.collapsible-body h4 {
  font-size: 0.8rem; font-weight: 600; color: var(--text);
  text-transform: uppercase; letter-spacing: 0.06em; margin: 16px 0 6px;
}
.collapsible-body h4:first-child { margin-top: 0; }
.collapsible-body ol, .collapsible-body ul { padding-left: 20px; }
.collapsible-body li { margin-bottom: 4px; }
.collapsible-body code {
  font-family: var(--font-mono); font-size: 0.8rem;
  background: var(--bg-surface); padding: 1px 5px; border-radius: 3px; color: var(--blue);
}

.drop-zone {
  border: 2px dashed var(--border); border-radius: 10px; padding: 28px 24px;
  text-align: center; background: var(--bg-surface);
  transition: border-color 0.15s, background 0.15s; cursor: pointer; margin-bottom: 12px;
}
.drop-zone.drag-over { border-color: var(--blue); background: #1c2a3a; }
.drop-zone.has-file  { border-color: var(--green); border-style: solid; }
.drop-zone .drop-icon { font-size: 2rem; margin-bottom: 8px; line-height: 1; }
.drop-zone .drop-primary { font-size: 0.9rem; font-weight: 500; }
.drop-zone .drop-secondary { font-size: 0.8rem; color: var(--text-muted); margin-top: 4px; }
.drop-zone .drop-filename { font-family: var(--font-mono); font-size: 0.8rem; color: var(--green); margin-top: 6px; }

.or-divider {
  text-align: center; font-size: 0.8rem; color: var(--text-muted); margin: 12px 0; position: relative;
}
.or-divider::before, .or-divider::after {
  content: ''; position: absolute; top: 50%; width: 44%; height: 1px; background: var(--border);
}
.or-divider::before { left: 0; }
.or-divider::after  { right: 0; }

.paste-area {
  width: 100%; background: var(--bg-surface); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px;
  font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.6;
  resize: vertical; min-height: 100px; transition: border-color 0.15s;
}
.paste-area:focus { outline: none; border-color: var(--blue); }
.paste-area::placeholder { color: var(--text-muted); opacity: 0.6; }

.btn-analyze {
  margin-top: 14px; width: 100%; padding: 10px; background: #1f6feb;
  color: #fff; border: none; border-radius: 8px; font-family: var(--font-ui);
  font-size: 0.9rem; font-weight: 600; cursor: pointer; letter-spacing: 0.01em;
  transition: background 0.15s;
}
.btn-analyze:hover  { background: #388bfd; }
.btn-analyze:active { background: #1158c7; }

.inline-error { font-size: 0.825rem; color: var(--red); margin-top: 8px; display: none; }
.inline-error.visible { display: block; }

#results { display: none; margin-top: 32px; }
#results.visible { display: block; }

.verdict-banner {
  border-radius: 10px; padding: 16px 20px; display: flex; align-items: center;
  gap: 14px; margin-bottom: 20px; border: 1px solid;
}
.verdict-banner.red   { background: #f8514910; border-color: #f8514933; }
.verdict-banner.amber { background: #d2992210; border-color: #d2992233; }
.verdict-banner.green { background: #3fb95010; border-color: #3fb95033; }
.verdict-icon  { font-size: 1.6rem; line-height: 1; flex-shrink: 0; }
.verdict-label { font-size: 1.05rem; font-weight: 700; }
.verdict-banner.red   .verdict-label { color: var(--red); }
.verdict-banner.amber .verdict-label { color: var(--amber); }
.verdict-banner.green .verdict-label { color: var(--green); }
.verdict-sub   { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }
.verdict-badge {
  margin-left: auto; font-size: 0.68rem; font-weight: 700; padding: 3px 9px;
  border-radius: 4px; letter-spacing: 0.06em; white-space: nowrap;
}
.verdict-banner.red   .verdict-badge { background: var(--red);   color: #fff; }
.verdict-banner.amber .verdict-badge { background: var(--amber); color: #0d1117; }
.verdict-banner.green .verdict-badge { background: var(--green); color: #0d1117; }

.section-label {
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-muted); margin-bottom: 8px;
}

.checks-list { display: flex; flex-direction: column; gap: 6px; margin-bottom: 24px; }
.check-row {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  background: var(--bg-surface); border-radius: 7px;
  border: 1px solid var(--bg-surface-2); border-left: 3px solid;
}
.check-row.pass  { border-left-color: var(--green); }
.check-row.warn  { border-left-color: var(--amber); }
.check-row.fail  { border-left-color: var(--red); }
.check-row.na    { border-left-color: #444; }
.check-tag {
  font-size: 0.68rem; font-weight: 700; padding: 2px 7px; border-radius: 3px;
  min-width: 36px; text-align: center; letter-spacing: 0.04em;
}
.check-row.pass .check-tag { background: var(--green-dim); color: var(--green); }
.check-row.warn .check-tag { background: var(--amber-dim); color: var(--amber); }
.check-row.fail .check-tag { background: var(--red-dim);   color: var(--red); }
.check-row.na   .check-tag { background: #2a2a2a; color: #666; }
.check-name   { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text); min-width: 160px; }
.check-detail { font-size: 0.78rem; color: var(--text-muted); flex: 1; }

.url-section { margin-bottom: 24px; }
.url-item {
  padding: 10px 14px; background: var(--bg-surface); border-radius: 7px;
  border: 1px solid var(--bg-surface-2); margin-bottom: 6px; font-size: 0.8rem;
}
.url-text  { font-family: var(--font-mono); color: var(--blue); word-break: break-all; margin-bottom: 4px; }
.url-flags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.url-flag  { font-size: 0.68rem; padding: 2px 7px; border-radius: 3px; background: var(--red-dim); color: var(--red); }
.url-clean { font-size: 0.8rem; color: var(--text-muted); font-style: italic; padding: 10px 14px; }
```

- [ ] **Step 2: Add temporary test markup to index.html to verify styles visually**

Replace `<div id="app"><p>Loading...</p></div>` with:

```html
<div id="app">
  <header class="page-header">
    <h1>Phishing Header Analyzer</h1>
    <p class="tagline">Paste or drop an email to check for phishing indicators.</p>
  </header>
  <div class="drop-zone">
    <div class="drop-icon">&#128231;</div>
    <div class="drop-primary">Drop a .eml file here</div>
    <div class="drop-secondary">Drag from your file manager</div>
  </div>
  <div class="or-divider">or</div>
  <textarea class="paste-area" placeholder="Paste headers here..."></textarea>
  <button class="btn-analyze">Analyze Headers</button>
  <div id="results" class="visible" style="margin-top:32px">
    <div class="verdict-banner red">
      <div class="verdict-icon">&#9888;</div>
      <div>
        <div class="verdict-label">Likely Phishing</div>
        <div class="verdict-sub">4 checks failed</div>
      </div>
      <span class="verdict-badge">HIGH RISK</span>
    </div>
    <div class="section-label">Check Breakdown</div>
    <div class="checks-list">
      <div class="check-row fail"><span class="check-tag">FAIL</span><span class="check-name">SPF</span><span class="check-detail">Received-SPF: fail</span></div>
      <div class="check-row warn"><span class="check-tag">WARN</span><span class="check-name">Reply-To Mismatch</span><span class="check-detail">domains differ</span></div>
      <div class="check-row pass"><span class="check-tag">PASS</span><span class="check-name">DKIM</span><span class="check-detail">dkim=pass</span></div>
      <div class="check-row na"><span class="check-tag">N/A</span><span class="check-name">DMARC</span><span class="check-detail">not found</span></div>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Open index.html in browser, verify dark theme renders correctly**

Expected: dark background, colored left borders, correct tag colors.

- [ ] **Step 4: Commit**

```bash
git add style.css index.html
git commit -m "Feat: dark security-tool CSS theme"
```

---

## Task 3: splitEmail() and parseHeaders()

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Replace tests/analyzer.test.js with**

```js
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
```

- [ ] **Step 2: Run -- expect failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Replace the IIFE body in analyzer.js**

```js
(function (exports) {

  function splitEmail(raw) {
    const sep = raw.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
    const idx = raw.indexOf(sep);
    if (idx === -1) return { headerText: raw, bodyText: '' };
    return { headerText: raw.slice(0, idx), bodyText: raw.slice(idx + sep.length) };
  }

  function parseHeaders(text) {
    const map = new Map();
    if (!text.trim()) return map;
    const folded = text.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ');
    for (const line of folded.split('\n')) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (!name) continue;
      if (!map.has(name)) map.set(name, []);
      map.get(name).push(value);
    }
    return map;
  }

  exports.splitEmail = splitEmail;
  exports.parseHeaders = parseHeaders;

})(typeof module !== 'undefined' ? module.exports : (window.Analyzer = {}));
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement splitEmail and parseHeaders"
```

---

## Task 4: extractDomain() and Auth Checks (SPF, DKIM, DMARC)

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Append to tests/analyzer.test.js before the final console.log**

```js
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
```

- [ ] **Step 2: Run -- expect new failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Add to analyzer.js inside the IIFE, before the exports**

```js
  function extractDomain(str) {
    const angleMatch = str.match(/<[^>]*@([^>]+)>/);
    if (angleMatch) return angleMatch[1].toLowerCase().trim();
    const bareMatch = str.match(/\S+@([^\s>]+)/);
    if (bareMatch) return bareMatch[1].toLowerCase().trim();
    return null;
  }

  function checkSPF(headers) {
    const vals = headers.get('received-spf');
    if (!vals || !vals.length) return { status: 'na', detail: 'Received-SPF header not found' };
    const keyword = vals[0].trim().toLowerCase().split(/[\s(]/)[0];
    if (keyword === 'pass') return { status: 'pass', detail: 'Received-SPF: pass' };
    if (keyword === 'softfail' || keyword === 'neutral') return { status: 'warn', detail: `Received-SPF: ${keyword}` };
    if (['fail','permerror','temperror'].includes(keyword)) return { status: 'fail', detail: `Received-SPF: ${keyword}` };
    return { status: 'na', detail: `Received-SPF: ${keyword} (unrecognized)` };
  }

  function checkDKIM(headers) {
    const auth = (headers.get('authentication-results') || []).join(' ').toLowerCase();
    if (auth.includes('dkim=pass')) return { status: 'pass', detail: 'DKIM signature verified (dkim=pass)' };
    if (auth.includes('dkim=fail')) return { status: 'fail', detail: 'DKIM signature failed (dkim=fail)' };
    if ((headers.get('dkim-signature') || []).length) return { status: 'pass', detail: 'DKIM-Signature header present' };
    return { status: 'na', detail: 'No DKIM information found' };
  }

  function checkDMARC(headers) {
    const auth = (headers.get('authentication-results') || []).join(' ').toLowerCase();
    if (auth.includes('dmarc=pass')) return { status: 'pass', detail: 'DMARC policy passed' };
    if (auth.includes('dmarc=fail')) return { status: 'fail', detail: 'DMARC policy failed' };
    return { status: 'na', detail: 'DMARC result not found in Authentication-Results' };
  }
```

Add to exports:

```js
  exports.extractDomain = extractDomain;
  exports.checkSPF = checkSPF;
  exports.checkDKIM = checkDKIM;
  exports.checkDMARC = checkDMARC;
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement SPF, DKIM, DMARC checks"
```

---

## Task 5: From-Header Checks (Reply-To, Return-Path, Display Name)

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Append to tests before final console.log**

```js
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
```

- [ ] **Step 2: Run -- expect new failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Add three functions to analyzer.js**

```js
  function checkReplyTo(headers) {
    const from = (headers.get('from') || [''])[0];
    const replyTo = (headers.get('reply-to') || [])[0];
    if (!replyTo) return { status: 'pass', detail: 'No Reply-To header present' };
    const fromDomain = extractDomain(from);
    const replyDomain = extractDomain(replyTo);
    if (!fromDomain || !replyDomain) return { status: 'na', detail: 'Could not parse domains from From/Reply-To' };
    if (fromDomain === replyDomain) return { status: 'pass', detail: `Reply-To domain matches From domain (${fromDomain})` };
    return { status: 'warn', detail: `Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})` };
  }

  function checkReturnPath(headers) {
    const from = (headers.get('from') || [''])[0];
    const rp = (headers.get('return-path') || [])[0];
    if (!rp) return { status: 'na', detail: 'Return-Path header not found' };
    const fromDomain = extractDomain(from);
    const rpDomain = extractDomain(rp);
    if (!fromDomain || !rpDomain) return { status: 'na', detail: 'Could not parse domains from From/Return-Path' };
    if (fromDomain === rpDomain) return { status: 'pass', detail: `Return-Path domain matches From domain (${fromDomain})` };
    return { status: 'warn', detail: `Return-Path domain (${rpDomain}) differs from From domain (${fromDomain})` };
  }

  function checkDisplayName(headers) {
    const from = (headers.get('from') || [''])[0];
    const displayMatch = from.match(/^"?([^"<@]+)"?\s*</);
    if (!displayMatch) return { status: 'pass', detail: 'No display name to inspect' };
    const displayName = displayMatch[1].trim().toLowerCase();
    const actualDomain = extractDomain(from);
    const domainInName = displayName.match(/\b([a-z0-9-]+\.[a-z]{2,})\b/);
    if (!domainInName) return { status: 'pass', detail: 'Display name contains no domain-like string' };
    const namedDomain = domainInName[1];
    if (!actualDomain || namedDomain === actualDomain) return { status: 'pass', detail: 'Display name domain matches sending domain' };
    return { status: 'warn', detail: `Display name references "${namedDomain}" but email is from ${actualDomain}` };
  }
```

Add to exports:

```js
  exports.checkReplyTo = checkReplyTo;
  exports.checkReturnPath = checkReturnPath;
  exports.checkDisplayName = checkDisplayName;
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement Reply-To, Return-Path, display name checks"
```

---

## Task 6: Message-ID and Received Hops

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Append tests**

```js
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
```

- [ ] **Step 2: Run -- expect new failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Add to analyzer.js**

```js
  function checkMessageId(headers) {
    const val = (headers.get('message-id') || [])[0];
    if (!val) return { status: 'warn', detail: 'Message-ID header is missing' };
    if (val.includes('@')) return { status: 'pass', detail: 'Message-ID present and well-formed' };
    return { status: 'warn', detail: 'Message-ID present but malformed (no @ found)' };
  }

  function checkReceivedHops(headers) {
    const received = headers.get('received') || [];
    const count = received.length;
    if (count === 0)  return { status: 'na',   detail: 'No Received headers found' };
    if (count <= 5)   return { status: 'pass',  detail: `${count} hop${count === 1 ? '' : 's'} (normal)` };
    if (count <= 10)  return { status: 'warn',  detail: `${count} hops (elevated)` };
    return { status: 'fail', detail: `${count} hops (excessive -- strongly suspicious)` };
  }
```

Add to exports:

```js
  exports.checkMessageId = checkMessageId;
  exports.checkReceivedHops = checkReceivedHops;
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement Message-ID and Received hops checks"
```

---

## Task 7: URL Extraction and Flagging

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Append tests**

```js
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
```

- [ ] **Step 2: Run -- expect new failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Add extractUrls() and flagUrl() to analyzer.js**

```js
  const URL_SHORTENERS = new Set([
    'bit.ly','tinyurl.com','t.co','ow.ly','buff.ly','is.gd','ift.tt',
    'adf.ly','j.mp','tr.im','wp.me','short.io','rb.gy','cutt.ly',
  ]);

  const BRAND_NAMES = [
    'paypal','microsoft','amazon','apple','google','facebook',
    'netflix','instagram','twitter','linkedin','dropbox','docusign',
    'chase','wellsfargo','bankofamerica','usps','fedex','ups',
  ];

  function extractUrls(text, parseHtml) {
    const urlMap = new Map();
    for (const m of text.matchAll(/https?:\/\/[^\s<>"')\]]+/gi)) {
      const url = m[0].replace(/[.,;:!?]+$/, '');
      if (!urlMap.has(url)) urlMap.set(url, { url, anchorText: null });
    }
    if (parseHtml) {
      for (const { href, text: anchorText } of parseHtml(text)) {
        if (!/^https?:\/\//i.test(href)) continue;
        if (urlMap.has(href)) urlMap.get(href).anchorText = anchorText;
        else urlMap.set(href, { url: href, anchorText });
      }
    }
    return Array.from(urlMap.values());
  }

  function flagUrl({ url, anchorText }) {
    const flags = [];
    let hostname;
    try { hostname = new URL(url).hostname.toLowerCase(); }
    catch { return ['Malformed URL']; }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
      flags.push('IP address hostname (no domain)');

    if (URL_SHORTENERS.has(hostname))
      flags.push('Known URL shortener');

    if (hostname.startsWith('xn--') || hostname.split('.').some(l => l.startsWith('xn--')))
      flags.push('Internationalized domain (possible homograph attack)');

    if (hostname.split('.').length > 4)
      flags.push('Excessive subdomains');

    for (const brand of BRAND_NAMES) {
      if (hostname.includes(brand) && hostname !== `${brand}.com` && !hostname.endsWith(`.${brand}.com`)) {
        flags.push(`Possible ${brand} lookalike domain`);
        break;
      }
    }

    if (anchorText) {
      const anchorHostMatch = anchorText.match(/https?:\/\/([^\s/]+)/i);
      if (anchorHostMatch && anchorHostMatch[1].toLowerCase() !== hostname)
        flags.push(`Anchor text shows "${anchorHostMatch[1].toLowerCase()}" but links to "${hostname}"`);
    }

    return flags;
  }
```

Add to exports:

```js
  exports.extractUrls = extractUrls;
  exports.flagUrl = flagUrl;
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement URL extraction and flagging"
```

---

## Task 8: calculateVerdict() and runAnalysis()

**Files:**
- Modify: `analyzer.js`
- Modify: `tests/analyzer.test.js`

- [ ] **Step 1: Append tests**

```js
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
```

- [ ] **Step 2: Run -- expect new failures**

```
node tests/analyzer.test.js
```

- [ ] **Step 3: Add calculateVerdict() and runAnalysis() to analyzer.js**

```js
  function calculateVerdict(checkResults) {
    let score = 0, failCount = 0, warnCount = 0;
    for (const c of checkResults) {
      if (c.status === 'fail') { score += 2; failCount++; }
      else if (c.status === 'warn') { score += 1; warnCount++; }
    }
    let label, color;
    if (score >= 4)      { label = 'Likely Phishing';  color = 'red'; }
    else if (score >= 2) { label = 'Suspicious';        color = 'amber'; }
    else                 { label = 'Likely Legitimate'; color = 'green'; }
    return { label, color, score, failCount, warnCount };
  }

  function runAnalysis(rawInput, { isEml = false, parseHtml = null } = {}) {
    const { headerText, bodyText } = isEml
      ? splitEmail(rawInput)
      : { headerText: rawInput, bodyText: '' };
    const headers = parseHeaders(headerText);
    if (headers.size === 0) return { error: 'Could not find email headers in this input.' };

    const checks = [
      { id: 'spf',          name: 'SPF',                   ...checkSPF(headers) },
      { id: 'dkim',         name: 'DKIM',                  ...checkDKIM(headers) },
      { id: 'dmarc',        name: 'DMARC',                 ...checkDMARC(headers) },
      { id: 'reply-to',     name: 'Reply-To Mismatch',     ...checkReplyTo(headers) },
      { id: 'return-path',  name: 'Return-Path Mismatch',  ...checkReturnPath(headers) },
      { id: 'display-name', name: 'Display Name Spoofing', ...checkDisplayName(headers) },
      { id: 'message-id',   name: 'Message-ID',            ...checkMessageId(headers) },
      { id: 'hops',         name: 'Received Hops',         ...checkReceivedHops(headers) },
    ];

    let urlResults = null;
    if (isEml) {
      urlResults = extractUrls(bodyText, parseHtml).map(u => ({ ...u, flags: flagUrl(u) }));
      const flaggedCount = urlResults.filter(u => u.flags.length > 0).length;
      checks.push({
        id: 'urls', name: 'Suspicious URLs',
        status: flaggedCount === 0 ? 'pass' : flaggedCount <= 2 ? 'warn' : 'fail',
        detail: flaggedCount === 0
          ? 'No suspicious URLs found'
          : `${flaggedCount} URL${flaggedCount > 1 ? 's' : ''} flagged`,
      });
    }

    return { checks, verdict: calculateVerdict(checks), urlResults };
  }
```

Add to exports:

```js
  exports.calculateVerdict = calculateVerdict;
  exports.runAnalysis = runAnalysis;
```

- [ ] **Step 4: Run -- expect all pass**

```
node tests/analyzer.test.js
```

- [ ] **Step 5: Commit**

```bash
git add analyzer.js tests/analyzer.test.js
git commit -m "Feat: implement calculateVerdict and runAnalysis"
```

---

## Task 9: Full Page HTML (Intro + Input)

**Files:**
- Modify: `index.html`

- [ ] **Step 1: Replace the entire `<div id="app">` block**

```html
<div id="app">

  <header class="page-header">
    <h1>Phishing Header Analyzer</h1>
    <p class="tagline">Paste raw email headers or drop a .eml file to check for phishing indicators. All analysis runs locally -- nothing is uploaded.</p>
  </header>

  <details class="collapsible">
    <summary>How to get your email headers</summary>
    <div class="collapsible-body">
      <h4>Gmail</h4>
      <ol>
        <li>Open the email.</li>
        <li>Click the three-dot menu (&#8942;) in the top-right of the message.</li>
        <li>Select <strong>Show original</strong>.</li>
        <li>Copy the full text, or click <strong>Download Original</strong> to save as a .eml file.</li>
      </ol>
      <h4>Outlook (Web)</h4>
      <ol>
        <li>Open the email.</li>
        <li>Click the three-dot menu &#8594; <strong>View</strong> &#8594; <strong>View message source</strong>.</li>
        <li>Copy all the text, or save via your browser's Save As.</li>
      </ol>
      <h4>Apple Mail</h4>
      <ol>
        <li>Select the email in your inbox.</li>
        <li>Go to <strong>View &#8594; Message &#8594; Raw Source</strong> (or press <code>&#8997;&#8984;U</code>).</li>
        <li>Copy the content, or drag the email to your Desktop to save as a .eml file.</li>
      </ol>
    </div>
  </details>

  <details class="collapsible">
    <summary>What this tool checks</summary>
    <div class="collapsible-body">
      <ul>
        <li><strong>SPF</strong> -- whether the sending server is authorized to send for the From domain</li>
        <li><strong>DKIM</strong> -- whether the email carries a valid cryptographic signature</li>
        <li><strong>DMARC</strong> -- whether the email passed the domain owner's published policy</li>
        <li><strong>Reply-To mismatch</strong> -- whether replies would go to a different domain than the sender</li>
        <li><strong>Return-Path mismatch</strong> -- whether bounces would go to a different domain</li>
        <li><strong>Display name spoofing</strong> -- whether the visible sender name references a domain that differs from the actual sending address</li>
        <li><strong>Message-ID</strong> -- whether the message carries a well-formed unique identifier</li>
        <li><strong>Received hops</strong> -- whether the email passed through an unusual number of mail servers</li>
        <li><strong>Suspicious URLs</strong> (.eml files only) -- whether body links use IP addresses, URL shorteners, or lookalike domains</li>
      </ul>
    </div>
  </details>

  <div id="input-section" style="margin-top:24px">
    <div id="drop-zone" class="drop-zone" role="button" tabindex="0" aria-label="Drop zone for .eml files">
      <div class="drop-icon">&#128231;</div>
      <div class="drop-primary">Drop a .eml file here</div>
      <div class="drop-secondary">Drag from your file manager or email client</div>
      <div id="drop-filename" class="drop-filename" style="display:none"></div>
    </div>
    <div id="drop-error" class="inline-error"></div>
    <div class="or-divider">or</div>
    <textarea id="paste-area" class="paste-area" rows="6"
      placeholder="Paste raw email headers here&#10;&#10;Received: from mail.example.com (mail.example.com [203.0.113.1])&#10;From: &quot;PayPal&quot; &lt;security@paypal.com&gt;&#10;Reply-To: harvest@evil.com&#10;..."></textarea>
    <div id="paste-error" class="inline-error"></div>
    <button id="btn-analyze" class="btn-analyze">Analyze Headers</button>
  </div>

  <div id="results"></div>

</div>
```

- [ ] **Step 2: Open index.html in browser, verify layout and collapsibles**

Expected: both `<details>` collapse/expand correctly, drop zone and textarea visible, Analyze button present.

- [ ] **Step 3: Commit**

```bash
git add index.html
git commit -m "Feat: add intro section, how-to guide, and input area HTML"
```

---

## Task 10: Event Wiring (Drag-and-Drop, Paste, Analyze)

**Files:**
- Modify: `index.html` (add `<script>` before `</body>`)

- [ ] **Step 1: Add this script block to index.html before `</body>`**

```html
<script>
  const dropZone     = document.getElementById('drop-zone');
  const dropFilename = document.getElementById('drop-filename');
  const dropError    = document.getElementById('drop-error');
  const pasteArea    = document.getElementById('paste-area');
  const pasteError   = document.getElementById('paste-error');
  const btnAnalyze   = document.getElementById('btn-analyze');

  let droppedEmlText = null;

  function showError(el, msg) { el.textContent = msg; el.classList.add('visible'); }
  function clearError(el)     { el.textContent = '';  el.classList.remove('visible'); }

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    clearError(dropError);
    droppedEmlText = null;
    dropZone.classList.remove('has-file');
    dropFilename.style.display = 'none';

    const file = e.dataTransfer.files[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.eml')) {
      showError(dropError, 'Only .eml files are supported. Use the paste area for raw headers.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      droppedEmlText = ev.target.result;
      dropZone.classList.add('has-file');
      dropFilename.textContent = file.name;
      dropFilename.style.display = 'block';
    };
    reader.readAsText(file);
  });

  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') dropZone.click();
  });

  btnAnalyze.addEventListener('click', () => {
    clearError(dropError);
    clearError(pasteError);

    const isEml = !!droppedEmlText;
    const input = isEml ? droppedEmlText : pasteArea.value.trim();

    if (!input) {
      showError(pasteError, 'Paste headers or drop a .eml file first.');
      return;
    }

    const parseHtml = isEml ? (html) => {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      return Array.from(doc.querySelectorAll('a[href]')).map(a => ({
        href: a.getAttribute('href') || '',
        text: a.textContent.trim(),
      }));
    } : null;

    const result = window.Analyzer.runAnalysis(input, { isEml, parseHtml });

    if (result.error) {
      showError(pasteError, result.error);
      return;
    }

    renderResults(result, isEml);
  });
</script>
```

- [ ] **Step 2: Verify in browser**

Paste `From: x@y.com` and click Analyze. Expect a console error about `renderResults` not being defined -- that is correct at this stage.

- [ ] **Step 3: Commit**

```bash
git add index.html
git commit -m "Feat: wire drag-and-drop, paste, and analyze button"
```

---

## Task 11: Results Rendering

**Files:**
- Modify: `index.html` (add rendering functions to the same `<script>` block, before `</script>`)

- [ ] **Step 1: Add rendering functions inside the existing script block, after the event handlers**

```js
  const VERDICT_ICONS  = { red: '\u26a0\ufe0f', amber: '\u26a0\ufe0f', green: '\u2705' };
  const VERDICT_BADGES = { red: 'HIGH RISK', amber: 'SUSPICIOUS', green: 'LIKELY SAFE' };
  const STATUS_LABELS  = { pass: 'PASS', warn: 'WARN', fail: 'FAIL', na: 'N/A' };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function renderResults(result, isEml) {
    const container = document.getElementById('results');
    container.textContent = '';
    container.classList.add('visible');
    container.appendChild(renderVerdict(result.verdict));
    container.appendChild(renderChecks(result.checks));
    if (isEml && result.urlResults !== null) {
      container.appendChild(renderUrls(result.urlResults));
    } else if (!isEml) {
      const note = el('p', null, 'Drop a .eml file to also scan links in the email body.');
      note.style.cssText = 'font-size:0.8rem;color:var(--text-muted);margin-top:-12px;margin-bottom:24px';
      container.appendChild(note);
    }
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderVerdict(verdict) {
    const banner = el('div', `verdict-banner ${verdict.color}`);

    banner.appendChild(el('div', 'verdict-icon', VERDICT_ICONS[verdict.color]));

    const textDiv = el('div');
    textDiv.appendChild(el('div', 'verdict-label', verdict.label));
    const parts = [];
    if (verdict.failCount > 0) parts.push(`${verdict.failCount} check${verdict.failCount > 1 ? 's' : ''} failed`);
    if (verdict.warnCount > 0) parts.push(`${verdict.warnCount} warning${verdict.warnCount > 1 ? 's' : ''}`);
    textDiv.appendChild(el('div', 'verdict-sub', parts.join(' \u00b7 ') || 'No issues found'));
    banner.appendChild(textDiv);

    banner.appendChild(el('span', 'verdict-badge', VERDICT_BADGES[verdict.color]));
    return banner;
  }

  function renderChecks(checks) {
    const wrap = el('div');
    wrap.appendChild(el('div', 'section-label', 'Check Breakdown'));
    const list = el('div', 'checks-list');
    for (const check of checks) {
      const row = el('div', `check-row ${check.status}`);
      row.appendChild(el('span', 'check-tag', STATUS_LABELS[check.status]));
      row.appendChild(el('span', 'check-name', check.name));
      row.appendChild(el('span', 'check-detail', check.detail));
      list.appendChild(row);
    }
    wrap.appendChild(list);
    return wrap;
  }

  function renderUrls(urlResults) {
    const wrap = el('div', 'url-section');
    wrap.appendChild(el('div', 'section-label', 'URL Analysis'));

    if (!urlResults.length) {
      wrap.appendChild(el('p', 'url-clean', 'No URLs found in email body.'));
      return wrap;
    }

    for (const { url, flags } of urlResults) {
      const item = el('div', 'url-item');
      item.appendChild(el('div', 'url-text', url));
      if (flags.length) {
        const flagsDiv = el('div', 'url-flags');
        for (const flag of flags) flagsDiv.appendChild(el('span', 'url-flag', flag));
        item.appendChild(flagsDiv);
      } else {
        const clean = el('span', null, 'No flags');
        clean.style.cssText = 'font-size:0.72rem;color:var(--green);margin-top:4px;display:inline-block';
        item.appendChild(clean);
      }
      wrap.appendChild(item);
    }
    return wrap;
  }
```

- [ ] **Step 2: Test with this sample (paste, click Analyze)**

```
Received: from mail.evil.com by mx.gmail.com
Received: from relay1.com by mail.evil.com
From: "PayPal Support" <support@paypa1-security.com>
Reply-To: harvest@evil.com
Return-Path: <bounce@evil.com>
Subject: Your account has been limited
Message-ID: notvalid
Received-SPF: fail (not permitted)
Authentication-Results: mx.google.com; dkim=fail
```

Expected: red verdict banner, FAIL on SPF/DKIM, WARN on Reply-To/Return-Path/Display Name/Message-ID, note about dropping .eml for URL scan.

- [ ] **Step 3: Run full test suite one final time**

```
node tests/analyzer.test.js
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add index.html
git commit -m "Feat: implement results rendering (verdict, checks, URLs)"
```

---

## Spec Coverage

| Requirement | Task |
|---|---|
| SPF / DKIM / DMARC checks | 4 |
| Reply-To / Return-Path / Display name checks | 5 |
| Message-ID / Received hops checks | 6 |
| URL extraction and flagging | 7 |
| Verdict scoring and runAnalysis orchestrator | 8 |
| Error: no headers found | 8 |
| Dark GitHub-inspired theme | 2 |
| Intro section and tagline | 9 |
| How-to guide (Gmail, Outlook, Apple Mail) | 9 |
| What-we-check list | 9 |
| .eml file drop with wrong-type rejection | 10 |
| Paste raw headers | 10 |
| Empty input error | 10 |
| Verdict banner (red / amber / green) | 11 |
| Per-check breakdown rows | 11 |
| URL results section | 11 |
| Paste-mode note (no URL scan) | 11 |
