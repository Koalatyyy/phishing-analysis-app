# Phishing Header Analyzer

A standalone browser-based tool for analyzing email headers and body links for phishing indicators. No server, no API keys, no install -- open `index.html` directly.

## Usage

Open `index.html` in any modern browser, then either:

- **Drop a `.eml` file** onto the drop zone (exported from Gmail, Outlook, or Apple Mail)
- **Paste raw headers** into the text area

Click **Analyze Headers** to get a color-coded verdict and per-check breakdown.

### Getting your email headers

| Client | Steps |
|---|---|
| Gmail | Open email -> three-dot menu -> Show original |
| Outlook (Web) | Three-dot menu -> View -> View message source |
| Apple Mail | View -> Message -> Raw Source (or Opt+Cmd+U) |

## What it checks

| Check | What it looks for |
|---|---|
| SPF | Sending server authorized for the From domain |
| DKIM | Valid cryptographic signature present |
| DMARC | Email passed the domain owner's published policy |
| Reply-To mismatch | Reply-To domain differs from From domain |
| Return-Path mismatch | Bounce address domain differs from From domain |
| Display name spoofing | Visible sender name contains a domain differing from the actual address |
| Message-ID | Presence and format of unique message identifier |
| Received hops | Unusual number of mail server hops (warn: 6-10, fail: 11+) |
| Suspicious URLs | IP hostnames, URL shorteners, punycode/IDN, excessive subdomains, brand lookalikes (.eml only) |

### Verdict scoring

- Each **fail** = 2 points, each **warn** = 1 point
- Score >= 4: **Likely Phishing** (red)
- Score >= 2: **Suspicious** (amber)
- Score < 2: **Likely Legitimate** (green)

## Files

```
index.html             # UI shell, event wiring, DOM rendering
style.css              # Dark GitHub-inspired theme
analyzer.js            # All analysis logic (also runs in Node.js)
tests/analyzer.test.js # Unit tests (Node.js built-in assert)
```

## Tests

```bash
node tests/analyzer.test.js
```

63 tests covering all analysis functions.

## Privacy

All analysis runs locally in the browser. No data is sent anywhere.
