# Phishing Header Analyzer -- Design Spec
_Date: 2026-04-07_

## Overview

A standalone browser-based tool for analyzing email headers to assess phishing likelihood. No server, no API keys, no install -- open `index.html` in any browser. Input via drag-and-drop of `.eml` files or paste of raw header text. Outputs a color-coded verdict and per-check breakdown.

---

## Architecture

Three files, no build step:

```
index.html    -- page shell, drop zone, textarea, results container
style.css     -- dark security-tool theme (Inter + JetBrains Mono via Google Fonts CDN)
analyzer.js   -- all parsing and analysis logic; pure functions, no dependencies
```

`index.html` handles all DOM events and delegates to `analyzer.js` for logic. Results are rendered back into the DOM. Nothing leaves the browser.

---

## UI

Dark GitHub-inspired theme. Inter for UI text, JetBrains Mono for header content and check names.

### Page structure (top to bottom)

1. **Intro section** -- one-liner description of the tool, then a collapsible "How to get your email headers" guide covering Gmail, Outlook, and Apple Mail, followed by a brief list of what checks are run.
2. **Input area** -- drag-and-drop zone with a textarea below for pasting raw headers. A single "Analyze" button triggers analysis. Non-.eml files are rejected with an inline error message.
3. **Results area** -- hidden until analysis runs, then shows:
   - Verdict banner (red / amber / green with risk label)
   - Check breakdown table
   - URL section (only when a .eml file was dropped and URLs were found)

---

## Input Handling

### .eml file drop
- Read file as text
- Extract headers: everything before the first blank line (`\n\n` or `\r\n\r\n`)
- Body is retained separately for URL extraction
- Non-.eml files show an inline error: "Only .eml files are supported"

### Paste
- Use textarea content as-is
- Parser handles both headers-only and full raw email (headers + body)
- No body URL analysis in paste mode (UI note: "Drop a .eml file to also scan links")

### Header normalization
- Fold multi-line headers (continuation lines starting with whitespace, per RFC 5322)
- Build a map of `headerName (lowercase) -> string[]` for O(1) lookup
- Preserve original casing in display

---

## Analysis Checks

### Header checks (run on both file drop and paste)

| # | Check | Source header(s) | Logic |
|---|---|---|---|
| 1 | SPF | `Received-SPF` | PASS=`pass`, WARN=`softfail`/`neutral`, FAIL=`fail`/`permerror`/`temperror`, N/A=missing |
| 2 | DKIM | `Authentication-Results`, `DKIM-Signature` | PASS=`dkim=pass` in auth-results or signature header present, FAIL=`dkim=fail`, N/A=neither present |
| 3 | DMARC | `Authentication-Results` | PASS=`dmarc=pass`, FAIL=`dmarc=fail`, N/A=not present |
| 4 | Reply-To mismatch | `From`, `Reply-To` | PASS=same domain or Reply-To absent, WARN=different domain |
| 5 | Return-Path mismatch | `From`, `Return-Path` | PASS=same domain, WARN=different domain, N/A=Return-Path absent |
| 6 | Display name spoofing | `From` | WARN if display name contains a string resembling a domain (contains `.`) that differs from the actual sending domain |
| 7 | Message-ID | `Message-ID` | PASS=present and contains `@`, WARN=missing or malformed |
| 8 | Received hops | `Received` (count) | PASS=1-5, WARN=6-10, FAIL=>10 |

### URL check (file drop only)

| # | Check | Logic |
|---|---|---|
| 9 | Suspicious URLs | Extract all `http(s)://` URLs from body. Flag each URL for: IP-address hostname, known URL shortener domain (hardcoded list: bit.ly, tinyurl.com, t.co, etc.), mismatched anchor text vs actual href in HTML emails (parsed via DOMParser), more than 2 subdomain levels (e.g. `a.b.c.evil.com`), punycode/IDN hostnames (starting with `xn--`), hostname containing a hardcoded brand name but not being that brand's actual domain (list: paypal, microsoft, amazon, apple, google, facebook, netflix). Each URL contributes 1 flag. PASS=0 flagged URLs, WARN=1-2 flagged URLs, FAIL=3+ flagged URLs |

URL results include a collapsible list showing each URL, its flags, and the raw string.

---

## Verdict Scoring

Each check result contributes to a score:
- FAIL = 2 points
- WARN = 1 point
- PASS / N/A = 0 points

N/A is neutral -- missing headers are not penalized (they are informational).

| Score | Verdict | Color |
|---|---|---|
| 0-1 | Likely Legitimate | Green |
| 2-3 | Suspicious | Amber |
| 4+ | Likely Phishing | Red |

The verdict banner shows the label, score, and a summary line (e.g. "3 checks failed, 2 warnings").

---

## Per-Check Display

Each check renders as a row:
- Colored left border (red=FAIL, amber=WARN, green=PASS, grey=N/A)
- Status tag (FAIL / WARN / PASS / N/A)
- Check name (monospace)
- One-line explanation of the result (e.g. "Received-SPF: fail -- sender not authorized for domain paypal.com")

---

## Error Handling

- Wrong file type: inline message in the drop zone, no results rendered
- Empty input on Analyze: inline prompt "Paste headers or drop a .eml file first"
- No headers found after parsing: inline message "Could not find email headers in this input"
- All errors are shown inline, never as alerts

---

## Out of Scope (v1)

- API-based checks (VirusTotal, AbuseIPDB, Google Safe Browsing) -- deferred
- Chrome extension packaging -- standalone web app only
- Saving or exporting results
- Batch analysis of multiple emails
