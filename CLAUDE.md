# Project Instructions

## Stack

- Vanilla HTML/CSS/JS -- no build step, no npm, no framework
- Node.js (for running tests only)
- Google Fonts CDN: Inter + JetBrains Mono

## Structure

```
index.html             # UI shell, event wiring, DOM rendering functions
style.css              # Dark GitHub-inspired theme (CSS custom properties)
analyzer.js            # All pure analysis logic
tests/analyzer.test.js # Unit tests
docs/                  # Design spec and implementation plan
```

## Commands

```bash
# Run tests
node tests/analyzer.test.js
```

No build or dev server -- open index.html directly in a browser.

## Architecture

`analyzer.js` exports via an IIFE that works in both Node.js and browser:

```js
(function(exports){
  // functions
})(typeof module !== 'undefined' ? module.exports : (window.Analyzer = {}));
```

`index.html` calls `window.Analyzer.runAnalysis(input, { isEml, parseHtml })` on button click and renders results via pure DOM methods.

## Conventions

- No `.innerHTML =` anywhere -- use `createElement`/`textContent`/`appendChild`
- No `.exec(` -- use `String.matchAll()` for regex iteration
- No external dependencies
- TypeScript not used; keep it plain JS
- Tests use Node.js built-in `assert` module, custom runner pattern
