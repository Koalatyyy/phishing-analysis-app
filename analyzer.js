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
