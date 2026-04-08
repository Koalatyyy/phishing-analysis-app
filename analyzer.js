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
    const displayMatch = from.match(/^"?([^"<]*)"?\s*</);
    if (!displayMatch) return { status: 'pass', detail: 'No display name to inspect' };
    const displayName = displayMatch[1].trim().toLowerCase();
    const actualDomain = extractDomain(from);
    const domainInName = displayName.match(/\b([a-z0-9-]+\.[a-z]{2,})\b/);
    if (!domainInName) return { status: 'pass', detail: 'Display name contains no domain-like string' };
    const namedDomain = domainInName[1];
    if (!actualDomain || namedDomain === actualDomain) return { status: 'pass', detail: 'Display name domain matches sending domain' };
    return { status: 'warn', detail: `Display name references "${namedDomain}" but email is from ${actualDomain}` };
  }

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

  exports.splitEmail = splitEmail;
  exports.parseHeaders = parseHeaders;
  exports.extractDomain = extractDomain;
  exports.checkSPF = checkSPF;
  exports.checkDKIM = checkDKIM;
  exports.checkDMARC = checkDMARC;
  exports.checkReplyTo = checkReplyTo;
  exports.checkReturnPath = checkReturnPath;
  exports.checkDisplayName = checkDisplayName;
  exports.checkMessageId = checkMessageId;
  exports.checkReceivedHops = checkReceivedHops;
  exports.extractUrls = extractUrls;
  exports.flagUrl = flagUrl;

})(typeof module !== 'undefined' ? module.exports : (window.Analyzer = {}));
