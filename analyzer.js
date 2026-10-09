/* Pure analysis module. No network requests, no message mutation. */
(function(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PhishGuard = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy']);
  const SCHEMES = /^https?:\/\//i;
  function hostname(raw) { try { const url = new URL(raw); return ['http:', 'https:'].includes(url.protocol) ? url.hostname.toLowerCase() : ''; } catch { return ''; } }
  function normalizeHost(host) { return host.replace(/^www\./, ''); }
  function unique(items) { return [...new Set(items)]; }
  function emailDomain(author) { const match = String(author || '').match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i); return match ? match[1].toLowerCase() : ''; }
  function inspect(data) {
    const findings = [];
    const add = (points, title, detail) => findings.push({points, title, detail});
    const sender = emailDomain(data.author);
    const reply = emailDomain(data.replyTo);
    if (reply && sender && reply !== sender) add(20, 'Reply-To domain differs', `${sender} → ${reply}`);
    const subject = String(data.subject || '');
    const content = String(data.text || '').slice(0, 200000);
    const prose = `${subject} ${content}`;
    if (/\b(verify your (account|identity)|account (locked|suspended)|password expires?|unusual sign.in|confirm your payment|update your billing)\b/i.test(prose)) add(15, 'Account pressure language', 'Message requests urgent account or payment action.');
    if (/\b(immediately|within 24 hours|final warning|urgent action required)\b/i.test(prose)) add(10, 'Urgency language', 'Message urges immediate action.');
    if (/\b(gift cards?|wire transfer|crypto(?:currency)? payment)\b/i.test(prose)) add(15, 'Unusual payment language', 'Check payment requests using an independently known contact method.');
    const links = (Array.isArray(data.links) ? data.links : []).slice(0, 250);
    let nonHttp = 0, ip = 0, short = 0, mismatch = 0, punycode = 0, credentials = 0;
    const encountered = new Set();
    for (const link of links) {
      const raw = String(link.href || '').trim();
      if (!SCHEMES.test(raw)) { if (/^(?:javascript|data):/i.test(raw)) nonHttp++; continue; }
      if (encountered.has(raw)) continue;
      encountered.add(raw);
      let url; try { url = new URL(raw); } catch { continue; }
      const host = normalizeHost(url.hostname.toLowerCase());
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) ip++;
      if (SHORTENERS.has(host)) short++;
      if (host.includes('xn--')) punycode++;
      if (url.username || url.password) credentials++;
      const label = String(link.label || '').trim();
      if (SCHEMES.test(label)) {
        const labelHost = normalizeHost(hostname(label));
        if (labelHost && labelHost !== host) mismatch++;
      }
    }
    if (mismatch) add(35, 'Visible link destination mismatch', `${mismatch} link(s) display one web host but actually point to another.`);
    if (ip) add(25, 'IP-address destination', `${ip} link(s) point to a raw IP address.`);
    if (punycode) add(20, 'Internationalized hostname encoding', `${punycode} link(s) contain punycode. This can be legitimate.`);
    if (credentials) add(25, 'Credentials embedded in URL', `${credentials} link(s) include user information before the hostname.`);
    if (short) add(10, 'Shortened URL', `${short} shortened link(s) obscure the destination.`);
    if (nonHttp) add(20, 'Potentially unsafe link scheme', `${nonHttp} link(s) use a non-web executable/data scheme.`);
    const score = Math.min(100, findings.reduce((total, item) => total + item.points, 0));
    return {score, level: score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low', findings, scannedLinks: encountered.size};
  }
  return { inspect, emailDomain, hostname };
});
