/* Automatic, event-driven message analysis. No network requests. */
'use strict';
const TAG = 'phishguard_risk';
const scans = new Map();
const MAX_CACHE = 300;
function extract(html) {
  const out = {text: [], links: [], total: 0};
  function walk(part, depth=0) {
    if (!part || depth > 15 || out.total >= 160000) return;
    const type = String(part.contentType || '').toLowerCase();
    if ((type.startsWith('text/html') || type.startsWith('text/plain')) && typeof part.body === 'string') {
      const body = part.body.slice(0, Math.max(0, 160000 - out.total)); out.total += body.length;
      if (type.startsWith('text/html')) {
        // Parse in a detached HTML document; do not load remote resources.
        const doc = new DOMParser().parseFromString(body, 'text/html');
        out.text.push((doc.body?.textContent || '').slice(0, 130000));
        for (const a of [...doc.querySelectorAll('a[href]')].slice(0, 250))
          out.links.push({href:a.getAttribute('href') || '', label:(a.textContent || '').slice(0, 300)});
      } else {
        out.text.push(body);
        for (const href of (body.match(/https?:\/\/[^\s<>"']+/gi) || []).slice(0, 250))
          out.links.push({href:href.replace(/[),.;!?]+$/, ''), label:''});
      }
    }
    for (const child of part.parts || []) walk(child, depth + 1);
  }
  return {out, walk};
}
async function analyze(message) {
  if (scans.has(message.id)) return scans.get(message.id);
  const full = await messenger.messages.getFull(message.id);
  const {out,walk} = extract(); walk(full);
  const report = PhishGuard.inspect({author:message.author, subject:message.subject,
    replyTo:(full.headers?.['reply-to'] || []).join(', '), text:out.text.join('\n'),links:out.links});
  scans.set(message.id, report);
  if (scans.size > MAX_CACHE) scans.delete(scans.keys().next().value);
  return report;
}
async function ensureTag() {
  const current = await messenger.messages.tags.list();
  if (!current.some(t => t.key === TAG)) await messenger.messages.tags.create(TAG, 'PhishGuard: Suspicious', '#d93025');
}
async function scanIncoming(message) {
  try {
    const report = await analyze(message);
    if (report.score < 20) return;
    await ensureTag();
    const tags = [...new Set([...(message.tags || []), TAG])];
    await messenger.messages.update(message.id, {...(report.score >= 50 ? {flagged:true} : {}),tags});
    if (report.score >= 50) await messenger.notifications.create(`phishguard-${message.id}`, {
      type:'basic', title:'PhishGuard: Suspicious email',
      message:`Risk ${report.score}/100: ${String(message.subject || '(no subject)').slice(0, 90)}. ${report.findings.slice(0,2).map(f=>f.title).join('; ')}`
    });
  } catch (error) { console.error('PhishGuard incoming scan failed:', error); }
}
messenger.messages.onNewMailReceived.addListener(async (_folder, page) => {
  // Yield between messages so an incoming batch doesn't monopolize the event loop.
  let current = page;
  while (current) {
    for (const message of current.messages || []) await scanIncoming(message);
    current = current.id ? await messenger.messages.continueList(current.id) : null;
  }
});
// UI requests are served by the same analysis path, not a second network or scanning service.
messenger.runtime.onMessage.addListener(async (request) => {
  if (request?.kind !== 'phishguard-report' || !Number.isInteger(request.messageId)) return;
  const message = await messenger.messages.get(request.messageId);
  return analyze(message);
});
