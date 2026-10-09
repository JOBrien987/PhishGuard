'use strict';
const statusNode = document.getElementById('status');
const resultsNode = document.getElementById('results');
function parseLinksFromHtml(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  return [...doc.querySelectorAll('a[href]')].slice(0, 250).map(a => ({ href: a.getAttribute('href') || '', label: (a.textContent || '').slice(0, 300) }));
}
function walkParts(part, gathered, depth = 0) {
  if (!part || depth > 20 || gathered.total > 250000) return;
  const type = String(part.contentType || '').toLowerCase();
  if (typeof part.body === 'string' && (type.startsWith('text/plain') || type.startsWith('text/html'))) {
    const body = part.body.slice(0, Math.max(0, 250000 - gathered.total));
    gathered.total += body.length;
    if (type.startsWith('text/html')) {
      const doc = new DOMParser().parseFromString(body, 'text/html');
      gathered.text.push((doc.body?.textContent || '').slice(0, 200000));
      gathered.links.push(...parseLinksFromHtml(body));
    } else {
      gathered.text.push(body);
      const found = body.match(/https?:\/\/[^\s<>"']+/gi) || [];
      gathered.links.push(...found.slice(0, 250).map(href => ({ href: href.replace(/[),.;!?]+$/, ''), label: '' })));
    }
  }
  for (const child of part.parts || []) walkParts(child, gathered, depth + 1);
}
function show(report) {
  statusNode.hidden = true;
  resultsNode.hidden = false;
  document.querySelector('.summary').classList.add(report.level);
  document.getElementById('score').textContent = `${report.score}/100`;
  document.getElementById('verdict').textContent = ({low:'Few indicators found',medium:'Review carefully',high:'Elevated phishing indicators'})[report.level];
  document.getElementById('counts').textContent = `${report.scannedLinks} unique web link(s) checked.`;
  const list = document.getElementById('findings');
  if (!report.findings.length) {
    const li = document.createElement('li');
    li.textContent = 'No listed indicators detected. Phishing can still be present; independently verify unexpected requests.';
    list.appendChild(li);
  }
  for (const finding of report.findings) {
    const li = document.createElement('li');
    const heading = document.createElement('strong');
    heading.textContent = `${finding.title} (+${finding.points})`;
    const detail = document.createElement('small');
    detail.textContent = finding.detail;
    li.append(heading, detail);
    list.appendChild(li);
  }
}
(async () => {
  try {
    const messages = await messenger.messageDisplay.getDisplayedMessages();
    if (!messages || messages.length !== 1) { statusNode.textContent = 'Open a single email, then click PhishGuard.'; return; }
    const message = messages[0];
    const full = await messenger.messages.getFull(message.id);
    const gathered = { text: [], links: [], total: 0 };
    walkParts(full, gathered);
    const h = full.headers || {};
    const reply = (h['reply-to'] || []).join(', ');
    show(PhishGuard.inspect({author: message.author, replyTo: reply, subject: message.subject, text: gathered.text.join('\n'), links: gathered.links}));
  } catch (error) { statusNode.textContent = `Unable to scan this message: ${error.message || 'Unknown error'}`; }
})();
