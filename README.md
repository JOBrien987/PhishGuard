# PhishGuard for Thunderbird

**An explainable, privacy-first phishing indicator checker built with JavaScript and Thunderbird MailExtensions.**

PhishGuard adds a toolbar button to an open email. Click it to review locally calculated phishing indicators: display-link destination mismatches, raw-IP and shortened links, punycode, unusual URL credentials, Reply-To domain differences, and common social engineering language.

## Privacy and limitations

- **No external requests, API keys, tracking, or message uploads.**
- Messages are read only on demand when the scan button is clicked.
- The score is a simple heuristic, **not** a probability of phishing, a malware scan, a verdict of trust, or a definitive email authentication result.
- Legitimate emails may trigger warnings; malicious emails may evade these checks.
- The extension does not expand short links, follow URLs, analyze attachments, validate SPF/DKIM/DMARC, or block messages.
- A scan is limited to the first 250 KB of text/HTML and the first 250 links per MIME part.

## Install locally

1. Download `phishguard-thunderbird.xpi` from this repository's releases (or build it as below).
2. In Thunderbird, open **Add-ons and Themes**, choose the gear menu, select **Install Add-on From File**, and select the `.xpi`.
3. Open one email and click **PhishGuard** in the message toolbar.
4. Read the reasons for the score. Independently verify suspicious requests.

Requires Thunderbird 128 or later. Tested through source-level checks only; compatibility with your specific Thunderbird build has not yet been verified.

## Development

No runtime dependencies. You need Node.js only to run the analyzer tests.

```sh
node --test tests/*.test.js
```

To build the XPI, zip the **contents** of the repository (with `manifest.json` at ZIP root), then rename `.zip` to `.xpi`.

## Design

- `manifest.json` — Thunderbird MV3 message toolbar action and minimum permissions.
- `popup.html`, `popup.css` — lightweight user interface.
- `src/popup.js` — on-demand message extraction and report rendering.
- `src/analyzer.js` — testable, dependency-free local detection logic.
- `tests/analyzer.test.js` — unit tests for basic detection and edge cases.

## Roadmap

- Add transparent configurable rule weights and stronger sender-domain validation.
- Add optional, privacy-preserving authentication-header review.
- Add an accessible export of the scan report.

## License

MIT. See [LICENSE](LICENSE).

## Automatic protection (v0.2 prototype)

When Thunderbird reports newly received messages, PhishGuard scans their headers and up to 160 KB of plain text/HTML locally. Messages scoring 20 or higher receive the red **PhishGuard: Suspicious** tag. Messages scoring 50 or higher are also starred and trigger a desktop notification. The existing toolbar button still provides detailed findings. No messages are sent to remote services; no messages are deleted or quarantined.

**Limitations:** New messages only; mail already in folders before installation is not retroactively scanned. Heuristic scores can produce false positives and false negatives. Automatic tags/stars require write permissions and Thunderbird must be running to process received mail. Manual Thunderbird integration testing is still required. Thunderbird's delivery event fires after junk classification and message filters, so alerts aren't guaranteed to precede opening the message.
