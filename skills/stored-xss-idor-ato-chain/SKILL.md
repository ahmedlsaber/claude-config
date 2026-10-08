---
name: stored-xss-idor-ato-chain
description: Chained zero-click account takeover via self-stored XSS plus IDOR in a messaging/AI chat feature. Find HTML/XSS stored in chat content, bypass weak filters using safe parser differentials such as SVG/script and encoded characters, then modify a conversationId/threadId in the message-send request to deliver the payload into another user's conversation without authorization. If the victim chat renders messages automatically, the XSS executes without a click and can abuse the victim's browser session. Triggers on self-stored XSS in chat, AI chat HTML rendering, conversationId IDOR, send message to another user's thread, zero-click ATO chain, SVG script filter bypass.
---

# Self-Stored XSS + Conversation IDOR → Zero-Click ATO

A self-stored XSS may look low impact when only the attacker can store and view it.
An IDOR in the message-delivery path changes the impact completely: inject the
payload into a victim's conversation, where it renders automatically and executes
without victim interaction.

## Chain

1. **Stored HTML/XSS**: chat messages are rendered as raw HTML instead of safely
   escaped/sanitized.
2. **Filter bypass**: the sanitizer blocks obvious event handlers/tokens but misses
   a browser parser differential, such as SVG/script content or encoded characters.
3. **Conversation IDOR**: the send-message request accepts a client-controlled
   `conversationId`/`threadId` and does not verify that the sender belongs to the
   conversation.
4. **Automatic rendering**: the victim's chat loads or renders the newly delivered
   message automatically.
5. **ATO impact**: the script executes in the victim's origin and abuses the session
   or authenticated browser actions.

## Testing sequence

### A. Confirm the stored HTML behavior
Use an owned test conversation and send harmless markup first:
```html
Test<h1>HTMLi</h1>
```
If it renders as an element, the output is not safely escaped. Then use a harmless
XSS proof on owned accounts only and inspect whether the content executes.

### B. Test sanitizer/parser differentials
If obvious payloads (`onerror`, `onload`, `alert`) are filtered, check whether the
sanitizer and browser parse the same structure. Test safe, bounded variants such as:
- SVG/script handling
- HTML entity or Unicode-escaped characters
- case and whitespace variations
- alternate event/property forms
- malformed nesting that browsers repair differently

Stop once execution is proven on an owned account. Do not steal cookies or target
real users.

### C. Test conversation authorization
Capture the normal send-message request:
```json
{"conversationId":"<owned-thread>","message":"..."}
```
Replace the id with a second **owned** account's conversation ID. A secure server
must reject it with 403/404. If the message is delivered, the conversation has an
IDOR/BOLA.

Test the same ownership check on read, edit, delete, attachment, reaction, and
thread-member endpoints.

### D. Confirm zero-click delivery
Use two owned accounts. Send a harmless marker to the second account's conversation
and observe whether it appears without that user opening or approving anything. Then
use the minimal owned-account XSS proof to confirm automatic execution.

## Impact and responsible proof

The strongest report combines:
- Stored XSS confirmed in the attacker's own chat.
- Cross-conversation message delivery confirmed only between owned accounts.
- Automatic rendering confirmed in the second owned account.
- A safe proof of browser-origin execution, without exfiltrating real cookies or
  modifying another user's account.

Describe the potential chain as session theft/browser-riding only when the program's
rules permit that demonstration. Prefer a canary value or a harmless authenticated
read on your own second account rather than sending cookies to a collector.

## Remediation

- Escape text by default; sanitize HTML with a well-maintained allowlist.
- Disallow active SVG/script content in chat messages; sanitize after decoding and
  canonicalization, not only before.
- Enforce conversation membership server-side on every read and write operation.
- Do not trust `conversationId` from the client; derive membership from the session.
- Use HttpOnly/Secure/SameSite cookies and a strong CSP to reduce XSS impact.
- Add tests for cross-thread message delivery and parser-differential payloads.

## Related techniques

Cross-reference `idor-methodology`, `idor-http-method-tampering`,
`unicode-homoglyph-bypass`, `null-byte-injection`, `2fa-bypass`, and
`account-takeover-flows`.
