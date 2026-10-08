---
name: password-reset-parameter-poisoning
description: Password-reset/magic-link parameter poisoning through hidden href/callback parameters and inconsistent backend parsing. Discover hidden parameters manually when Arjun/Param Miner misses them because the scanner uses invalid baseline values; identify a hidden `href`/callback parameter used to build the magic-link URL, set it to an owned canary/collaborator URL, and confirm the reset/login link points there, leaking the login token/credentials when followed. Also covers HTTP Parameter Pollution (duplicate email values reaching different microservices), recipient/header parsing with comma/space/semicolon separators, SMTP/header injection branches, and reset-link host/callback poisoning. Triggers on magic link, password reset parameter poisoning, hidden href parameter, Arjun misses parameter, HPP email reset, forgot password callback, reset token leak, credential leak through email link.
---

# Password-Reset / Magic-Link Parameter Poisoning

Password-reset and magic-link flows often accept more parameters than the UI exposes.
A hidden `href`, callback, redirect, or email-routing parameter can let an attacker
control where the login/reset link points — leaking a token/credential when the
victim or an email previewer follows it.

## Core chain — hidden `href` → magic-link token leak

1. Start with the forgot-registration/password-reset request and map the normal
   body. It may appear to accept only:
   ```json
   { "email": "test@example.com" }
   ```
2. **Don't rely exclusively on Arjun/Param Miner.** If the baseline email value is
   invalid, every candidate request returns the same validation error/content length,
   so response-diff tools miss dynamic parameters.
3. Build a manual parameter wordlist from the app's JS, response fields, HTML/forms,
   and common names (`href`, `url`, `callbackUrl`, `redirect`, `returnUrl`, `link`,
   `template`, `registration`, `email`). Add each candidate with a valid email and
   a distinctive canary value; compare response and email output.
4. If `href`/callback is reflected into the reset email, set it to an **owned
   canary/Collaborator URL** (not a third-party victim target).
5. The email's magic link points to the canary URL with the token attached; following
   it leaks the token/credential to your controlled server → use it only on your own
   test account to confirm impact.

## Why tools miss hidden parameters

Parameter discovery tools commonly use placeholder values such as `1234`. If the
endpoint validates the known `email` field first, every request with an unknown
parameter still returns "Invalid email" and the same response length. The parameter
can be real but invisible to the scanner.

Better manual approach:
```python
params = ["href", "callbackUrl", "redirect", "returnUrl", "link", "url"]
for p in params:
    body = {"email":"owned-test@example.com", p:"https://canary.example/"+p}
    # compare response, email body, link destination, and timing
```
Use valid baseline values and canaries that make reflection obvious.

## HPP / microservice parsing branch

If the reset flow crosses services with different parameter parsers, duplicate fields
may be interpreted differently:
```json
{"email":"victim@example.com", "email":"attacker@example.com"}
```
One service may use the first value (DB lookup), another the second (SMTP delivery),
creating a split between the account whose token is generated and where the email is
sent. Test first/last duplicate ordering and JSON/form/query variants.

For email recipient parsing, test separators only on owned accounts and within scope:
- comma `,`
- semicolon `;`
- space
- newline/CRLF (SMTP injection branch; modern mail functions may reject it)

## Related poisoning branches

- **Host header / X-Forwarded-Host** in reset-link construction → see
  `host-header-password-poisoning`.
- **Null-byte callback URL parsing** → see `null-byte-injection`.
- **Email-change verification link applied to whoever clicks** → see
  `account-takeover-flows`.
- **OAuth callback identity/callback URL tampering** → see
  `oauth-misconfiguration`.

## Reusable checklist

1. Capture the normal reset/magic-link request and email.
2. Inspect JS and request/response fields for hidden URL/link parameters.
3. Use valid owned email values when testing parameter discovery.
4. Test `href`, `callbackUrl`, `redirect`, `returnUrl`, `url`, `link` with a controlled
   canary URL.
5. Compare first/last duplicate parameters across query, form, and JSON parsers.
6. Confirm the generated link contains the canary plus a token/code.
7. Follow it only using an owned test account; confirm the token's scope and expiry.
8. Check whether the token is single-use, account-bound, and accepted only at the
   intended origin.

## Reporting

- Classify as password-reset/magic-link poisoning, sensitive token disclosure, or
  account takeover (CWE-640 / CWE-601 / CWE-200).
- Include the hidden parameter, the before/after request, the generated email link,
  and a canary-server request proving the token reached your controlled host.
- Fix: allowlist accepted parameters, bind link generation to a fixed origin, ignore
  client-controlled href/redirect values, normalize duplicate parameters consistently,
  reject CR/LF/control bytes, and bind reset tokens to the intended account/session.

## Safety

Use only owned test mailboxes and a controlled canary endpoint. Do not target real
victims, collect third-party reset tokens, or reset another user's password.
