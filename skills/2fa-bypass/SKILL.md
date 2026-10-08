---
name: 2fa-bypass
description: Two-factor-authentication (2FA/MFA) bypass methodology - the 10 common patterns. (1) Force-browsing to skip 2FA (call post-MFA APIs directly with the pre-MFA cookie; try referer to the MFA page). (2) OTP/code leakage in responses/JS/logs. (3) OTP brute-force (weak rate limits). (4) Recovery flows bypass MFA (password reset/email change grant session without 2FA). (5) Backup-code / recovery-code abuse (retrievable/regenerable without reauth). (6) CSRF to disable 2FA. (7) Weak 'remember me' tokens / predictable sessions. (8) Forgotten subdomains / legacy / staging endpoints with no MFA. (9) OAuth / account-linking pitfalls (link external identity without owner confirmation). (10) Response/status manipulation + client-side logic trust (flip success/mfa_passed flag). Complements otp-bypass (OTP-code methods). Triggers on 2FA bypass, MFA bypass, force-browse past 2FA, otp leakage in response, reset password bypass MFA, backup-code abuse, disable 2FA csrf, remember-me token forge, legacy endpoint no MFA, social login link takeover, flip mfa_passed flag.
---

# 2FA / MFA Bypass — 10 Patterns

"Bypass 2FA" almost always means a **logical/flow** or **process** weakness, not
cracking TOTP crypto. Get to an authenticated area without the second factor, or
reset/circumvent it. Pair with `otp-bypass` (which covers the OTP *code* methods).

For each pattern: how it looks, how to test, how to fix.

## 1) Force-browsing to skip the 2FA check
The UI shows the 2FA page, but a direct call to a post-MFA API accepts the pre-MFA
session cookie.
- **Test**: log in to the MFA screen; capture the session cookie/token; call likely
  protected endpoints directly (profile, settings, orders, payment-method) with that
  cookie — any returning data/side-effect = a skip. Try many paths
  (`/api/v1/...`, `/internal/...`, `/user/...`) and methods (GET/POST/PATCH). If none
  work, set the `Referer` header to the 2FA page URL — the app may infer "passed 2FA"
  from the referer.
- **Fix**: server-side MFA-completed check on EVERY sensitive endpoint; don't issue a
  full-privilege session cookie until both factors; a pre-MFA token stays tightly
  scoped; add an `mfa_verified` claim; centralize auth checks in middleware.

## 2) Code leakage (responses, JS, logs)
The OTP is returned to the client (`{"status":"ok","otp":"123456"}`) or appears in JS.
- **Test**: trigger OTP generation and inspect all responses; grep JS/network for
  `otp`, `code`, `token`, `verify`. If the code/logic is in client resources → leak.
- **Fix**: never return OTPs to the client; keep generation/validation server-side;
  strip debug fields; single-use + short-lived.

## 3) Brute-forcing OTPs (weak rate limits)
Short numeric codes, no lockout/max-attempts.
- **Test**: observe the verify endpoint; script guesses in a SAFE lab and see whether
  server-side limits lock anything out. Many attempts accepted = vulnerable. (See
  `otp-bypass` for more OTP methods.)
- **Fix**: server-side rate limits + backoff, single-use, short-lived, CAPTCHA/
  lockout/alerts.

## 4) Recovery flows that bypass MFA
Reset/email-change grants a full session (or allows changing recovery info) without
rechecking 2FA.
- **Test**: use password reset — does it create a full session without MFA? Try
  changing recovery email/phone — is MFA required? If reset/change gives access
  without the 2nd factor → bypass.
- **Fix**: re-enroll/verify MFA after reset before full access; require password + MFA
  to change recovery info; log + alert recovery.

## 5) Backup / recovery-code abuse
Backup codes viewable/re-generable in plaintext via an API, without reauth.
- **Test**: inspect endpoints that show/regenerate backup codes; see if viewing/
  regenerating requires password+2FA. Retrievable without extra checks = unsafe.
- **Fix**: display once, store hashed; require password + MFA to view/regenerate;
  monitor regeneration.

## 6) CSRF to disable 2FA
An endpoint toggles/disables MFA without CSRF protection (or without password confirm).
- **Test**: find MFA-toggle / settings endpoints; check for CSRF tokens, SameSite,
  frame-blocking. A cross-site POST in a test env triggers it.
- **Fix**: anti-CSRF tokens + SameSite; require password confirmation to disable MFA;
  frame-ancestors/X-Frame-Options.

## 7) Weak 'remember me' tokens / predictable sessions
Remember-me token forgeable/predictable → autologin without MFA.
- **Test**: inspect remember-me token format across accounts; check predictability/
  forge-ability in a lab.
- **Fix**: long random opaque tokens stored server-side; bind to device metadata;
  revocable; rotate + expire.

## 8) Forgotten subdomains / legacy / staging endpoints
Main site enforces MFA; a legacy API host or staging subdomain does not.
- **Test**: enumerate subdomains + API versions; test MFA enforcement on each host;
  any host accepting credentials without MFA = weak spot.
- **Fix**: inventory/secure all endpoints; centralized auth layer; decommission/block
  legacy or firewall them until retired.

## 9) OAuth / account-linking pitfalls
Linking an external (social) account without owner confirmation, or treating provider
login as full MFA-equivalent.
- **Test**: review the linking flow — is reauthentication required? Try linking an
  external identity in a test env; if it links without confirmation → risk.
- **Fix**: require password + MFA to link; notify/confirm new linked identities; treat
  external login as one signal (extra checks for critical actions). (See
  `oauth-misconfiguration`, `sso-postmessage-pkce`.)

## 10) Response/status manipulation & client-side logic trust
The app trusts a client response flag to decide access (e.g. after password, a
response carries `success`/`mfa_passed`/`mfa_required`, and the client navigates to
protected areas based on it).
- **Test**: log in to the OTP step on a test account; intercept; find the `success` /
  `mfa_passed` / `mfa_required` flag; set it to `true` (or change status); observe
  whether the client proceeds to protected pages / privileged actions without server
  confirmation.
- **Fix**: the server decides access (never from a client-supplied response); deem
  `mfa_passed` a server-side claim; don't use a client flag to gate navigation.

## Reusable checklist
1. **Map the auth flow + all hosts** (main + legacy/staging subdomains + API versions).
2. **Force-browse**: call post-MFA APIs with the pre-MFA cookie (and try Referer to the
   MFA page); test multiple paths/methods.
3. **Code leakage**: inspect responses/JS for OTP/secret.
4. **Brute-force**: OTP verify endpoint rate-limit/lockout behavior.
5. **Recovery**: reset/email-change → does it bypass MFA? recovery-info change needs
   MFA?
6. **Backup codes**: retrievable/regenerable without reauth?
7. **CSRF**: MFA-toggle/settings endpoints lacking tokens/SameSite/frame-blocking.
8. **Remember-me**: token predictability/forge-ability.
9. **OAuth linking**: external identity linkable without confirmation.
10. **Response manipulation**: flip `success`/`mfa_passed` on the client.
11. Own test accounts only; don't target real victims.

## Gotchas
- Force-browsing needs the pre-MFA cookie to actually hold a scoped-but-usable
  session; a Referer-based check is app-specific (test both).
- Brute-force/forging: always in a safe lab, respect rate limits, use your own OTP.
- Some fixes (e.g. middleware centralization) still leave specific endpoints
  unprotected — retest every sensitive route, not just the main flow.
