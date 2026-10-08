---
name: account-takeover-flows
description: Account Takeover (ATO) via signup, password-reset, and action-verification flows. Covers (1) signup-email-normalization/CRLF bypass (register an already-registered email by appending %0a/newline), (2) password-reset email-parameter tampering (mint a reset for attacker, swap 'email' to victim in the reset-complete POST), (3) predictable/forgeable reset token (Base64 '{userID,email}' -> forge victim's token), (4) reusable/brute-forceable reset token (sequential user ID in token -> enumerate to victim), and (5) verification/action-link "whoever clicks it" confused-deputy ATO (a change-email/phone verification link issued to attacker updates the victim when the victim clicks it, because the token is not bound to the requesting account/session). A reusable ATO checklist for signup, forgot-password, reset-consumption, token-generation, and action-verification endpoints. Triggers on: account takeover, reset password email swap, forge password reset link, base64 reset token, CRLF/newline in email/username bypass, predictable reset token, reusable token, signup with existing email, verification link updates wrong user / clicked by another user.
---

# Account Takeover via Signup & Password-Reset Flows

Four recurring ATO sub-classes worth testing on every application with
registration + password reset. Same-origin, no external tooling required for most.

Key primitives to test on **every** auth flow:
- Does the "already registered" / existence / uniqueness check compare the raw
  value, and does the downstream identity resolution normalize it differently?
- Is the reset token **bound** to the account it was issued for (server-side), and
  is it **random, single-use, and time-limited**?
- Is the final mutation (register/reset) authorized against who the token/cookie
  belongs to, or does it trust a client-supplied identity param (email/userId)?

## 1 — Signup ATO via email normalization / newline injection

The register endpoint blocks re-registering an existing email. Bypass by making the
**existence check** miss while the **account creation** lands on the same identity:

- Append a newline / CRLF / invisible char: `victim@gmail.com%0a` (URL-encoded
  `%0a` = `\n`). The uniqueness check sees `victim@gmail.com` ≠ `victim@gmail.com\n`
  and allows it; the user/email resolution then treats it as the same account (or
  the app trims it) → you're logged into the **victim's** account.
- Other separators to try: `%00` (null), `%0d` (CR), trailing space `%20`,
  `\t`, plus-tag `+tag`, dot variants, case flips (see case-sensitivity /
  unicode-homoglyph skills for more).

Worked example: register with `victim@gmail.com%0a` → response `registerStatus:true`,
`Set-Cookie: userid=<victim's id>` → you're in the victim's account.

Check: does the "is email taken" probe compare the exact string, while creation
handles it loosely? Test each separator at the end and inside the local part.

## 2 — Password-reset ATO via email-parameter tampering

The reset workflow issues a link for the **attacker**, then the reset-complete
request carries an `email` (or `userId`) param the client controls. Swap it to the
victim's and the server resets the **victim's** password (it doesn't re-derive the
account from the reset token):

Worked example:
1. Forgot-password for `attacker@gmail.com` → receive reset link.
2. Open it, fill new password, intercept the completion POST:
   `POST /user/password-reset-done`
   `email=attacker@gmail.com&password=Security@1&confirm_password=Security@1`
3. Change `email=attacker@gmail.com` → `email=victim@gmail.com`. Forward.
4. Response `{"status":"success"}`. Log in as victim with the new password.

Check: after a successful reset, is the target account derived from the token
(server-bound) or from the client `email`/`userId`/`user` param? If client-provided
→ swap it. Also test swapping a `user_id`/`userId` field, and changing the email in
the initial forgot-password POST itself.

## 3 — Predictable / forgeable reset token (e.g. Base64 {userID,email})

Reset links embed a token that decodes to an identifier pair and is used
**verbatim** (no signature). Forge the victim's token:

Worked example:
- Link: `/user/reset-password/Mzk3Njk1LGF0dGFja2VyQGdtYWlsLmNvbQ==`
- Decode: `Mzk3Njk1LGF0dGFja2VyQGdtYWlsLmNvbQ==` → `397695,attacker@gmail.com`
- Get the victim's userID + email (often just from visiting their public profile).
- Encode `397694,victim@gmail.com` → `Mzk3Njk0LHZpY3RpbUBnbWFpbC5jb20=`
- Visit the forged URL → reset page for victim → set password → login.

Check: is the token **independently forgeable** (no server signature/HMAC, just a
reversible encoding)? Try base64 (and base64url, hex of `{id,email}`, `id:email`,
URL-encoded, JSON) variants. If it decodes to user-controllable fields and the
endpoint trusts them → forge.

## 4 — Reusable / brute-forceable reset token

Even if you only know the victim's **email** (not the userID), if tokens are
constructed as `{sequential_integer},email` (base64) and are **reusable** (no
single-use/expiry), enumerate the ID space:

Worked example (scripted):
```
known good token:  Mzk3Njk1LGF0dGFja2VyQGdtYWlsLmNvbQ==  -> 397695,attacker@gmail.com
for id in range(lo, hi):
    token = b64(f"{id},victim@gmail.com")
    send GET /user/reset-password/{token}
    if 3xx / reset page reached:  -> victim's reset enabled; set new password
```
Only the victim's email is required; iterate the numeric user id.

Check: is the numeric part a low-entropy sequential userID? Is a valid token enough
to reset without also sending a fresh mail (i.e. token is **reusable/self-service**)?
If both → enumerate.

## 5 — Verification-link / action-link "whoever clicks it" (session-binding flaw)

An email verification (or "confirm change") link is issued to confirm ONE user's
action (e.g. change email to new address). If the link token is **not bound to the
account/session that requested it** — i.e. the backend only checks "a valid/current
token" and then applies the action to **whichever account is currently logged in /
the token's stored target** — then a link meant for user A updates user B when B
clicks it (confused deputy / CSRF-style).

Worked example (change-email ATO):
1. Two accounts: `victim@gmail.com`, `attacker@gmail.com`.
2. In **attacker's** session, request an email change to `123@gmail.com` → a
   verification link is sent to `123@gmail.com`. Copy that link.
3. Paste/open that link **while logged in as `victim@gmail.com`**.
4. If vulnerable, the **victim's** email is updated to `123@gmail.com` (the link's
   action applies to whoever clicks, not who requested it).
5. Now use the verify code to regain/control `123@gmail.com` (owned by attacker),
   and the victim is locked out of their changed account → **ATO** (attacker sets
   victim's email to an attacker-controlled one, then resets the password).

Check: does the verification/action token bind the action to the **requesting
account + session**, or does it just carry "the new value + a valid token" and apply
it to the current (or a client-chosen) identity? The latter is the bug.

Reusable across: change-email, change-phone, change-username, primary-email-set,
2FA-disable confirmation, and any one-time action link that should be bound to the
requester.


## Reusable ATO checklist (per flow)

For signup:
- [ ] Can a registered email be re-registered via separator/case/normalization (%0a,
      %00, space, `+tag`, dot, unicode, case) → onto the SAME account?
- [ ] Does signup set an auth cookie for the account created from the (abused) email?

For forgot-password / reset:
- [ ] Is the reset link token **server-bound** to the account it was issued for?
- [ ] Does the reset-complete request derive the target from the token, or from a
      client `email`/`userId` param (swap → victim)?
- [ ] Is the token **forgeable** (reversible/base64, no signature) from
      user-controlled fields (userID, email)?
- [ ] Is the token **reusable** (works without a fresh mail) and low-entropy
      (sequential userID) → brute-force?
- [ ] Is the token single-use + expired after first reset / after time?

For action / verification links (email/phone/username change, 2FA-disable confirm):
- [ ] Is the verification link **bound to the requesting account + session**, or does
      it apply to whatever account clicks it (or a client-supplied id)?
- [ ] Open the attacker's verification link while logged in as the victim → does the
      victim's email/phone change? (confused-deputy ATO)

For all:
- [ ] Can you confirm access (login as victim with the new/created password)?
- [ ] Only use OWN victim + attacker test accounts; never target real users.

## Reporting
- Classify as **Account Takeover** (CWE-640 / CWE-287 / CWE-522 / CWE-302). Critical
  to High depending on account value (no 2FA = Critical).
- Per sub-class, the root cause + fix:
  1. Normalize/validate email server-side (reject separators, compare on canonical
     form) before uniqueness + creation, and require real email verification.
  2. Derive the reset target **only from the server-issued token**, never from a
     client identity param.
  3. Sign the token (HMAC) or use random unguessable tokens; never reversible
     `{id,email}` encodings.
  4. Make tokens high-entropy random, single-use, time-limited, and bound to the
     issuing account.
  5. For action/verification links: bind the action to the **requesting session +
     account** (the token must carry/reference WHO requested it and only apply to
     that principal), so a link issued to A cannot update B's email/phone.
- Include the exact before/after requests and the confirmation you got access.

## Gotchas
- If the server enforces email verification (must click a link in a real mailbox),
  the signup bypass may not yield a usable session — but a broken existence check is
  still a finding (enables account enumeration / potential ATO if verification is
  skippable). Report that.
- Always confirm the token is actually consumed/validated server-side; a forged token
  that loads the page but rejects the write is not ATO.
- Brute-force responsibly: stay well within rate limits on your own test account;
  cap the ID range to a small controlled window.
