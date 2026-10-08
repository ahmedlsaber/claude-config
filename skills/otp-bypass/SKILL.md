---
name: otp-bypass
description: One-time-password (OTP) bypass methods for account takeover / verifying protected actions. Covers (1) response manipulation - capture the server's success response to a correct OTP, then submit a random/wrong OTP but splice/replay the captured success response (or modify the response boolean) so the client/server thinks verification passed; (2) client-side flag disable - OTP check gated by a storage/param flag (is_otp_enabled:false in localStorage or a request param) -> flip it; (3) OTP brute-force/weak OTP (short length, no rate limit, no attempt cap); (4) predictable/static OTP; (5) reponse-body tampering of the verify result (false->true, error->success); (6) missing server-side re-validation (OTP check only on one step). Trigger on OTP bypass, response manipulation OTP, is_otp_enabled false, 4/6 digit OTP brute force, forgot-password OTP, appointment/onboarding OTP verification bypass.
---

# OTP Bypass — methods & test set

One-time-password flows guard password reset, account actions, onboarding, and
appointment/transaction verification. When the OTP check is weak, it enables full
account takeover or a protected-action bypass. Test every method; they differ in
root cause.

## Method 1 — Response manipulation (replay / splice the success response)

The flow: request OTP → submit OTP → server returns a "correct/verified" response →
client proceeds to the next step (change password, complete booking).

The bypass:
1. On YOUR account, request a password reset → you get the real OTP → submit the
   **correct** OTP and **capture the success response** (body, or just the status +
   next-step fields).
2. On the VICTIM's account, request a reset → an OTP goes to the victim (you don't
   know it).
3. Submit a **random/wrong OTP** (e.g. `1111`) and, in Burp, **replace the response
   with the captured correct-OTP success response** (response body manipulation), or
   forward a modified response `{"success":true,...}`.
4. If the server takes the client's response state at face value (no server-side
   re-check of the token/step), the flow proceeds "as verified" → you can reset the
   victim's password → **account takeover**.

Key: the server must not independently re-validate the OTP/token on the final step;
it trusts the response carried forward (or trusts the client-supplied "verified"
state).

## Method 2 — Client-side flag / storage disable

If the OTP step is gated by a **client-stored or client-param flag**, flip it:

- `localStorage` / `sessionStorage` / cookie: set `is_otp_enabled: false`.
- A request/response param: `is_otp_enabled` → `false`, or remove a `requiresOtp`
  field.
- Refresh and the OTP verification step is skipped; the app proceeds with the
  unverified email/phone.

(Common on onboarding/appointment flows that "verify" an email/phone but only check
the flag client-side.)

## Method 3 — OTP brute-force / weak implementation

- Very short OTP (4 digits = 10k combos) with **no rate limit and no attempt cap**.
- Brute-force the OTP in a loop (Turbo Intruder / script); a missing lockout or
  per-IP/per-session attempt limit means it cracks.
- Note: a 6-digit OTP with no rate limit is also brute-forceable (1M guesses) if the
  endpoint doesn't throttle.

## Method 4 — Predictable / static / re-usable OTP

- Server generates a **fixed/guessable** OTP or leaks it in the response (some
  debug/development builds return the OTP in the API response).
- OTP not single-use: the same OTP works for multiple attempts/accounts; or it
  doesn't expire.
- OTP tied to the wrong session: try another user's/session's OTP.

## Method 5 — Response/body tampering of the verify result

Even without a captured "correct" response: submit any request and **change the
verify result** in the response (`verified:false` → `true`, `success:false` →
`true`, error→success, or change the redirect target). If the front-end only acts
on the (modified) response and the backend doesn't enforce, you pass the step.

## Method 6 — Missing server-side re-validation (one-step-only)

The OTP check happens on the "verify" endpoint, but the **follow-up action** (change
password, complete signup) doesn't re-check that an OTP was validated (no state/flag
server-side). Skip straight to the final action endpoint → it proceeds.

## Method 7 — JWT/access token issued BEFORE the OTP; drop the OTP step

A serious 2FA bypass: the server mints an **access token (JWT) in the OTP-verify
request's Authorization header BEFORE it validates the OTP** (or the token is already
valid for authenticated endpoints regardless of the OTP result).

Flow:
1. Log in with valid credentials → app prompts for 2FA OTP.
2. Capture the OTP-verify request (`POST /api/verify-otp`) — it carries
   `Authorization: Bearer <JWT>` in the header, generated before OTP validation.
3. **Drop the request** (or replay the JWT directly against other endpoints).
4. Use that JWT against `/api/...` endpoints (enumerate with GAP/Intruder, send the
   bearer token) → **all authenticated endpoints, incl. sensitive ones (payment,
   profile, orders), are accessible WITHOUT completing the OTP.**

Root cause: the access token is issued before/in addition to the 2FA check, and the
API does not require proof that the session passed OTP. The JWT is "valid for
authenticated endpoints" even though 2FA was never confirmed.

### Retest after the fix — browser forcing / direct navigation
After a patch, most endpoints may redirect unauthenticated requests to the OTP page.
**Re-test carefully**, because a fix is often incomplete:
- **Browser-force**: navigate directly to each sensitive endpoint by URL
  (`/payment/order`, `/payment/order/transection`) instead of through the UI flow.
- Some endpoints were re-gated but one (often a payment/order route) was missed →
  still accessible without OTP = another report (incomplete fix).

<br/>

## Reusable checklist

1. **Map the OTP flow** end-to-end (request, verify, final action) and which endpoint
   actually holds the "verified" state.
2. **Test response manipulation** (Method 1/5): capture the success response, change
   `success`/`verified`/error fields or +splice into the wrong-OTP submit.
3. **Test the client gate** (Method 2): inspect storage + params for `otp_enabled` /
   `is_otp_enabled` / `requiresOtp` / `needVerify`, flip or remove them.
4. **Test brute-force** (Method 3): enumerate the OTP space; note attempt caps/rate
   limits and time-windows.
5. **Test predictability** (Method 4): same OTP reuse, OTP in response, static OTP.
6. **Test the final action's server-side state** (Method 6): can you reach the
   post-OTP action without a valid verification?
7. **Test the pre-issued token** (Method 7): capture the OTP-verify request and check
   whether the Authorization JWT is usable against other endpoints WITHOUT completing
   the OTP — drop the request / replay the token (enumerate endpoints with GAP/Intruder).
8. **Retest after a fix** — browser-force each sensitive endpoint by direct URL to
   find any route the patch missed.
9. Confirm impact on the victim (password change / booking / account) using **own**
   test accounts; clean up.

## Reporting
- Classify as **broken authentication / improper access control / logic flaw**
  (CWE-287 / CWE-307 / CWE-352). Account takeover = Critical/High.
- Include: the exact OTP flow requests, the wrong-OTP + tampered/replayed response
  that "passed", and proof the victim's action (password change / onboarding)
  succeeded.
- Root cause per method: server trusts client-supplied response/state or a client
  storage flag; no attempt/rate limiting; static/re-usable OTP; missing server-side
  re-validation on the final step; or an **access token minted before the OTP is
  validated** (Method 7).
- Fix: re-validate the OTP/token server-side on the final action (single source of
  truth), never trust a client flag or response, enforce attempt caps + rate limits +
  expiry + single-use, generate high-entropy random OTPs, bind the verified state to
  the session server-side, and **never issue/accept a usable access token before the
  2FA check passes** (tie API auth to post-OTP verification on EVERY endpoint).

## Gotchas
- Response manipulation only works if the app trusts client-side state; if the server
  re-checks, it fails — verify by reaching the post-OTP action.
- Brute-force responsibly: stay under rate limits, use a small window on your own
  account.
- Always use own test accounts; never read/use a real OTP from a third party.
