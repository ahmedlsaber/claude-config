---
name: oauth-misconfiguration
description: OAuth-based account takeover via misconfigurations in the login/signup-with (Facebook/Google/Apple/Twitter) flow. Primary primitives: (1) the OAuth callback trusts client-supplied identity parameters (email, name, id) instead of the verified identity from the IdP — tamper the email/name in the callback to register/login as the victim (account takeover); (2) state-parameter CSRF / login-CSRF (attacker logs into victim's account by completing OAuth in their own browser); (3) redirect_uri / host tampering; (4) account-linking confusion (email-based matching links attacker IdP account to victim's pre-existing account); (5) missing/weak scope or token validation (reuse another user's access code, accept a code with a mismatched audience). Covers the OAuth dance and where in it the trust boundary breaks. Triggers on: login/register with Facebook/Google/Apple, change email in OAuth callback to victim, OAuth account takeover, state parameter CSRF, redirect_uri tampering, account linking by email.
---

# OAuth Misconfiguration → Account Takeover

When a site offers "Continue with Facebook/Google/Apple/Twitter", the login/register
dance has a trust boundary: the app must derive identity from the **IdP-verified**
data, not from anything the attacker can manipulate. Find where that boundary breaks
and you can register/login **as anyone**.

## The OAuth dance (know where the boundary is)

1. App redirects browser → IdP (google.com).
2. User picks an account; IdP verifies credentials.
3. IdP sends a `code`/token back to the **app's callback** endpoint.
4. App **trades the code for the user's identity** (name, email, id) and logs/registers.

Step 3–4 is where the bug lives: the callback receives the code, and the app
translates it into a user. If the app **trusts parameters it put in its own body**
(email, name) instead of the IdP's verified token response, an attacker controls whose
account is created/logged into.

## Primary primitive — tampered identity in the callback (the ATO)

Intercept the **OAuth callback** request (the one that carries the code and tells the
app "create/log me in") and modify the **email / name / id** parameters:

- Original: `email=<my_email>&name=<my_name>&code=<real_code>`
- Modified: `email=victim@gmail.com&name=Hacked Account&code=<real_code>`

If the app adds the user to its DB using **these client-supplied fields** (not the
IdP-verified identity) and doesn't validate them:
- You register a NEW account with the **victim's email** → account creation on the
  victim's identity (defacement/impersonation), or
- If the app matches by email → you **log into the victim's existing account**
  (full account takeover).

Confirm by logging in / resetting the password on the new/compromised email.

## The broader OAuth test set (run each)

1. **Tamper callback identity params** (email, name, id) — the ATO above.
2. **State / login-CSRF**: the OAuth request must carry a `state` param (a CSRF token
   bound to step 1). If `state` is missing/weak, an attacker can:
   - complete OAuth in their OWN browser with their IdP account,
   - feed the resulting callback to the victim (e.g. via a link),
   - the victim's browser, already logged-in-user-session, consumes the callback and
     "links" the victim's account to the attacker's IdP account → attacker later logs
     in as the victim.
3. **redirect_uri / host tampering**: the app must validate `redirect_uri`/`redirect_uri`
   whitelist. If not, point it at an attacker host to receive the code/state and use it.
4. **Account linking by email**: if the login matches an existing account by the
   IdP email alone (without verifying it's the same person), the "login with X"
   links an attacker's new IdP identity to a victim's existing account.
5. **Token/code validation**: does the app verify the code's `aud`/`iss`/`client_id`
   and nonce? A code meant for a different client/relyer shouldn't be accepted.

## Reusable checklist

1. Test **every** auth function: form login/register, each OAuth provider, and the
   password reset (+ OAuth-linked accounts).
2. For each OAuth flow, **intercept the callback** and enumerate every parameter
   (email, name, id, code, state, redirect_uri).
3. **Modify identity params** (email→victim) and note whether a new/compromised
   account is created/logged in.
4. Test **state presence + binding**, **redirect_uri validation**, and **email-based
   account linking**.
5. Confirm ATO: set/reset password on the victim's email and log in.

## Reporting
- Classify as **broken authentication / account takeover / improper authorization**
  (CWE-287 / CWE-384 / CWE-352). Mass ATO = Critical/High.
- Include: the OAuth callback request before/after, the successful "created/logged in"
  response on the victim's email, and (for the state/CSRF variant) the two-browser PoC.
- Root cause: the app derives identity from **client-controllable** callback params
  / a missing `state` binding / an unvalidated `redirect_uri`, instead of the
  IdP-verified subject and a CSRF-protected flow.
- Fix: derive the account only from the IdP-verified subject (id + email from the
  validated token); enforce a random `state` param bound to the session; whitelist and
  verify `redirect_uri`; never link accounts by email alone without a prior verify.

## Gotchas
- Some flows send the identity in a SEPARATE exchange (server-side code→token) where
  the front-end params are decorative — test whether the email/name you set actually
  changed the created user (prove it by logging in / changing password), else it may
  be a no-op.
- The **state/login-CSRF** and **email-linking** variants often need two accounts
  + two browsers; have them ready.
- Only use your own + a victim test account you own; never target real users' emails.
