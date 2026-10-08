---
name: client-generated-hmac-token-forgery
description: "Client-side hardcoded HMAC secret used to generate server-trusted sdToken values, with a predictable time bucket and client-supplied userId/deviceId, enabling forged authentication, privilege escalation, and support-ticket access. The frontend ships the HMAC key (readable from JS/source maps/web assets), and the server accepts any sdToken whose HMAC verifies — so an attacker reconstructs the exact input (userId, deviceId, time bucket), signs it locally, and mints a valid token for any account, including admin/support-impersonation tokens. Covers the authorized workflow: subdomain/source/JS discovery, secret detection and decoding, recognizing client-generated auth signatures, reconstructing token input/canonicalization and time windows, safe verification only with owned accounts or explicit authorization, non-destructive read-only proof (never mint admin/third-party tokens), impact assessment, evidence/reporting, and remediation (server-side signing, opaque sessions/JWT with secure claims, no client secrets, nonce/replay protection, authorization per resource). Triggers on hardcoded HMAC secret in JS, sdToken generated client-side, predictable time bucket token, client-supplied userId/deviceId in token input, forge auth token from frontend key, HMAC key in source map, support ticket token forgery, mint sdToken locally, client-side token signing."
---

# Client-Generated HMAC Token (sdToken) Forgery

The application authenticates/authorizes requests with a **signature token
(`sdToken`-style)** that is **generated inside the browser** using an **HMAC
secret hardcoded in the client**. The signing input is built from **client-
supplied fields** — typically `userId`, `deviceId`, and a **predictable time
bucket** (minute/hour/day floor, no randomness) — with no server-issued nonce.
Because the server only verifies that the HMAC is valid (and does not bind the
token to a server-side session, random challenge, or fresh timestamp), anyone
who extracts the key from the public frontend can **reconstruct the input,
sign it locally, and mint a valid token for any userId they choose** — including
admin or support-impersonation identities → forged authentication, privilege
escalation, and access to support-ticket workflows.

## ⚠️ Safety (read first)

- **Do not test live targets** with this skill outside an explicit, in-scope
  authorization. This is an analysis/verification methodology, not a weaponizer.
- **Safe verification only with owned accounts or explicit authorization.**
  All validation uses only accounts you own, even in an authorized scope.
- **Non-destructive read-only proof only.** Prove token acceptance against a
  read-only endpoint with a token minted for your OWN account.
- **Never generate admin/third-party tokens.** Do not mint sdTokens for admin,
  support, or any account you do not own — even "just to prove" the impact.
  Describe the escalation in the report; demonstrate it on owned accounts.
- Abort any step that would touch third-party data.

## The pattern (worked example)

1. A JS bundle (or source map / config asset) contains a **hardcoded HMAC
   secret** — a Base64/hex constant that sits next to token/sign helpers:
   ```javascript
   const SDK_KEY = "a3J5cHRvLXNlY3JldC1kb250LXNoaXAtbWU=";   // base64 of a key
   function buildSdToken(userId, deviceId, ts) {
     const bucket = Math.floor(ts / 60000);                    // 1-minute bucket
     const input  = [userId, deviceId, bucket].join(":");
     return CryptoJS.HmacSHA256(input, SDK_KEY).toString();
   }
   ```
2. The app calls `buildSdToken(...)` on page load / before each API call and
   sends the result (e.g. `sdToken` header, `token` query param, or in the
   JSON body) alongside plaintext `userId` / `deviceId`.
3. The server receives the token, **recomputes or verifies the HMAC with the
   same key**, and — finding it valid — **trusts the accompanying userId** to
   establish the session identity / grant access.
4. Attacker reads the public JS, extracts `SDK_KEY`, and for **any userId**
   computes a valid `sdToken` for the **current time bucket**:
   ```text
   sdToken(userId=X, deviceId=anything, bucket=floor(now/60000))
   ```
   → the server authenticates as user X. With `userId` of an admin or support
   agent → privilege escalation; with a ticket id tied to another user →
   support-ticket access.

## Why it works (the missing controls)

- **Secret in the client = public.** Anything shipped to the browser is
  retrievable by anyone; an HMAC key used for *signing* must never live there.
- **Signature covers only client-supplied fields.** No server-issued nonce,
  random challenge, or session binding is part of the signed input.
- **Predictable time bucket ≠ freshness.** The "expiry" is a coarse, computable
  window (and often the server accepts a wide/bucketed range), so tokens can be
  pre-computed and replayed within the window — no live oracle needed.
- **Server trusts the token for identity.** The token (or its accompanying
  client-supplied userId) *is* the authentication/authorization decision
  instead of an opaque server-bound session; resources are then keyed to that
  client-chosen identity with no per-resource re-check.

## Reusable checklist (authorized workflow)

1. **Authorized workflow.** Confirm the host is in scope and the engagement
   covers this class. Owned test accounts only. Abort anything that would touch
   third-party data.

2. **Subdomain/source/JS discovery.** Enumerate the frontend surface first:
   `*.target.com` hosts, CDN/static origins, staging clones (often ship debug
   bundles), and API gateways. See `recon-methodology`. Collect every JS bundle,
   source map (`.map`), inline script, `runtime-config`, and manifest.

3. **Secret detection and decoding.** Grep collected assets for
   `sdToken|sign|token|hmac|secret|key|cipher|encrypt|auth` plus Base64/hex
   constant patterns. Decode candidate strings; look for an ASCII/hex key of
   plausible length near a signing function. Confirm the key is actually *used
   for signing* (symmetric HMAC), not a public key for verification.

4. **Recognize client-generated auth signatures.** Trace how the token is
   built and where it is sent: find the function that concatenates inputs and
   calls `HmacSHA256`/`HmacSHA1`/`createHmac`/`sign`, note the output placement
   (header/query/body), and diff the token across requests to identify which
   parts change (time bucket) and which are constant.

5. **Reconstruct token input/canonicalization.** Determine the exact input
   list (`userId`, `deviceId`, timestamp/bucket), their **order**, separator
   (`:`, `|`, `,`, empty concat), encoding (raw/Base64/hex), and the algorithm
   (HMAC-SHA256 vs SHA1 vs MD5). Validate your reconstruction against tokens
   your OWN account already received.

6. **Reconstruct time windows.** Determine the bucket granularity (seconds /
   minutes / hours / day-start) and the reference clock (epoch floor vs local
   day). Confirm how wide a window the server tolerates (pre-compute a few
   buckets around `now`).

7. **Safe verification — owned accounts only.** Re-implement the signing
   function locally and mint an sdToken for **your own account** (your real
   `userId`); call a **read-only** endpoint that accepts it. 2xx + your own
   data = forged-token acceptance proven. Optionally repeat with your **second
   owned account** to show the token carries identity (still both owned).

8. **Non-destructive read-only proof.** Never mint admin/third-party tokens,
   never attempt to read another user's tickets or PII, never mutate state with
   a forged token. Impact is demonstrated by (a) token acceptance for an owned
   account and (b) the *reconstruction* — the key is in public JS and the input
   is fully client-controlled, so any userId is reachable.

9. **Impact assessment.** Forged authentication for any account (mass ATO);
   privilege escalation if admin/support userIds are enumerable/known
   (employee email → userId, role fields in the token, support-agent ids);
   support-ticket access if tickets are keyed by a client-supplied id the
   forged token unlocks. Replay window = bucket size if no nonce. Unauthenticated
   forging → Critical. CVSS anchor: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1
   (Critical) for full impersonation without credentials; lower if a valid
   deviceId/session is also required.

10. **Evidence and reporting.** Keep the redacted secret, the signing-function
    snippet (with the key masked), your reconstruction, the owned-account
    acceptance request/response, and the time-bucket demonstration. State
    explicitly: only owned accounts were used; no admin/third-party token was
    ever generated.

## Reporting

- Classify as **hardcoded cryptographic key + improper authentication /
  insufficient authenticity verification** — primary **CWE-321** (Use of
  Hard-coded Cryptographic Key) and **CWE-798** (Use of Hard-coded Credentials),
  with **CWE-287** (Improper Authentication), **CWE-345** (Insufficient
  Verification of Data Authenticity), **CWE-294** (Authentication Bypass by
  Capture-replay), and **CWE-862** (Missing Authorization).
- Evidence to include: where the key ships (JS/source-map asset path), the
  redacted key, the token-construction code, your local reconstruction script,
  the owned-account forged-token acceptance, and the time-bucket/replay
  analysis.
- Root cause: the signing secret is shipped to the client and the server treats
  a client-computable HMAC over client-supplied identity fields as proof of
  identity; no server nonce, session binding, or per-resource authorization.
- State explicitly: validation used only owned accounts; no admin/third-party
  token was generated; no third-party data was touched.

## Remediation

- **Server-side signing only.** Never ship the signing key (or any shared
  secret used for authentication) to the client. The browser should send
  credentials to the server; the server mints tokens.
- **Opaque sessions or JWTs with secure claims.** Replace client-computed
  tokens with opaque server-bound session ids, or JWTs signed server-side with
  `sub`/`aud`/`exp`/`iss`/`tenant` claims validated on every request — never
  with identity fields the client chose.
- **No client secrets.** Anything in JS is public: rotate/revoke the leaked key
  immediately and invalidate all tokens previously issued with it (removing it
  from JS alone is insufficient — copies persist in caches/history/bundles).
- **Nonce/replay protection.** Add a server-issued random challenge or
  single-use nonce to the signed input; enforce strict freshness (reject
  expired/non-current tokens) and one-time use; bind tokens to the session/device.
- **Authorization per resource.** Even with a valid token, the server must
  re-check the authenticated principal against the requested resource
  (support ticket, user profile, admin action) — never derive authorization
  solely from client-supplied identity claims.

## CWE mapping

| CWE ID | Title |
| ------ | ----- |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-287 | Improper Authentication |
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-294 | Authentication Bypass by Capture-replay |
| CWE-862 | Missing Authorization |

## Related skills

- `hardcoded-client-bearer-token-api-access` — secrets/creds shipped in client assets
- `tamperable-identity-cookie` — server trusting a client-controlled identifier
- `multi-tenant-token-isolation` — JWT claim/identity validation flaws
- `oauth-security` — token issuance/validation and JWT algorithm confusion
- `insecure-parameter-state-flag` — client-controlled state trusted by the server
- `privilege-flag-verb-escalation` — privilege escalation via client-supplied identity/role
- `js-hidden-endpoint-mass-pii` — JS-bundle discovery of endpoints and secrets
- `recon-methodology` — subdomain/source surface mapping

## Gotchas

- The "secret" may be obfuscated (packed, encoded, split across constants) —
  decode/deobfuscate before assuming it's unusable; also check source maps and
  `runtime-config` for the unminified original.
- Confirm it is a **symmetric signing key**, not a public verification key: a
  public key can't forge; a hardcoded HMAC/secret key can.
- The time reference may be **server-relative** (server-issued `ts` echoed in
  the response) rather than client `Date.now()` — find where the bucket value
  comes from before reconstructing.
- The token may need a **valid `deviceId`** that is registered server-side —
  forge only the parts you control and pair an owned device id.
- The server may still validate `userId` against the session for *some*
  endpoints — check whether the token alone authenticates or merely carries
  identity claims; the bug is wherever the token is trusted as identity.
- Try adjacent **buckets** if the server tolerates clock skew; if a token works
  across many buckets, the replay window is that much larger (higher impact).
- Only ever demonstrate with your own accounts — minting a token for an admin
  or a third party, even as "proof", escalates you from tester to attacker.

## Checklist

- [ ] Scope + authorization confirmed; owned accounts only; no live testing outside scope
- [ ] Frontend surface enumerated (subdomains, CDN, staging, gateways)
- [ ] JS/source maps scraped and grep'd for token/sign/secret/key patterns
- [ ] Candidate key decoded and confirmed as a symmetric HMAC signing key
- [ ] Token generation traced: inputs, order, separator, encoding, algorithm
- [ ] Time-bucket granularity and reference clock reconstructed
- [ ] Local re-implementation verified against OWN account's real tokens
- [ ] Forged token accepted by a read-only endpoint for an OWNED account
- [ ] No admin/third-party token generated; no third-party data touched
- [ ] Impact, CWE mapping, and remediation documented in the report