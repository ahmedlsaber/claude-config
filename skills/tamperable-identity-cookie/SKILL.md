---
name: tamperable-identity-cookie
description: IDOR via a tamperable / weakly-encoded identity cookie or client-supplied identifier. Find the value the app uses to tie a session to an account — often a Base64 cookie or a client-supplied user id/userIdx — decode it, change the user id to another user's, re-encode/send, and read that user's PII (profile, order, messages). When the numeric id is sequential, this becomes mass PII disclosure (tens of thousands of users). Core primitive: the app trusts a client-controlled (encoded but not signed) identifier instead of a server-side session binding. Triggers on: base64 cookie with user id, change user id in cookie to access another account, tamperable session identifier, userIdx/usr id in cookie or request, /GetProfiledetails IDOR, mass account PII via weak identity token.
---

# IDOR via Tamperable Identity Cookie / Weak Session Identifier

The simplest mass-IDOR: the application identifies the logged-in account not by a
server-bound session, but by a **client-supplied value** — frequently a **Base64**
(or otherwise reversible, non-signed) **cookie** containing the user ID. Decode it,
change the user id, re-encode, and the server returns the other account's data.

## The core primitive

1. While browsing, find the request that returns YOUR data (e.g. `/GetProfiledetails`)
   and spot the **identity cookie** (often Base64-looking).
2. **Decode it** → it reveals plaintext fields including your **user id** (and maybe
   account type, inst id, etc.):
   ```
   decoded cookie ~> {"uid": <your_id>, ...}  or  "<your_id>:<something>"
   ```
3. This answers *how access control is implemented*: it trusts this client value,
   not a transcript-bound server session.
4. **Tamper**: change the id to another user's (e.g. `509070`), **re-encode** (Base64),
   send the same request with the modified cookie.
5. The server returns the **other user's PII** (profile, orders, messages).

Because the user id is a **sequential integer**, iterate ids → **mass PII**
(tens of thousands of accounts). No per-row authorization exists.

## Reusable checklist

1. **Decode every Base64-looking cookie/token** in your authenticated requests
   (cookie header, `Authorization`, body params). Look for raw user id / email /
   role fields.
2. **Ask how identity is bound**: is the session keyed to a server-side session id
   (opaque), or to a **client-visible/reversible identifier** (base64, unsigned
   JWT, `id:hash` without the hash being verified, a numeric cookie)? The latter is
   the bug.
3. **Tamper the identifier** to a different account's id (your own 2nd account first,
   then a low sequential id). Re-encode and resend.
4. **Confirm it's a real different account** (PII differs from yours) — proof of the
   IDOR.
5. **Assess mass/magnitude** — sequential ids → state it's enumerable for all N users
   (report the finding; only pull a few confirming records).
6. Also test the same tampering on:
   - other PII endpoints (profile, orders, messages, invoices, tickets) keyed by the
     same weak id
   - writing endpoints (update profile, mark-as-read) — may allow modify/delete,
     not just read (higher impact)
   - a **different role** (admin/customer ids) reachable by flipping a role field too.

## Reporting
- Classify as **IDOR / BOLA / broken session-identity binding** — CWE-639 / CWE-287 /
  CWE-345. Mass PII = High/Critical.
- Include: the request + the decoded cookie showing the user id, the tampered cookie
  (new id) returning a different account's PII, and the note that sequential ids make
  it mass-enumerable (50k users).
- Root cause: the server identifies the account from an **unsigned/weakly-encoded
  client value** instead of an opaque, server-bound session. The id param is
  enumerable and endpoint lacks per-row authz.
- Fix: use an opaque, random, server-side session id; never trust a client-supplied
  identifier for object access; enforce per-object authorization server-side; use
  non-guessable object ids or scope by the authenticated principal.

## Gotchas
- Not every Base64 cookie is tamperable — it may be **signed/HMAC'd** (tamper →
  invalid). Try ONE tampered value; if rejected as unauthorized/bad-signature →
  it's protected, move on.
- Even an unsigned id cookie that is only used for the *current* request may still
  be exploitable if the server reads the account from it — that's exactly the bug.
- Confirm the returned data belongs to a **different** account (distinct PII), using
  a low sequential id or your own 2nd account.
- Only enumerate a small bound to prove magnitude; never harvest a large volume of
  third-party PII.
