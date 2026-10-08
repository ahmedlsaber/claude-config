---
name: idor-methodology
description: Master IDOR (Insecure Direct Object Reference / BOLA) hunting methodology that links every IDOR sub-class into one repeatable process, plus the advanced write/impersonation primitives. Covers: find id-keyed endpoints, check read vs write methods (204/No-Content write + GET read), pagination/enumeration params (size/page vs id), hashed/encoded IDs (decode, handle id+hash pairs where the hash is only checked on read), write-on-behalf-of via authorId/team[user]id, auth-header (base64 user:id) tampering to full account takeover, and cross-feature reuse (approvers, groups, posts, tickets). Tips: don't ignore hashed/encoded IDs, try different HTTP methods, analyze request+response, brute different endpoints. Cross-references the specialized skills: idor-http-method-tampering, tamperable-identity-cookie, locked-object-idor-bypass, js-hidden-endpoint-mass-pii, role-subjects-membership-bypass. Triggers on IDOR, BOLA, broken object-level access, access another user's data by id, account takeover via user_id param, pagination enumeration.
---

# IDOR / BOLA — Master Methodology

A repeatable process covering every IDOR sub-class. "IDOR is cold" because it's
easy — but there is always surface (write endpoints, pagination params, encoded
ids, cross-feature reuse) others skipped. Combine these primitives, then chain to
impersonation / ATO for real impact.

Cross-reference the specialized skills: `idor-http-method-tampering`,
`tamperable-identity-cookie`, `locked-object-idor-bypass`,
`js-hidden-endpoint-mass-pii`, `role-subjects-membership-bypass`.

## The process

1. **Find id-keyed endpoints.** Any object id in the path, body, or query
   (user_id, authorId, team[0][user][id], request_id, group_id, ticket id, post id,
   approver id). Map where each is READ and where it is WRITTEN.

2. **Read vs. write method asymmetry — the 204 trick (Bug 1).**
   A write to a foreign id returns **204 No Content** (success, but no body to
   confirm — easy to dismiss). Don't stop there:
   - Replay the SAME foreign-id request with a **GET** → `204` becomes the **full PII
     response**. The write path silently accepted the id; the read path leaks the row.
   - Rule: treat every **204/silent-success** on a foreign id as a lead, then switch
     methods to confirm/exfiltrate.

3. **Pagination / enumeration params when id is hard to get (Bug 2).**
   When `/api/account` returns your own data with no exposed id, try sibling paths
   and query params:
   ```
   /api/user   /api/users   ->  maybe one user
   /api/users?page=1&size=1 ->  works! increment size/page -> different users' PII
   ```
   Common params: `page`, `offset`, `limit`, `size`, `cursor`, `per_page`, `id_min`,
   `id_max`, `start`, `end`. One paginated list = mass enumeration.

4. **Hashed / encoded IDs — Decode, then find the id behind the hash (Bugs 4 & 5).**
   - **Base64 id:** decode; if it's `{id}:{id}` or `{id},{email}` etc. and used as a
     token/auth value, tamper it (see below).
   - **id + hash pair** (e.g. `/Issue/9085/855f5bb...`): the hash is tied to the id
     **for the READ URL**, but the **mutation endpoints often take the bare id** and
     DON'T validate the hash. Change `9085` → `9084` on the **comment/close/upload**
     write → works on other tickets even though the read URL hash blocked it.
   - Tip: **don't ignore hashed/encoded IDs** — the hash usually protects only one
     surface (read), not the writes.

5. **Write-on-behalf-of (impersonation) via author fields (Bug 3).**
   Create/edit/delete endpoints often let you supply WHO the actor is:
   - `authorId`, `user_id`, `team[0][user][id]`, `createdBy`, `ownerId`, `author`.
   - Set it to another user's id (e.g. an admin) → the object is created/owned/
     editable as that user. Full impersonation of a privileged account for that
     resource. This is a write IDOR → object-impersonation.

6. **Tamper the identity carrier (auth header / cookie) → ATO (Bug 5).**
   When the write says "User not authenticated" even with a tampered `user_id` in the
   body, look at HOW auth is carried — a **Base64 auth header** may embed the userId:
   ```
   Authorization: ... ODIxMjIyODY6ODIxMjIyODY=   ->  decode: 82122286:82122286
   change to victim: 82122285:82122285  ->  base64  ODIxMjIyODU6ODIxMjIyODU=
   ```
   Re-send → request succeeds as the victim. Then change the victim's email and reset
   their password → **account takeover**. (See `tamperable-identity-cookie`.)

7. **Cross-feature reuse.** If one feature is vulnerable, the same id-keyed pattern
   is usually present across: users, groups, approvers, posts, tickets, comments,
   invitations, files. Re-test the same primitive on each.

## The tips (constantly re-apply)
- **Don't ignore hashed/encoded IDs** — decode them; the hash rarely guards every
  surface.
- **Try different request methods** — a 204 write is a read/PII waiting to happen.
- **Analyze the request AND response** — response codes (204 vs 404 vs 403 vs 200)
  are the oracle for whether a foreign id "worked".
- **Try different endpoints / brute-force them** — sibling routes (`/api/user`,
  `/api/users`, `/api/account`) and pagination params.

## Impact ladder
read-only IDOR (PII) < paginated mass PII < write-on-behalf (impersonation) <
tampered auth → email change → password reset = **full ATO**.

## Reporting
- Classify as **BOLA / IDOR** (CWE-639/284/862); severity scales with what you can
  do (read PII vs. write vs. ATO) and how many users (pagination → mass).
- Include the exact requests: the silent-success (204) write on a foreign id vs. the
  GET returning PII; the id+hash READ block vs. the bare-id WRITE success; the base64
  auth-header before/after.
- Root cause: object access not scoped to the authenticated principal on ALL
  surfaces (write paths, paginated lists, encoded-id paths). Fix: per-object/per-row
  authorization everywhere, server-bound session (not client `user_id`), validate
  hashes on writes too.
- Note authorization scope: use own + 2nd-account test ids; never target real users;
  don't mass-dump PII.

## Gotchas
- A foreign-id **write** may return 200/204 while doing nothing (no-op) — verify by
  reading back, or by observing a side effect (owner/author changed, comment appears
  on the other ticket).
- If the encoded id is **signed/HMAC'd**, tampering invalidates it — move on; not
  every base64 token is the bug.
- Only pull enough to prove impact; stop on third-party data; clean up created
  objects/tickets afterward.
