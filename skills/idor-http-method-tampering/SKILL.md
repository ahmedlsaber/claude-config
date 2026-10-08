---
name: idor-http-method-tampering
description: IDOR (Insecure Direct Object Reference) combined with HTTP method/verb tampering. When an endpoint exposes a parameterized object ID (e.g. ?id=197) and access-control is tied to a specific HTTP method, change BOTH the object ID and the HTTP method (e.g. PUT -> GET, or POST -> GET/DELETE) to bypass the authorization check and read/modify another user's object. Classic: editInvite?undefined&id=197 is blocked (insufficient permissions) on PUT, but a GET on id=196 returns the victim's full PII (name/email). Covers enumerating sequential object IDs, verb-switching to skip a method-scoped ACL, and reading cross-user resources. Triggers on: IDOR, insecure direct object reference, change id parameter to access another user, HTTP method tampering, GET request bypass on PUT endpoint, access other user's invite/profile/data by id.
---

# IDOR + HTTP Method (Verb) Tampering

An **IDOR** is when an endpoint trusts a client-supplied object identifier (a user
id, invite id, file id, order id) without verifying the caller is authorized to
access THAT object. Classic: replace `?id=197` with `?id=196` and read another
user's data.

The high-value twist here: **the authorization is often tied to a specific HTTP
method.** A `PUT`/`POST` (the "edit/write" form the UI uses) enforces ownership /
permission, but the same resource id exposed via a **different verb** (e.g. `GET`,
or `DELETE`) has no such check. So you can **change both the id and the method** to
bypass the ACL and reach another user's object.

## The worked example

1. Create two accounts; set up a group and an invite so you understand the model.
2. In the UI, the invited-member flow has an **"Edit Invite"** action that calls:
   ```
   https://business.example.com/editInvite?undefined&id=197
   ```
   (a PUT / update style request against your own invite id 197).
3. Change the id to another user's (`id=196`) and try the same (PUT) request →
   **403 "you do not have sufficient permissions"** (ownership check fires).
4. **Change the request method from PUT to GET**, keep `id=196`:
   ```
   GET /editInvite?undefined&id=196
   ```
   → **200 with the victim's full data** (name, surname, email).
   The read/GET handler looks the object up by id and returns it with **no
   ownership check**, while the write/PUT handler had the ACL.

Result: an IDOR that is only reachable by switching verbs — a low/medium effort but
very common bypass.

## Methodical checklist

For every parameterized object endpoint (`?id=`, `/resource/{id}`, `/invites/{id}`
…):

1. **Enumerate the object space** — the id is usually a sequential integer (try
   `id±1`) or a guessable UUID. Confirm you can reference a foreign object id.
2. **Test each HTTP method** on the same path+id:
   - `GET` (read/leak)
   - `PUT` / `PATCH` / `POST` (modify)
   - `DELETE` (remove)
   - `OPTIONS`, `HEAD` (may reveal or bypass)
3. **Method-scoped ACL**: the UI path (e.g. PUT) is authorized, but a different verb
   on the same resource is not. Switch verbs and re-test the foreign id.
4. Check authorization at the **object** level, not just "is the user logged in":
   does the handler verify the object belongs to the caller's workspace/user?

Combine with:
- **Sequential iteration** (id ±1, ±N) to sweep other users' objects.
- **Verb-based routes** (path parsing): some frameworks/PROXY treat
  `/resource/{id}` and `/resource/{id}/` (trailing slash) or different case
  differently; also try method-override headers (`X-HTTP-Method-Override: GET`,
  `_method=GET`) if the app honors them.

## Reusable cases / where this appears
- Invite/edit flows (`/invites/{id}`, `editInvite?id=`) — read a foreign invite's
  PII.
- User/org profile resources (`/user/{id}`, `/profile?id=`) — read another user's
  PII / details.
- Order, invoice, message, attachment, file ids by sequential integer.
- Admin-only GET endpoints reachable by a low-priv user via the same id.

## Reporting
- Classify as **IDOR / Broken Object Level Authorization (BOLA)** — CWE-639/CWE-862.
- Impact: read (PII leak) and/or modify/delete another user's objects — severity by
  data sensitivity (PII = medium+, full account/object control = high).
- Include the exact requests: the blocked `PUT ?id=196` (403) and the succeeding
  `GET ?id=196` (200 with victim data), proving the idowner check is method-scoped.
- Root cause: the read handler fails to enforce object ownership (only the write
  handler checked it), and object ids are enumerable.
- Fix: enforce authorization per-object on EVERY method/verb (centralized authz),
  not just the UI's primary verb.

## Gotchas
- Confirm the foreign-id response actually corresponds to a **different** user's
  object (not a graceful 200 with an empty/self object).
- Ownership may be enforced only on certain verbs — test all verbs + method-override.
- Only test on your own two test accounts (A reads B's object) — never real users;
  don't dump a large id range (abort on third-party data).
- Clean up any created groups/invites after confirming.
