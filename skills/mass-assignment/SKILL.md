---
name: mass-assignment
description: Mass-assignment / mass parameter injection vulnerability testing. Endpoints that bind request fields onto an object/DB row WITHOUT an allowlist accept extra/hidden fields (password, role, isAdmin, verified, email, isPro, state flags, id, token, provider...). High-impact sub-cases: (1) zero-click ATO via reset-token overwrite, (2) whole-app DoS via oversized numeric id (1e9 -> float -> broken lookups), (3) delete/overwrite another user's object by assigning an existing victim id, (4) privilege escalation / block admin actions (provider/type/2FA), (5) UI-hidden restricted field via KEY-SUBSTITUTION (swap genderIdentity->email in a profile update to change email with NO verification -> register/claim any email / identity takeover; pivot UI-locked fields to backend-writable). Testing: Param Miner + manual copy-of-response-params + key/pivot substitution. Combine with pre-account-takeover, insecure-parameter-state-flag, privilege-flag-verb-escalation. Triggers on mass assignment, add password/id/token/email to request, zero-click ATO token overwrite, oversized id DoS, delete another user's object via id, block admin deactivate/2FA, change email via key substitution, bypass email verification through profile update.
---

# Mass Assignment / Mass Parameter Injection

A framework "binds" request fields onto an object / DB row using reflection on the
field names, with **no allowlist of permitted fields**. If you send an extra field
the UI doesn't expose (or the developer names things by a discoverable convention),
it gets assigned too. That lets you set fields you should never control directly —
`password`, `role`, `isAdmin`, `verified`, `isPro`, `activated`, `email`,
`isVisible`, `approved`, timestamps.

## How to find it

1. **Identify binder endpoints** (create/update that map JSON/form to a model):
   user/account creation, profile update, document/entity create. Developer-heavy
   stacks (Rails strong-params without permit list, Spring @ModelAttribute, ASP.NET
   model binding, frameworks that auto-map) are prime.
2. **Send extra fields** — add keys the UI doesn't send and mirror the object's
   real fields:
   - `password` / `password_hash` / `role` / `isAdmin` / `is_staff` / `employee`
   - `verified` / `activated` / `approved` / `isVisible` / `isPro` / `plan` / `tier`
   - `email` / `username` / `createdAt` / `id`
3. **Guess the naming convention** from observed habits/other endpoints: camelCase,
   snake_case, `is_`/`is` prefixes, `type`, `sso_type`, etc. Try both case styles.
4. **Confirm assignment**: re-read the resource — does the extra field persist and
   take effect (password usable at login, verified tick, role change, email changed)?

## Real examples
- **Create-account with a password**: the UI "create an account by name" request
  silently accepts an extra `password` field → you set the password for an account
  you create under another/any user's email.
- **Flop a state flag**: add `verified:true`, `isVisible:true`, `approved:true`,
  `activated:true` → bypass verification/approval/visibility (see also
  `insecure-parameter-state-flag`).
- **Role/entitlement**: set `role:admin` / `isPro:true` → privilege/bypass (see
  `privilege-flag-verb-escalation`, `client-side-feature-gating`).

## The `id`-overwrite & value sub-cases (highest impact)

Beyond flags/password, mass-assigning **`id` and other identity fields** has four
distinct, critical variations:

### 1 — Zero-click ATO: reset-token overwrite
Inject an `id` (or token field) into a **blind action** like the password-reset
request so your fake token/code overwrites the legitimate one:
```
POST /resources/auth/resetPasswordLink   { ... , "id": "<victim_id>", "token": "<fake>" }
```
The system accepts the injected fake token as valid → you can reset the victim's
password with **no victim interaction** (zero-click ATO). No response needed = a
"blind action"; verify by using the fake token to actually reset.

### 2 — Whole-app DoS via oversized `id`
Send an **abnormally large numeric id** (`1e9`, `1e99999`, a huge integer like
`2111111111112147483647`). If the backend coerces to floating point / stores it
(`2.111e+21`), every **ID comparison/lookup breaks** → user creation, invites, and
most user operations fail application-wide (DoS).

### 3 — Delete/overwrite another user's object (Entity-Integrity violation)
Creating a new object but **assigning an existing victim's `id`** (in the request)
makes the DB **overwrite/deletes** the victim's row (e.g. their client list) with
your new object — unauthorized deletion / data destruction of other users' objects.
This is a primary-key uniqueness violation the app fails to guard.

### 4 — Privilege escalation / block admin actions
Mass-assign fields like `provider` / `type` (or `2FA`, `totp`, `active`) on your
own profile so that admin actions **fail** — e.g. injecting fake `provider`/`type`
prevents the org owner from **deactivating your account or resetting your 2FA**
(you become hard to remove / revoke). Note "endpoint inconsistency": it may work on
one endpoint (profile) and not another (`/organization/members`).

### 5 — UI-hidden restricted field via key substitution (email-verification bypass)
The profile/update endpoint for benign fields (gender, height, name) binds any
key/value the client sends. Even though the **UI doesn't allow** changing a
sensitive field (email, username), the backend **binds it anyway**. Swap the key of
any editable field for a sensitive one:
```
# normal: { "genderIdentity": "x" }
# attacked: { "email": "victim@other.com" }
```
The email (or username) is updated **without any verification**. Consequences:
- **Register/claim any email** — set your account's email to a victim's, gaining
  their identity on the platform / enabling pre-ATO.
- **Bypass the email-change verification** the UI enforces (the backend never
  re-checks on this update path).
- Unlike other `id`/token sub-cases, this one is just a **key rename** in an
  otherwise-allowed request — very easy to miss yet often High (email/identity
  takeover).

## How to test effectively
- **Automated**: Param Miner (Burp) guesses hidden parameters — good for discovery,
  but it can **miss blind actions** (no visible response clue).
- **Manual (gold standard)**: copy every parameter reflected in the response and
  send it back with the request — this catches blind mass-assignment (e.g.
  password-reset token overwrite) that automated scans miss. Endpoints may mass-
  assign on some routes and not others — test each.
- **Key substitution / pivot**: take a request that updates a benign field and swap
  its **key** for a sensitive one the UI hides (`genderIdentity` → `email`,
  `height` → `username`, `name` → `role`). The backend often binds it with no extra
  validation/protection. Also check the pivot "if a field is UI-locked, is it still
  backend-writable?" — many apps gate the UI but not the API.

## Reusable checklist
1. List the object's fields (from responses, other endpoints, JS) so you know what
   to try.
2. Add each candidate field to the create/update body and observe whether it
   persists / takes effect server-side.
3. Especially test: `id`, `email`, `password`, `role`, `admin`, `verified`,
   `approved`, `active`, `visible`, `isOwner`, `plan`, `type`, `sso_type`, `provider`,
   `token`.
4. **Blind-action check**: for requests with no visible response (reset, invite,
   notification), send the response's parameters back manually and verify via a side
   effect (e.g. use the injected token to reset, or check the recipient got your ID).
5. **Oversized-value test**: send huge ints/`1e9` in numeric/id fields and confirm
   the stored/compared value breaks behavior.
6. Combine: mass-assigned `password` + another user's/any email → pre-ATO; flag
   flips → privilege escalation (link those skills).
7. Use own test accounts; revert the assigned field after confirming.

## Reporting
- Classify as **mass assignment / improper validation** (CWE-915). Severity depends
  on the field you can set: `password`/`email`/`role`/`verified`/`id`/`token` →
  High/account-takeover-grade; cosmetic flags → Medium. Oversized-id → DoS;
  id-overwrite → unauthorized deletion (data destruction).
- Include the request with the extra field, the re-read proving it persisted, and
  the resulting impact (login with chosen password, verified/primary/visible, admin,
  reset via fake token, deleted victim object, blocked admin action, app-wide break).
- Root cause: object binding without an allowlist (or a too-permissive permit list),
  no type/length/range validation on numeric ids, and no entity-integrity handling.
  Fix: use an explicit allowlist of bindable fields (strong params / @JsonIgnore /
  DTOs), never bind `password`/`role`/`verified`/`id`/`token` from the client,
  validate authorization on any sensitive field, range-check numeric / id inputs,
  and protect primary keys from client supply.

## Gotchas
- Some binders ignore unknown fields silently — only a real assignment counts
  (prove it via re-read / a side effect).
- Sending `id` may create/overwrite a different record or fail with a constraint —
  be careful; test on a throwaway ID (or your own object) first, and prefer your own
  second account over a real victim's row.
- Huge-int ids can **break the app or your own session** — use a small controlled
  value and confirm impact, then clean up / restore the affected row.
- Only mass-assign on your own accounts; never touch another real user's record.
