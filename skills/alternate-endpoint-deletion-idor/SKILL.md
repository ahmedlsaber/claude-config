---
name: alternate-endpoint-deletion-idor
description: Arbitrary user deletion via a hidden/alternate user-management endpoint discovered by comparing UI workflows (e.g. bulkPeopleUpdate vs bulkPeopleDelete). The app implements the same logical 'people management' action through two code paths — the visible UI calls a guarded bulk-update endpoint, while a sibling hidden/alternate endpoint (bulkPeopleDelete), reachable from an alternate UI path, a JS bundle, or a naming-convention guess, performs deletions with only a logged-in check and NO per-object authorization. Tampering the numeric user ID (userIds, people_ids, uids) deletes arbitrary users. Covers the authorized workflow, wildcard/subdomain mapping of the account/user-management surface, request diffing across UI paths, hidden endpoint/method differential testing (OPTIONS/Allow, verb swaps, naming variants), numeric-ID ownership checks, and SAFE validation with only two owned test accounts using reversible/non-destructive markers first (soft-delete/dry-run/response-differential) and a disposable owned account only for hard-delete proof. Explicitly warns: never delete third-party users, never send destructive requests outside authorization, and only run inside an authorized engagement. Triggers on bulkPeopleDelete, alternate user-management endpoint, delete user by numeric id, comparing requests from different UI paths, hidden admin/management endpoint, arbitrary user deletion, missing authorization on delete, IDOR on delete endpoint.
---

# Hidden/Alternate User-Management Endpoint → Arbitrary User Deletion

A platform exposes the **same logical "people management" action through two code
paths**. The visible UI path calls a guarded endpoint (bulk *update*), while a
**hidden/alternate sibling endpoint** (bulk *delete*) — reachable from an alternate
UI path, a JS bundle, or a naming-convention guess — performs the destructive
version with **only a logged-in check and no per-object authorization**. Tampering
the numeric user ID deletes **arbitrary users**. This is a High/Critical
Missing-Authorization / IDOR finding.

## ⚠️ Safety (read first)

- **Never delete third-party users.** All validation uses **only accounts you own**,
  even in an authorized scope. Report the vuln — don't demonstrate it on real data.
- **Never send destructive requests outside authorization.** If the engagement or
  scope does not explicitly cover this class of testing, stop at non-destructive
  proof (response differential, dry-run, soft-delete marker).
- **Do not test live targets** with this skill outside an explicit, in-scope
  authorization. Prefer reversible/non-destructive markers wherever possible; a hard
  delete is only ever run against a freshly-created, disposable owned account.
- Abort any step that would touch third-party data.

## The pattern (worked example: bulkPeopleUpdate vs bulkPeopleDelete)

1. A platform has a "people management" feature. The **visible UI path** (team
   settings / admin panel) performs bulk edits via
   `POST /api/org/{org_id}/people/bulkPeopleUpdate` with
   `{"userIds":[1001,1002],"fields":{...}}` — this endpoint **checks
   authorization** (caller must be an admin of `org_id`; target users must belong
   to it).
2. An **alternate UI path** (a back-office/legacy panel, a different role's UI, or a
   route found in JS) performs the same logical operation via a **sibling endpoint**
   `POST /api/org/{org_id}/people/bulkPeopleDelete` with `{"userIds":[...]}`.
3. **Comparing the two requests** (same action, different UI paths) shows the delete
   variant **only checks that you are logged in** — it never verifies the caller is
   an admin of the org, or that the target users belong to the caller's
   org/tenant.
4. Send `bulkPeopleDelete` with **another user's numeric ID** → server returns
   200/204 and that account is deleted → **arbitrary user deletion**.

## Why it works (the missing controls)

- **Duplicate/legacy code path**: "bulk people management" was implemented twice —
  the visible UI path got the authorization checks; the alternate path didn't.
- **Hidden surface**: the delete endpoint isn't linked in the main UI, so it escaped
  security review (legacy/back-office builds, staging clones).
- **Session check ≠ authorization**: the endpoint tests "logged in?" but not "can
  THIS caller delete THIS user?".
- **Numeric sequential ids** make targeting trivial (`userIds`, `people_ids`, `uids`).

## Reusable checklist

1. **Authorized workflow.** Confirm the host is in scope and the engagement covers
   this class. Owned test accounts only. Abort anything that would touch
   third-party data.

2. **Wildcard/subdomain mapping.** Map the account/user-management surface across
   `*.target.com`: admin/back-office/legacy hosts (`admin.`, `backoffice.`,
   `internal.`, `staff.`, `manage.`, `people.`, `org.`, `team.`, `crm.`, `ops.`),
   staging clones (often run unguarded builds), and API gateways. See
   `recon-methodology`.

3. **Account/user-management surface discovery.** Within each host, enumerate every
   endpoint that touches user/people/member records: JS bundle review (grep for
   `/people`, `bulkPeople`, `user_management`, `member`, `deleteUser`,
   `removeUser`), swagger/OpenAPI docs, OPTIONS/route maps, and the UI's own network
   tab. Flag numeric-id params. See `js-hidden-endpoint-mass-pii`.

4. **Compare requests from different UI paths.** Exercise the SAME logical action
   through every path that offers it (dashboard, team settings, admin panel, org
   switcher, API console, mobile web). Capture each request (method, path, body,
   headers) and **diff them**: same action, different endpoints → a guarded and an
   unguarded copy often coexist. `bulkPeopleUpdate` vs `bulkPeopleDelete` is the
   classic pair.

5. **Hidden endpoint/method differential testing.** For each discovered management
   endpoint: enumerate verbs (`OPTIONS` / `Allow` header), swap verbs
   (POST→DELETE, PUT→PATCH), and probe **naming variants** of guarded endpoints
   (Update→Delete/Remove/Disable/Destroy, Add→Remove, Enable→Disable, edit→delete).
   The unguarded variant frequently accepts the **same body shape** as the guarded
   one. See `idor-http-method-tampering`, `privilege-flag-verb-escalation`.

6. **Numeric ID ownership checks.** Send the candidate delete with **your own
   account's id** → confirm it works (authorized baseline). Then send it with your
   **second owned account's id** (different org/tenant if the app has tenants) →
   does it succeed even though account A has no authority over account B? Check
   whether the server validates that target users belong to the caller's org. Use
   the response-code differential as the oracle (200/204 vs 403/404).

7. **Safe validation — two owned accounts, reversible/non-destructive markers.**
   Never point a delete at a third-party user. Prefer, in order:
   - **Response differential only**: if the guarded path 403s on a foreign id and
     the unguarded path 200s, the authz-gap is proven — stop there if the delete
     itself would destroy anything you can't restore.
   - **Reversible markers**: prefer soft-delete/deactivate/disable variants,
     `dryRun`/`preview`/`validate` params, or a delete that emails a confirmation
     link (intercept at the confirmation step instead of completing it).
   - **Hard-delete proof (last resort)**: only against a **freshly-created,
     disposable owned account** you are prepared to sacrifice — never an account
     you need, never a third-party account even if in-scope. If the platform
     restores/recreates, do it and confirm restoration. Document the sacrificed
     account.
   - Clean up any test data you created.

8. **Impact classification.** Arbitrary deletion of any user account is **High to
   Critical**: permanent availability impact on the victim (account gone, data
   loss), trivially chained with user enumeration, and if admins/employees can be
   deleted → mass DoS / business disruption. Unauthenticated (no session required)
   → Critical. CVSS anchor: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` ≈ 6.5–7.1 (High),
   rising to ~9.1 (Critical) for admin-account deletion or no-auth.

## Reporting

- Classify as **Missing Authorization / IDOR on a delete endpoint** — primary
  **CWE-862** (Missing Authorization), with **CWE-639** (Authorization Bypass
  Through User-Controlled Key) and **CWE-284** (Improper Access Control).
- Evidence to include: the two UI paths; the guarded request vs the unguarded
  request (the diff); the numeric-id tampering (own id → second owned account's
  id); the response differential; and the confirmation that the affected account
  was owned and restored/disposable.
- Root cause: the same logical operation is implemented in two endpoints and the
  authorization check was not applied to the alternate one; deletion endpoints
  lack per-object/tenant checks.
- State explicitly: validation used only owned accounts; no third-party data was
  touched; destructive actions were limited to a disposable owned account or a
  non-destructive marker.

## Remediation

- **One implementation, one check**: route every "people management" action through
  a single authorized service; remove hidden/duplicate endpoints or re-point them
  at the same authorization path.
- **Server-side per-object authorization**: the caller must hold the required role
  over the tenant/org the target user belongs to; never trust client-supplied org
  membership.
- **Non-enumerable identifiers** (UUIDs) or server-side id scoping; reject ids
  outside the caller's tenant.
- **Harden the delete itself**: confirmation token/step, soft-delete with restore,
  audit log, rate limit, idempotency keys; treat account deletion as a privileged,
  reversible-by-default operation.

## CWE mapping

| CWE ID | Title |
| ------ | ----- |
| CWE-862 | Missing Authorization |
| CWE-639 | Authorization Bypass Through User-Controlled Key |
| CWE-284 | Improper Access Control |

## Related skills

- `js-hidden-endpoint-mass-pii` — hidden/management endpoint discovery via JS
- `idor-methodology` — master IDOR/BOLA methodology
- `idor-http-method-tampering` — verb/method differential on id-keyed endpoints
- `privilege-flag-verb-escalation` — OPTIONS/Allow verb discovery
- `internal-domain-signup-privilege` — internal/back-office subdomain abuse
- `recon-methodology` — wildcard/subdomain mapping
- `unauth-id-pii-and-archive-id-harvest` — enumerable-id harvesting
- `reversible-permanent-action-replay` — restoring state after a proof

## Gotchas

- A delete endpoint may return 200/204 but be a **no-op** (soft-delete flag
  ignored, or a second confirm step required) — verify the account is actually gone
  (login fails / GET returns 404 / admin list no longer shows it) and restore it.
- Some "hidden" endpoints only work with an admin cookie — the bug may be that
  **any admin of any org** can delete users of **other orgs** (cross-tenant), not
  that any logged-in user can. Both are reportable; classify precisely.
- Don't assume the guarded endpoint is the "real" one — the alternate path is
  usually the **legacy/back-office copy** that missed the authz refactor.
- If ids are **UUIDs**, tampering still works when the endpoint skips the ownership
  check — the numeric-id detail is an enumeration convenience, not a requirement.
- A confirmation/email step on deletes is a soft gate: if you can suppress or race
  it, that's part of the finding.
- Only use owned accounts; never delete a third-party user, even in an authorized
  scope.