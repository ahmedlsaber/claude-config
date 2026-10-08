---
name: locked-object-idor-bypass
description: Bypassing feature/state locks via IDOR on your OWN objects. When a server state-locks some of your resources (e.g. a free plan allows 3 lists and locks the 4th+: it cannot be renamed, edited, shared), the 'manage' endpoints (rename/edit/share) usually take a client-supplied object id (bookmark_id). Even though the locked object belongs to YOU, the backend only enforces the lock at the UI layer (or only for 'new management' flows) and trusts the reference-id on an allowed object. Take a request for an UNLOCKED object (rename/edit/share), swap the object-id (bookmark_id) with the LOCKED object's id -> the operation succeeds on the locked object (rename, add icon, share the locked list). Bypasses plan/feature limits and locked-state restrictions. Distinct from cross-user IDOR: here both resources are the attacker's; the flaw is that locked-state/entitlement restrictions are not enforced on the id-reference endpoints. Triggers on: rename/edit/share a LOCKED list/listitem/object by swapping its id, bypass free-plan 3-list lock, locked-state restriction bypass, own-object IDOR, feature-gating bypass via object id.
---

# Locked-Object IDOR Bypass (L-BOLA on your own state-limited resources)

A feature/state-lock on a resource is enforced at the **UI** (or only on the
"create/new" path), but the **manage endpoints (rename / edit / share / configure)**
take a client-supplied object id and look the object up **without re-checking the
locked state / entitlement**. So you can act on a **locked** resource — even your
own — by submitting the operation through the id of an **unlocked** (allowed) one.

This is IDOR (broken object-level / state-level authorization) but on the *attacker's
own* objects, crossing a **locked/entitlement boundary** rather than a user boundary.

## The worked example

Setup (free plan): you can have 3 active lists; a 4th+ list is **locked** (can't be
managed/renamed/shared/edited — only deleted).

1. Create lists; the site displays a "you can only have 3" message and locks the
   excess lists. Confirm via UI that the locked list can't be renamed/edited/shared.
2. In the UI an **unlocked** list's management request (rename) carries the object id:
   ```
   <manage-request> bookmark_id=<unlocked_list_id>   # allowed
   ```
3. Copy the locked list's `bookmark_id` (from DevTools / the list URL `/lists/<id>`).
4. Intercept the unlocked list's management request and **replace `bookmark_id` with
   the locked list's id**:
   ```
   <manage-request> bookmark_id=<LOCKED_list_id>     # returns success!
   ```
5. Result: you **renamed the locked list, added an icon, and shared it** — actions
   the UI blocks for a locked list. Sharing also works because the app puts the
   `bookmark_id` directly in the URL path (`/lists/<bookmarkID>`), so others can open
   the locked list via that path.

All IDs in the scenario are your own — the flaw is that the **locked-state check is
not enforced on the id-reference manage endpoints**.

## The core pattern (reusable)

Ask: **is a server-enforced feature/state lock (plan/entitlement/quota/only-3/
locked-item) actually checked on the MUTATION, or only reflected in the UI?**

For any allowed operation that references an object by id:
1. Find an operation the UI allows (rename/edit/share/config) on an **allowed** or
   **unlocked** object.
2. Take that exact request and **swap the object-id** for a **locked / disallowed /
   over-quota / premium-gated** object of yours.
3. If it succeeds on the locked/restricted object → locked-state/entitlement bypass.

Applies broadly:
- **Plan/quota locks**: free-tier caps (N active lists/items/docs/seats) where
  over-limit resources are "locked" but a manage endpoint trusts the id.
- **Premium feature gating**: actions reserved for paid accounts, enforced only in
  the UI, bypassable by referencing a premium object via a free object's request.
- **Approval/pending states**: "pending/needs-approval" objects that pass through
  review can be edited/shipped anyway by id-reference.
- **Read-only / archived / frozen state**: archived docs/accounts/items that are
  "frozen" but still writable via their id on an allowed-object request.

## Methodical checklist

1. Map the **feature/state lock** and which operations it blocks in the UI
   (rename, edit, share, delete, configure).
2. Capture each operation's request and note the **object-id field** and where it
   goes (body, URL path, query).
3. For the locked/restricted object, obtain its id (URL path, DevTools DOM, a
   sibling read call).
4. Replay the allowed-object request, **swap in the locked object's id**, and check
   whether the restricted operation now succeeds.
5. Verify the change **persists** (reload the locked object — renamed/edited/shared)
   — that's the proof it bypassed the lock, not a client no-op.
6. Check whether the lock is re-applied if you directly reference the locked id
   with the *normal* operation (sanity: UI blocks it; only the id-swap path succeeds).

## Reporting
- Classify as **IDOR / Broken Object Level Authorization**, or a **business-logic /
  entitlement-bypass** (bypassing plan/feature/state locks). If it leaks or exposes
  locked/premium resources to sharing, note that impact (e.g. sharing locked lists
  publicly or cross-user).
- Impact angle: bypassing a paid/plan restriction or a locked/approved state to
  perform disallowed actions (and possibly expose them to others via a shareable
  id-path).
- Include the exact request + the before/after: the UI-blocked operation on the
  locked id, vs the id-swapped request succeeding; show the locked object's state
  changed (renamed/edited/shared persists).
- Root cause: the manage endpoints enforce per-object authorization/gating only on
  some paths or not at all; the locked/entitlement state is not checked server-side
  on mutation. Fix: enforce the locked-state/entitlement check server-side on every
  mutation, keyed by the actual target object, not the client-supplied id of the
  referring object.
- Note even though both IDs were the attacker's, the violation is the ability to act
  on a locked/premium-gated resource (broken feature/entitlement boundary).

## Gotchas
- The id may be a UUID that appears in the list URL path — easy to copy and swap.
- Ensure the operation actually **changes** the target (persist + reload), not just
  returns 200 on a no-op.
- Only use your own over-quota / locked test objects; never target other users' data.
- Clean up (delete the locked/residual lists) after confirming.
