---
name: quota-plan-limit-bypass
description: Quota / plan-limit / usage-limit bypass via (A) deferred-acceptance counting and (B) race conditions. (A) When a plan limits active members/profiles/seats but the counter only increments on a deferred event (e.g. invite acceptance, task completion), you can stage N pending items then finalize them all to exceed the paid limit — e.g. send 100 invite links then accept all, onboarding 100 members into a 3-seat team plan for free. (B) When a per-plan usage cap (e.g. 300 browser profiles) is enforced per-request without atomicity, fire concurrent create requests (Turbo Intruder / multiprocessing) to exceed the cap (306 > 300). Also covers: plan-gating bypass by calling the invite/paid-feature API directly with a no-plan session instead of going through the UI. Triggers on: invite more members than plan, exceed profile/seat/quota limit, race condition on usage cap, free/no-plan user calls paid API directly, plan entitlement bypass.
---

# Quota / Plan-Limit Bypass

Four-way pattern for turning pricing/usage limits into free or over-limit usage that
directly costs the company money. All of these are **business-logic** (not
scanner) bugs and recur across paid SaaS products.

## A — Deferred-acceptance counting (stage invites, then finalize)

Many plans cap **active** members/seats, but the counter only increments on a
*deferred* event (invite acceptance, not invitation creation). So you can stage an
unlimited number of pending items and finalize them all at once, exceeding the paid
limit for free.

Worked example (team plan = 3 members, +$32/user after):
1. Send invitation links to as many members as you want (e.g. 6, 10, 100) —
   **member count stays 0 / unchanged** because nobody has *accepted* yet.
2. Visit/accept all the invite links in sequence.
3. All members are added with **no overage charge** — 6+ members on a 3-seat plan.
4. Repeat to add 100 members → company loses $322 ($32 × ~real users beyond 3).

Pattern to test: does the plan's seat/usage counter increment on **create** (invite
sent, profile staged) or on **finalize** (accept/complete)? If the latter, stage-and-
finalize bypasses the cap.

## B — Race condition on a per-plan usage cap

When a per-plan limit (create N profiles / N requests / N uploads) is enforced
non-atomically, concurrent identical requests all pass their individual check and
exceed the total.

Worked example (solo plan = 300 profiles):
1. Create 298 profiles.
2. Capture the "create profile" request.
3. Replay it concurrently (Turbo Intruder with many threads, or a Python
   threading/multiprocessing script) at random payload positions.
4. Result: 306 profiles created (> 300 cap).

Each concurrent request sees count < 300 before committing → all succeed. Test
limits that on-touch increment without a lock/constraint.

## C — Plan-gating bypass via direct API (client-side gating)

The UI hides the paid feature (invite members, export, advanced tool) for a
no-plan / low-tier user, but the backend **API call itself is not authorized**.
Call the endpoint directly with your session → it succeeds (no forbidden).

Worked example:
1. Capture the `POST` invite-user request while on a paid plan.
2. Swap the Authorization token to a **no-plan** user's token (and the workspace ID).
3. Resend → **success**, user invited (should have been 403/Forbidden).

Pattern: find which features are gated *client-side* (a menu/button hidden) but
whose underlying endpoint has no server-side entitlement/plan check.

## D — Low-privilege read of paid/private workspace data (broken access control)

UI hides certain data (members, roles, invitations, balance, plan) from a
low-privilege role, but the API endpoints return it. Direct GET with the low-role
session leaks it.

Worked example — "User" role (no permission to see other members/plan) can GET:
```
GET /api/.../workspace/restrictions
GET /api/.../workspace/users?limit=100&offset=0
GET /api/.../workspace/invitations?limit=1000&offset=0
GET /api/.../workspace/user_balance
```
→ full member list, roles, invitations, balance, plan.

## E — Plus-addressing / email-alias free-trial farming

Email systems commonly deliver all plus-addressed variants to one inbox:
`mahmoud@example.com`, `mahmoud+1@example.com`, `mahmoud+2@example.com`. If the
application treats each raw string as a new identity, a subscription/free-trial
limit is per alias instead of per mailbox:

1. Register `mahmoud@example.com` → receive/verify → 13-day trial.
2. Register `mahmoud+1@example.com` → verification arrives at the same mailbox.
3. Verify → a fresh 13-day trial is granted to the alias account.
4. Repeat indefinitely, bypassing the trial/entitlement limit.

Test other canonicalization variants: case, dot placement (provider-dependent),
plus tags, Unicode normalization. The key proof is **same mailbox + fresh entitlement**
for each alias. Normalize the email (according to the provider's canonical rules)
before uniqueness/trial eligibility checks, or require stronger account/phone/payment
binding.

## F — Revocation/reactivation cycles bypass the cumulative member cap

A plan may count only **currently active** members. Revoking a member sets
`is_active:false` and decrements the counter, but the member remains in the database;
flipping `is_active:true` later reactivates them without re-counting or plan validation.
Combine with the seat cap:

1. Add the maximum allowed members (e.g. 2); revoke them → counter returns below cap.
2. Add two different members; revoke them too.
3. Repeat to accumulate many revoked members.
4. Replay/reactivate all revoked members concurrently or sequentially → all become
   active while the active-member counter/plan limit is bypassed.

This is different from the invite-accept race: it exploits **soft deletion + stale
quota accounting**. The fix is to enforce the cap on reactivation too and count active
members atomically against the plan.

## G — Non-expiring inventory reservation + limit race (ticket/seat/stock DoS)

Reservation systems hold scarce inventory while payment is completed. The hold must
expire automatically; otherwise an unpaid reservation becomes a permanent inventory
lock. Pair that with a race on the per-account reservation limit:

1. Reserve a seat/item without paying; wait past the advertised grace period (and
   past the event/start time) → if it remains reserved, the hold has no effective
   expiry.
2. A per-account cap is supposed to limit holds (e.g. 5 seats). Send multiple booking
   requests concurrently at the limit; if check-and-increment is non-atomic, more
   than 5 reservations succeed.
3. Chain: reserve N seats in parallel, then do not pay. Because holds never expire,
   the attacker locks a large portion of the stadium/stock indefinitely without
   paying, blocking genuine purchases and causing revenue/availability loss.

Test only owned test events/inventory and stop at a small proof count. The fix needs
expiry/cleanup for unpaid holds, payment-bound reservation state, atomic quota
checks, and an admin release/reconciliation path.

## Methodical checklist

1. **Map the limit** — what's capped (seats, profiles, requests, storage, trials,
   reservations, inventory) and at which tier/paywall.
2. **When does the counter/eligibility increment?** Create-time vs finalize-time
   (deferred acceptance), active-only vs cumulative, per raw email string, or
   reservation expiry. If finalize-time → stage-and-finalize; if active-only →
   revoke/reactivate cycle; if raw email → plus-address trial farming; if holds don't
   expire → inventory lock.
3. **Is the endpoint server-authorized?** Try the paid/invite/read API directly with
   a no-plan or low-role session → success = client-side gating / broken ACL.
4. **Is the cap atomic?** Fire N concurrent create/reactivate/reservation requests
   near the limit and count the result (> cap = race).
5. Confirm the **financial/entitlement/availability impact** (free overage, plan-less
   usage, unlimited trial, blocked tickets/seats/stock, private data leaked) — that's
   what makes it reportable.

## Reporting
- Classify per type: **business-logic (quota/entitlement bypass)** for A, C, and E,
  **race condition (improper atomicity)** for B, **broken access control** for D,
  **stale soft-delete/quota accounting** for F, and **inventory/availability DoS**
  for G.
- Quantify financial impact (free trials/members × price, excess profiles × price,
  blocked seats/tickets/stock × lost sales) — concrete cost/loss is persuasive.
- Capture exact requests + counter/state before/after (trial eligibility, active vs
  revoked, reservation expiry, member/profile count) and a small bounded proof.
- Fix: canonicalize email; enforce quotas on acceptance/reactivation atomically;
  server-side plan/role checks; expire unpaid holds and reconcile reservations with
  payment state.

## Gotchas
- If acceptance is not required (member added immediately on invite-send), the
  deferred-acceptance trick doesn't apply — the cap increments on send. Test which
  event triggers the counter.
- Race: ensure the limit is checked-and-incremented without a lock; if it holds a
  transaction/constraint, the race won't fire — move on.
- Email aliases differ by provider: plus-addressing is common, but dot normalization
  is provider-specific. Confirm verification lands in the same owned mailbox.
- Reactivation may be intentionally allowed for soft-deleted members; the bypass is
  only real if active usage exceeds the plan cap and the quota/accounting does not
  reconcile.
- Only use owned/no-plan test accounts, and clean up (remove added members, delete
  excess profiles, cancel trials) after confirming. Do not actually consume paid
  overage beyond a small PoC amount.
