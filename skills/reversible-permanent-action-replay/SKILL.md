---
name: reversible-permanent-action-replay
description: Replay of a previously-authorized, 'permanent'/'irreversible' state-changing action to undo or re-apply it -> improper authorization / state confusion. When an app marks an action irreversible (project/account/domain transfer, email change, ownership change, close-out) but the token/request is NOT invalidated after first use and the backend doesn't re-validate the CURRENT state/ownership, an attacker can capture that one-time request (e.g. POST /api/0/accept-transfer/ with a signed data blob) and REUSE it later to reclaim control even after the action was supposed to be permanent. Root cause: no one-time/token-revocation or state-validation on replay. Triggers on: replay accept-transfer/accept-invite/ownership-change to undo permanence, reuse a one-time authorized request, transfer back then reclaim, irreversible action not actually irreversible, missing state validation on replay.
---

# Replay a "Permanent/Irreversible" Authorized Action → State Confusion / Improper Authz

When an app promises an action is **permanent and cannot be undone** (project/account
transfer, ownership change, domain or email move, closure), but the back-edge that
performs it uses a **reusable token/request** and does **not re-validate the current
state**, an attacker can capture the sanctioned request and **replay it later to
re-trigger the action** — effectively un-doing the "permanence."

## The pattern (worked example: project transfer)

1. Victim (A) transfers a project to Attacker (B); B **accepts** and **captures** the
   `POST /api/0/accept-transfer/` request (body carries a signed `data` blob with
   actor_id/from_org/project_id/user_id/transaction_id + a signature).
2. B later transfers the project **back to A**; A accepts, regaining ownership —
   the transfer is "done" and supposedly permanent.
3. **B re-sends the previously captured `accept-transfer/` request** (the same signed
   `data` blob).
4. The backend accepts it **again** (token not invalidated after first use, ownership
   not re-checked) → B **reclaims the project** even though it now belongs to A.

Result: a "permanent" transfer is reversible by replaying a captured authorized
request → unauthorized access/control + data manipulation.

## Why it works (the missing controls)

- The transfer token/request is **not single-use** — after one accept it should be
  revoked/consumed, but it isn't (the signed `data` stays valid).
- The backend **does not validate the CURRENT state** — it acts on the token's
  embedded ids without confirming the project's present owner / that a transfer is
  still pending for that exact transaction.
- "One-time / irreversible" actions are implemented as replayable idempotent writes.

## Reusable checklist

1. **Find state-affecting "one-time/permanent" actions**: project/account/org
   transfer, ownership/role change, domain/email move, invite-accept, close-out,
   key/SSO handover.
2. **Capture the authorized request** that finalizes the action (e.g. the signed
   `accept-transfer` data blob, an `action=accept` mutation, a confirmation POST).
3. **Complete a full cycle** (A→B accept, then B→A accept) and, afterward, **replay
   the captured B-accept request** against the now-A-owned project.
4. **Check the backend's response**: if it accepts again and the ownership flips back
   to B → the "permanent" transfer is not enforced on replay.
5. **Vary the replay**: re-run immediately and after the owner changed; try replaying
   the token against the same / a related object; check if the signed blob's
   transaction is validated against the DB's live transfer record.
6. Confirm impact (regained access + ability to read/modify the project), then clean
   up (return ownership). Use two OWN test accounts.

## Reporting
- Classify as **Improper Authorization / state confusion / missing one-time-token
  revocation** (CWE-862 / CWE-345 / CWE-424 / CWE-794). Severity by what the replayed
  action unlocks (project/data control) — here it was meaningful but handled as a
  targeted finding.
- Include: the captured `accept-transfer/` request + signed `data`, the full
  transfer-back cycle, and the replay that reclaims ownership despite the "permanent"
  promise.
- Root cause: the irreversible action is not truly single-use (token not revoked /
  not state-validated on replay). Fix: consume/invalidate the transfer token after
  one accept, bind it to the live transaction + current owner, and re-validate the
  current state on every execution (reject if the proposed transfer no longer
  matches the DB).

## Gotchas
- If the token is bound to a single-use DB transaction, replay fails cleanly (400/404)
  — that's the secure case; step back.
- Some apps require the action to be "pending"; if the backend checks the project's
  owner equals the blob's actor at execution, replay won't flip it. Confirm by
  actually observing the ownership change on replay.
- Only use your own two accounts and restore ownership after the PoC. Never replay
  against real users' projects.
