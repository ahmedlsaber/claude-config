---
name: insecure-parameter-state-flag
description: Bypass a verification / approval / visibility workflow by adding or flipping a boolean STATE FLAG in the request (e.g. activated:true, for_student_verification:true, isVisible:true, verified:true, approved:true, isActive:true). When a resource must be verified/approved/activated by a human or email step, but the backend derives that status from a client-supplied boolean/flag in the create/update payload, an attacker can set it to true (or add the missing flag) to mark the item verified/visible/approved without completing the intended process. Two worked examples: (A) email-verification bypass - add-extra-mail request carries 'activated' and 'for student verification' booleans, set both true -> the unverified extra mail becomes primary; (B) study/approval bypass - custom 'study' input carries isVisible:false by default, add isVisible:true -> unapproved study info appears (and effectively gets approved) on the profile. Triggers on: activated/isVisible/verified/approved flag true, bypass mail/study/verification via parameter, add boolean to request, insecure parameter, make unverified item visible/primary/approved.
---

# Insecure Parameter / State-Flag Bypass (verification, approval, visibility)

Many apps enforce "must be verified / approved / activated" for a resource, but the
backend reads that final status from a **client-supplied boolean flag** in the
create/update payload instead of computing it server-side. Add it or flip it to
`true` and the item is treated as verified/visible/approved without the intended
step.

## The primitive

A field that should require verification/approval (an extra email, custom study
info, a document, a comment, a profile section) is submitted with state booleans the
client controls. Default is `false`; set them to `true`:
```json
// add-extra-mail request
{ "email": "x@example.com", "activated": true, "for_student_verification": true }
```
or append a missing flag:
```json
{ "study": "admin", ... , "isVisible": true }
```
Result: the unverified/unj~e~not-yet-approved item becomes verified / visible /
primary / approved, bypassing the intended confirmation.

## Two worked examples

### A — Email (extra→primary) verification bypass
1. The app lets a user add an **extra mail**, but converting it to **primary mail**
   normally requires a **verification code** sent to that extra mail.
2. Add the email; intercept the request — it carries booleans like `activated` and
   `for_student_verification`, both `false` (or unset).
3. Set both to `true` and submit.
4. Back in the UI, the email shows a "verified" tick; clicking it moves the extra
   mail to primary — the old primary becomes extra. **Verification bypassed.**

### B — Custom study / info approval bypass
1. Users add custom **study** info that must be **verified + approved by management**
   (not visible until approved).
2. Send the add-study request; the response shows `isVisible:false` (it is hidden).
3. Resubmit adding `isVisible:true` to the request.
4. The unapproved study info **appears directly on the profile** (and is effectively
   approved) — content the management should have vetted first.

## Reusable checklist
1. For every create/update that feeds a **verification/approval/visibility** concept
   (email/phone verify, custom-field approval, document upload, profile section,
   comment moderation, publish/activate a listing):
   - Intercept and read the response for **state fields** (`activated`, `verified`,
     `isVisible`, `isActive`, `approved`, `enabled`, `is_*`, `needsApproval`,
     `status`, `state`).
   - Submit with those flags set to `true` (or add the missing `true` flag) and see
     if the item becomes verified/visible/approved server-side.
2. Also test `false→true` on: publish/activate, make-default/primary, make-public,
   bypass-timeout, and moderation-marker flags.
3. Confirm the state actually persists and the UI reflects it (tick/visible), proving
   the bypass is real (not just a cosmetic response).
4. Check the same primitive on the **stud-den key path**: the "make primary",
   "publish", or "show on profile" action may itself accept the flag.

## Reporting
- Classify as **improper access control / missing server-side validation / business
  logic flag-trust** (CWE-284 / CWE-863 / CWE-20). Minor individually, but the
  ability to bypass verification/approval/visibility is real.
- Include: the request with the default `false`, the modified request with
  `activated:true` / `isVisible:true` / etc., and proof in the UI that the item is
  now verified/visible/approved/primary.
- Root cause: the server reads verification/approval/visibility state from
  client-supplied booleans instead of enforcing the process server-side. Fix:
  derive these states server-side from the actual verification/approval workflow;
  ignore or reject client-sent state flags; enforce on read + write.

## Gotchas
- If the backend ignores the client flag and re-derives status (verification
  actually checked), setting `true` is a no-op — confirm the UI shows the change
  (tick / visible / primary).
- Some items become visible but are still "pending" in the DB; check whether the
  action (make primary / publish / approve) actually honors the flag end-to-end.
- Only use your own accounts; undo the change (delete/remove the activated email or
  the fake study) after the PoC.
