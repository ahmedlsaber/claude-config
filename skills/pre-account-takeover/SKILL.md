---
name: pre-account-takeover
description: Pre-Account Takeover (Pre-ATO) — register/take an account under a victim's identity BEFORE they do, so that when the victim later registers/logs in, the attacker keeps working access. Vectors: (1) register the victim's email before them (if existence check can be bypassed), (2) mass-assign a password onto an account under the victim's email, (3) exploit a two-database (Store vs SSO) or 'migrate' flow so two passwords coexist for one account — attacker's old password still logs in alongside the victim's new one → concurrent full access. Confirmed Pre-ATO = attacker can still log in with their old password after the victim sets theirs. Triggers on: pre-register victim email, two passwords same account, pre-account takeover, register another user before them, migrate SSO two-password coexist, mass-assigned password + victim email.
---

# Pre-Account Takeover (Pre-ATO)

Take control of a victim's account **before** they create/register it, or set it up
so that after they register with their own credentials, **your credentials still
work too**. The definitive test: you register with `passwdAttacker`, victim later
registers the same account with `passwdVictim`, and **you can still log in with
`passwdAttacker`** → confirmed Pre-ATO (concurrent, full access).

## Why it matters vs. normal ATO
Normal ATO steals an existing account. Pre-ATO pre-claims an identity so that the
moment it exists (or in parallel), the attacker already has a working backdoor — and
often the legitimate user has no idea someone else has access.

## Vectors to build Pre-ATO

### 1 — Pre-register the victim's email (bypass the existence check)
If you can create an account whose email equals the victim's (and the "is this
email taken?" check is bypassable or absent):
- set a known `password` (via mass-assignment if the form doesn't allow it),
- the victim later can't take their own name, or if they can re-register, your old
  credential may still work.

### 2 — Mass-assigned password onto an account under the victim's email
A create-account request that accepts extra fields lets you set `password` while
submitting another user's (or an unregistered) email. (See `mass-assignment`.) Then
log in with that password.

### 3 — Two-database / "migrate" two-password coexist (the advanced case)
Some apps split identity across two stores (e.g. a **Store** DB and an **SSO**
DB) with a **migrate** feature:
- A user created in Store can be migrated to SSO → login works in both, using the
  Store-created password.
- When the victim later registers the same email in SSO natively, they set their
  own password — but because the migrated SSO account still holds the attacker's
  password (or the two stores aren't synchronized), **both passwords work**.
- Result: attacker + victim log in to the same account simultaneously with
  different passwords.

## Reusable checklist
1. **Map account creation + any account association/migrate flows** across all
   subdomains/identity stores (store.…, sso.…, login.…). Note the DB/flow each is on.
2. **Test creating an account with another / unregistered email** — can you pre-claim
   a victim identity? Does the existence check run on all code paths?
3. **Mass-assign a password** (and other fields) onto that account. (See
   `mass-assignment`.)
4. **Trigger the migrate/SSO flow** and see whether two IP ↔ password sets coexist.
5. The **confirmation test**: victim (your second account) registers the same email
   with a different password → try logging in with the attacker's old password. If it
   works → confirmed Pre-ATO. Then, additionally, log in as the victim normally and
   confirm full resource access from your account.

## Reporting
- Classify as **Pre-Account Takeover / broken authentication / improper authorization
  (hybrid)** (CWE-287 / CWE-639 / CWE-362). Pre-ATO that grants full/unchallenged
  land; access is High; critical if it reaches an internal/privileged identity.
- Include: the pre-registration/mass-assignment request, the migrate/2-DB flow, and
  the two-password proof (attacker logs in with an old password after the victim
  changed theirs), plus access to the victim's resources.
- Root cause: identity pre-claimability (weak existence/ownership check on email) +
  account/password not bound exclusively per identity (2 stores unsynchronized, or
  mass-assignable password). Fix: make email ownership a hard server-side check on
  every creation path, bind credentials to a single canonical identity store, and
  invalidate/at-test alternate credentials on password change/migrate.

## Gotchas
- The "two passwords coexist" must be proven (attacker old login still works after a
  change) — that's the ATO; a mere registration pre-claim may only be a Medium
  business-logic issue.
- Real victims' emails → do NOT pre-claim a real person; use a disposable email you
  control to represent the victim (two of your own accounts).
- Mind the WAF/scan-limit: do everything manually (as the author noted) to avoid
  IP blocks.
