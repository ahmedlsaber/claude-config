---
name: case-sensitivity-bypass
description: Case-sensitivity / input-normalization bypass. Change the case of a value (email, username, domain, extension, key) to skip a case-sensitive validation or deny check, then have the downstream system (which treats it case-insensitively) process it anyway. Classic uses: invite/downgrade a higher-privilege user who is protected by a deny-rule, bypass 'you can't modify a role with higher privileges' / duplicate / ownership checks, bypass email allowlists/denylists, OAuth redirect_uri host matching, JWT/issuer checks, file-extension filters. Triggers on: email case 'test@gmail.com' vs 'test@gmail.coM', role downgrade of an Owner/Admin, invite protection bypass, case-insensitive downstream vs case-sensitive guard.
---

# Case-Sensitivity / Input-Normalization Bypass

A validation or access-control check compares values **case-sensitively** (or via a
case-sensitive denylist), but the downstream system that acts on the value treats it
**case-insensitively** (emails, usernames, domains). Feed the same value in a
different case (e.g. change the last letter of an email to uppercase) to dodge the
guard while still reaching the real account.

```
test@gmail.com  (protected Owner - deny rule fires)
test@gmail.coM  (case changed - deny rule misses it, invite/role-change succeeds)
→ the real Owner (test@gmail.com) receives the invite, accepts, and gets downgraded
```

This works because many validators forget to normalize case before comparing, while
email/identity resolution is case-insensitive by design.

## The worked example (role downgrade / lockout)

1. **Owner** creates an org and invites users with roles (Super Admin, Admin).
2. As **Administrator**, you (per the product) *cannot* delete or modify roles of
   accounts with **higher privileges** (the Owner) — a rule like "can't invite /
   downgrade the Owner" fires.
3. Try to invite the Owner as **View Only** → error ("can't invite/change this user's role").
4. **There is a <8-bit-permission and <8> bypass:** change the last letter of the
   Owner's email to uppercase: `owner@gmail.com` → `owner@gmail.coM`. Invite
   succeeds (the deny check is case-sensitive and no longer matches).
5. Owner accepts the invitation → **their role is set to View Only**.
6. **Impact:** the org Owner can no longer act — can't invite/remove members, can't
   access admin functions — **locked out of their own team**. (And the case-twisted
   email may even create a duplicate/confused account identity.)

## Reusable pattern (methodical)

For every guard that compares an identifier (email, username, domain, host, ext):

Try changing **case only** (letters), in positions:
- Appending/uppercasing the **last character**: `gmail.com` → `gmail.coM`
- Uppercasing a **letter in the local part**: `test` → `Test` / `tEst`
- Uppercasing a letter in the **domain**: `gmail` → `Gmail`
Then verify the downstream action still resolved to the SAME real account.

Other normalization tricks alongside case (chain them):
- trailing dot in domain: `gmail.com` → `gmail.com.`
- extra `+tag`: `user+1@gmail.com` (many allow/deny lists miss it but Gmail ignores `+`)
- dots in local part: `user.name` vs `username` (Gmail ignores dots)
- percent-encoding in URL params / OAuth: `%40`, doubled-encoding
- Unicode lookalikes / full-width letters
- leading/trailing whitespace, `\t`, `\n`, `\r` (trim vs no-trim mismatch)

## Where to apply (highest-value fences first)
- **Invite / role-change / remove-member protection** ("can't act on higher-privilege
  user") — the case-skip downgrades an owner/admin.
- **Duplicate / ownership / email-taken** checks — create a second identity for the
  same person or block their own-confirmation.
- **Email allowlist / denylist / domain whitelist** (signup, invite) — bypass
  "@company.com" required, or invite a blocked domain.
- **OAuth redirect_uri / host matching** — case mismatch between registered and
  requested host.
- **JWT `iss`/`aud`/`azp` string compares**, or a host header check.
- **File-extension / content-type filters** (`.PHP`, `.JSP`) where the server or CDN
  serves case-insensitively.

## Reporting
- Confirm the downstream resolves to the SAME account (invite landed on the real
  user, role actually changed) — that's what makes it a real bypass, not a no-op.
- Severity depends on what the guard protected: downgrading/locking out an Owner or
  Admin (privilege manipulation / DoS via lost control) is the strong case; pure
  duplicate-account creation is weaker.
- Root cause: lack of case normalization before the authorization/deny comparison,
  while identity resolution stays case-insensitive. Fix = normalize (lowercase) on
  both sides.

## Gotchas
- If the deny check normalizes (lowercases) on its side, the bypass won't fire — move on.
- Verify role actually changed and control was lost, on an owned test org only.
- Clean up: restore the Owner's role, remove phantom/duplicate accounts after confirming.
- Case in the domain is invalid for real DNS (`.coM` still resolves), but the local
  part case (`Test@`) is the most reliable; both worth testing.
