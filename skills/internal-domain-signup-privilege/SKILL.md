---
name: internal-domain-signup-privilege
description: Register an account with a company's INTERNAL domain email to unlock hidden privileges / internal workspaces, and escalate to account takeover of internal staff. When a site blocks signups on its own domain ('only signups via Google/no company emails'), bypass the check with a validation trick (null byte \u0000 / newline / unicode homoglyph / case / spaces — cross-ref null-byte-injection, unicode-homoglyph-bypass, case-sensitivity-bypass) to register with an @company.com email. Then the internal-domain account gains internal/unverified privileges; if email verification is weak (verification only on email-change, or you can choose the recipient), chain it to take over an internal/founder account by targeting their mailbox (discover staff emails via Hunter.io / OSINT). Severity jumps from medium (internal-domain account created) to high (internal account takeover). Trigger: register with company internal email, null byte email bypass, signup with @company.com, internal staff account takeover, email verification targeting founder/employee, hidden internal workspace via corporate email.
---

# Internal-Domain Signup → Hidden Privileges → Internal Account Takeover

Create an account with the company's **own internal domain email** to gain access
that ordinary signups can't, then chain a weak email-verification step to take over
an internal/founder account. The blocking of corporate-email signups is a cheap
check — bypass it, and an internal identity can unlock a lot.

## Step 1 — register with the internal domain (bypass the block)

Test if signup rejects your own/company domain direct registration. If yes, find the
bypass. The writer's working trick was a **null byte injected into the email field**:

```json
POST /api/1/login/oauth/provider/signups
{
  "email": "REDACTED@company.com\u0000",
  "password": "...",
  "firstName": "Ali", "lastName": "M.",
  "overrideLocale": "en_US", "emailPreference": "OPT_IN",
  "requestId": "<UUID>"
}
```
The `\u0000` (JSON null byte) passes the "no company emails" validation (the check
sees the value ≠ blocked string) while the backend/user-model treats it as the
company email → an internal-domain account is created.

Other block-bypass vectors if `\u0000` fails: `\n`/`\t`/space, unicode homoglyphs
(see `unicode-homoglyph-bypass` for the normalization table), spaces in odd places
(`a@company .com`), case (`Ali@company.com`), `+tag` / dot variants. Use the
`null-byte-injection`, `case-sensitivity-bypass`, `unicode-homoglyph-bypass` skills.

## Step 2 — realize the privilege gain

- An internal-domain email account may be **treated as (partially) internal**:
  higher default role, ability to see internal company data, join the company's org,
  use admin-only features, or skip certain checks.
- If the account is only "partially verified" (e.g. email verified only on change,
  not on signup), you still have a foothold under an internal identity — report it
  (often Medium), then try to escalate.

## Step 3 — escalate to internal account takeover (email-verification targeting)

If email verification is weak — e.g. it only fires on **email change**, or you can
control/choose who receives the verification mail — aim it at an internal target:
1. **Discover internal staff emails** via OSINT (Hunter.io, LinkedIn, `@company.com`
   patterns, employee directories, leaks).
2. **Create an account (or trigger a verification) tied to the founder's / an
   employee's internal email**.
3. If the site sends a **verification link to that internal mailbox**, and the flow
   lets you become the verified owner of that email (or the verification link
   enables account takeover of that identity), then when the employee clicks it
   (or if verification is skippable), you gain control of the internal account.

Severity: Medium (registering with internal domain, partially verified) → **High**
(potential full takeover of a founder/internal account via verification targeting).

## Reusable checklist
1. **Probe signup** with the target's own domain email (`@company.com`) and with an
   ordinary email — note if corporate emails are blocked.
2. **Bypass the block** with `\u0000`, `\n`/`\t`, unicode homoglyphs, spaces, case,
   `+tag` (cross-ref the validation-bypass skills).
3. **Assess the internal privilege** of the created internal-domain account: roles,
   workspaces, data access, features.
4. **Test/characterize the email-verification weakness**: is verification required on
   signup, or only on change? Can you choose it fires for the internal mailbox?
5. **Escalate responsibly**: to demonstrate internal-account takeover, use a mailbox
   you own that LOOKS internal-adjacent, or stop at "can create an internal-domain
   account + verification targeting" without actually taking over a real employee —
   report the potential. Never target a real founder/employee's account.

## Reporting
- Two-stage severity:
  - **Internal-domain account creation** (bypassing the corporate-email block) —
    Medium: unauthorized internal identity, hidden privileges, potential internal data.
  - + **weak email-verification enabling internal/founder account takeover** — High.
- Include: the `\u0000` (or other bypass) request, evidence the internal-domain
  account was created with elevated/partial privileges, and the verification-flow
  weakness that would let you take control of an internal mailbox identity.
- Root cause: email validation is not strict (null-byte / normalization bypass) and
  signup/verification grants internal privileges based on the email domain without
  real verification; email-verification weak (change-only / sender-selectable).
- Fix: strict, normalized email validation (reject control chars, canonicalize)
  BEFORE granting internal-domain privileges; require real mailbox verification on
  signup for any internal/invited domain; bind verification to the signed-up identity.

## Gotchas
- Confirm the internal-domain account actually gets **different/elevated** behavior —
  else it's a minimal finding.
- Creating accounts with a REAL internal staff email is a touchy, high-risk demo: do
  NOT actually take over a founder/employee. Use your OWN test identities that match
  the internal domain pattern, or stop at "the flow would deliver a verification to
  that mailbox" and report the potential.
- Cross-check `hunter.io`/OSINT only for your own program research; don't probe real
  users' mailboxes.
