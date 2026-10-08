---
name: logic-bug-hunting
description: Business-logic / broken-workflow bug hunting methodology. Focus on how the application WORKS and where its LOGIC disagrees with intent, instead of scanner-driven XSS/SQLi/CSRF. Covers map-the-workflow, role/privilege modeling, step-skipping and workflow-verification bypasses (e.g. password-verify gate in a change-email flow that can be jumped), access-control interference, and thinking 'what if the user did something else or skipped a step'. Best for programs with thousands of already-scanned reports where traditional vulns are gone but logic bugs remain. Triggers on: logic bug, broken workflow, step-skipping, access control bypass via flow, business logic, verify-password/2FA gate bypass, email/phone change verification.
---

# Business-Logic / Broken-Workflow Bug Hunting

The highest-value, least-competitive bug class. Scanner-driven vulns (XSS, SQLi,
CSRF) get mass-discovered and cleaned. **Logic bugs depend on understanding the
business, not on a payload list** — so they survive in programs even after 750+
accepted reports.

> You are a big noob if you just run an XSS payload list through Burp Intruder.
> Logic bugs come from how you think as a hacker, not what scanner you run.

## Why hunt logic bugs
- XSS/SQLi/CSRF are saturated — every bro hacker + every scanner already tried them.
- Logic bugs are unique to your understanding of the app. Fewer people can find them.
- They chain: a "low impact" logic flaw (e.g. skip the password-verify step) becomes
  high impact combined with a session-hijack or other primitive.

## Methodology (simple, repeatable)

### 1. Use the app as a normal user FIRST
Browse every feature. Intercept all requests (proxy). Read the app's docs /
engineering blog to understand the business model.

Build answers to:
1. **Purpose** — what is the app for? (store, portal, CMS, marketplace, fintech…)
2. **Privileges** — admin / proUser / normalUser / seller… what can each do?
3. **Authentication** — how does the app know a user's identity AND privileges?
   (JWT role, cookie, header, a flag in the request body?)
4. **Workflow per sensitive function** — map each end-to-end:
   email change, phone change, password reset, login/2FA, purchase, sell, payout,
   invite user, delete user, change role, export data.
   - Intercept and **keep track of every request** in these flows.
   - Note how sensitive actions + access control are implemented (client-side gate?
     server check? hidden parameter? session state?).

### 2. Think outside the box — violate the expected sequence
The core heuristic: **"The app tells me to do A → B → C. What if I skip a step,
reorder them, replay them, or send a step to a different user?"**

- **Step-skipping**: jump straight to the final step of a flow. If the intermediate
  verification (password, 2FA, confirm) is only checked on the page, not server-side
  on the final action, you win.
- **Direct endpoint access**: go straight to the page/endpoint the flow ends at
  (e.g. `/profile/email/change`) without completing the verify step.
- **Privilege confusion**: send an admin endpoint/action as a normal user — does it
  actually enforce, or does it 404/403 only on some paths?
- **Replay**: can a one-time step (OTP, ticket, verify token) be reused, or used for
  a different user/account?
- **Parameter tampering on the flow**: the gate often passes a `return`/`next`/
  `redirect` param — decode it, change it, or hit it directly.

### 3. The worked example (email-change verify bypass)
Workflow:
1. `POST /user/profile` → click "change email"
2. `GET /user/verification-pc` → enter password to verify
3. If correct → server returns to `GET /profile/email/change?return=...`
4. Page lets you change the email

The bug: step 2's `/verification-pc` endpoint carries the destination in a `return`
param (URL-encoded):
```
/user/verification-pc?return=https%3A%2F%2Ffreeplastine.com%2Fprofile%2Femail%2Fchange
```
**Question:** does the app actually enforce that the password was entered server-side,
or does it just use `return` to navigate the already-authenticated user?

**Try:** decode the param, go straight to
`freeplastine.com/profile/email/change` **without entering the password**. If it
loads and lets you change the email → the password-verify "gate" is client-side /
not enforced on the final action = **broken-workflow / missing-server-verification**.

The phone/email change is the same pattern — attack both.

### 4. Chain the impact
A logic flaw is rarely "critical" alone. Show its real value by chaining:
- skip-verify email change + session hijack → attacker changes victim's email →
  takes over the account permanently.
- skip-2FA/skip-confirm on a money action + XSS/CSRF → unauthorized transfer.

Report the primitives (the verification gap) accurately, and note the chained
impact for severity. Triage may rate the primitive itself Medium/High — that's fine;
the finding is the missing server-side verification.

## Reusable checks for sensitive workflows
For each: email change, phone change, password reset, 2FA setup/disable, role
change, invite, payout, delete — ask:
- Is the verify/confirm step checked **server-side on the final mutation**, or only
  client-side (a redirect/`return` param)?
- Can I reach the destination endpoint directly (GET the final page, POST the final
  action) with an authenticated session but WITHOUT the gate token?
- Is the flow's intermediate token/ticket/user binding checkable (one-time, user-bound)?
- Does a normal-user session hitting an admin/privileged endpoint actually get
  rejected, or does only some paths enforce it?
- Does reordering (do step C before B) work?

## Gotchas
- Always complete the intended flow first to understand the normal request set.
- Keep a request log per flow — you can't spot what's skippable if you don't know
  the steps.
- Test only on owned/authorized accounts; never target real third-party users' data.
- A "High" report may be re-triaged to Medium if the primitive alone lacks direct
  impact — that's normal; frame the chained impact clearly but don't overclaim.
