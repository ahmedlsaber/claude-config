---
name: privilege-flag-verb-escalation
description: Vertical privilege escalation by flipping a hidden privilege/entitlement FLAG on a user/customer object via an unadvertised HTTP verb, and realizing the financial/business impact. Method: (1) read the app's JS to find privilege-related params (isEmployee, isCorporate, isAdmin, isPro, isInternal, role/level, entitlements), (2) find the object endpoint that exposes them (e.g. GET /customer/{id}), (3) discover other allowed verbs (OPTIONS / method-allow listing, or try PATCH/PUT/POST/DELETE) — often PATCH is unguarded, (4) PATCH the flag false->true (or add it) and re-read, (5) then exercise the gained privilege to show impact (employee discount at checkout, admin view, corporate pricing, hidden workspace, internal entitlements -> often a large financial loss or access gain). Includes the 'discover higher-privilege users and what sets them apart' approach. Cross-ref idor-http-method-tampering (verb discovery), quota-plan-limit-bypass (entitlement/pricing bypass), tamperable-identity-cookie (encoded id). Triggers on isEmployee/isCorporate isAdmin flag flip, PATCH to /customer/{id}, employee discount at checkout, privilege escalation via JS-param, hidden privilege flag write.
---

# Privilege-Flag + Verb → Vertical Privilege Escalation (with business impact)

A regular user flips a **hidden privilege/entitlement flag** (isEmployee, isCorporate,
isAdmin, isPro, isInternal, role, tier, entitlements) on their own customer object
by sending an **unguarded verb** (frequently `PATCH`), then reaps the **financial or
access benefit** (employee discount, admin view, corporate pricing, internal
workspace). New privileges = higher severity than a plain IDOR because it's a direct
authorization/entitlement bypass with real impact.

## Step 1 — look for higher-privilege users & the flags that separate them

Ask: are there privileged users (admins, employees, corporate, pro, internal)? How is
the app deciding? **Read the JavaScript** for the flag/param names that mark them —
commonly exposed in the customer/auth response:
```
isEmployee, isCorporate, isAdmin, isPro, isInternal, role, plan, tier, entitlements
```
Often you see them in a `GET /customer/{id}` (or /me, /user, /account) response.

## Step 2 — find a writable path for the flag

- Try flipping it via the obvious channels first (a "Match/replace" on the GET or a
  POST/PUT) — often blocked or ignored.
- **Discover acceptable verbs**: send `OPTIONS /customer/{id}` (or note the
  `Allow:` header / route map) → if it lists `PATCH`, that's the writable method,
  often unguarded compared to the RESTful GET/PUT.
- Send `PATCH /customer/{id}` with the flag changed:
  ```http
  PATCH /customer/{id}
  { "isEmployee": true }        # or the app-specific body
  ```
- Re-read `GET /customer/{id}` → the flag is now `true` (persisted).

## Step 3 — realize the impact

Go to the feature the privilege unlocks and show the business result:
- Employee/corporate discount at checkout (can be a large sum — e.g. >3000€).
- Admin/internal data access, corporate pricing, hidden workspace, pro features.
- Any entitlement change that produces unauthorized benefit or cost to the company.

## Reusable checklist

1. **Read JS** for privilege-related params/roles in the auth/customer responses.
2. **Identify the object + its verb surface**: `GET /customer/{id}`, then `OPTIONS` /
   `Allow` header / route map to find what else is allowed (PATCH/PUT/POST/DELETE).
3. **Write the flag**: PATCH/PUT the `isEmployee`/`isCorporate`/etc. to `true` (or
   add it if absent); confirm it persists on re-read.
4. **Exercise the privilege**: go to checkout / the gated feature and capture the
   enabled benefit (discount, access, data).
5. **Scope**: is the flag on YOUR object only (self-elevation) or can you set it on
   others' (combine with IDOR)? Self-elevation to a privileged role is already a real
   vertical-priv-esc finding.
6. Confirm and clean up (set the flag back). Use own accounts.

## Reporting
- Classify as **vertical privilege escalation / improper access control**
  (CWE-269 / CWE-284 / CWE-862). The financial impact (large discount) or data/access
  gain drives severity (High/Critical if the employee/internal path leaks data or
  costs the company).
- Include: the JS/response showing the flag, the PATCH request flipping false->true,
  the re-read confirming it, and the checkout/feature showing the granted benefit.
- Root cause: the entitlement/role is a **client-writable flag** on the object, and
  the `PATCH` (or other) verb lacks an authorization/entitlement check; the app then
  grants privileges (discount, admin, internal) purely from that flag.
- Fix: never derive privileges/entitlements from client-supplied or writable flags;
  enforce role/entitlement server-side from the authenticated session (not the
  customer object body); apply per-verb authorization (PATCH/PUT guarded like the
  GET); treat employee/corporate/pricing status as server-denied facts.

## Gotchas
- Flipping a flag that the backend re-derives server-side (or ignores) is a no-op —
  confirm the flag actually persists AND that the granted feature turns on.
- Some apps allow the write but overwrite source-of-truth; verify impact at checkout
  / the gated feature, not just the field value.
- Only use your own account; set the flag back after the PoC. If you discover it can
  be applied to other users (IDOR combo), do not target real users.
