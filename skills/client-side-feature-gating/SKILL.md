---
name: client-side-feature-gating
description: Premium/Pro/Enterprise feature bypass when the SKY is gated ONLY on the client (HTML disabled / data-feature=&quot;locked&quot; / hidden menu / JS check) with NO backend entitlement validation. A basic/free user removes the disabled attribute (or un-hides the button/feature, or directly calls the feature endpoint) and the premium feature activates — the server never re-checks the subscription/entitlement. Covers: Inspect/remove disabled, remove data-feature=&quot;locked&quot;, reveal hidden premium menus, call the gated endpoint directly, toggle a client entitlement flag/plan object in storage, and confirm the unlocked feature's business impact. Root cause = missing backend authorization/entitlement; fix = enforce plan/feature checks server-side from the authenticated subscription, never from client state. Cross-ref quota-plan-limit-bypass (plan gating) and privilege-flag-verb-escalation (flag via API). Triggers on remove disabled attribute unlock Pro feature, data-feature locked bypass, client-side feature gating, premium/Pro/Enterprise feature without subscription, front-end only access control.
---

# Client-Side Feature Gating → Premium/Pro/Enterprise Bypass (no backend check)

A SaaS gates Pro/Enterprise features purely on the **front end** (a `disabled`
attribute, `data-feature="locked"`, a hidden menu, or a JS entitlement object) and
the **backend never validates the subscription**. A free/basic user removes the
client-side block and the premium feature simply works — no auth, no subscription,
no server check.

## The primitive

- Buttons/features for paying users carry client markers:
  ```html
  <button disabled data-feature="locked">Export / AI / Advanced ...</button>
  ```
- Remove the `disabled` attribute (or drop/change `data-feature="locked"`) in
  DevTools/Inspect → the button becomes active.
- Click it → the feature activates with **no server-side rejection**, because the
  app only ever checked the client state. Works across multiple premium features.

## Variants of the same flaw

1. **Remove `disabled` / `data-feature="locked"`** (HTML) → feature clickable.
2. **Un-hide a hidden/`display:none` premium menu or button** → navigate to it.
3. **Call the gated endpoint directly** (the premium action's API) — often it's
   reachable without any entitlement header; the UI just didn't show it.
4. **Toggle a client entitlement object in storage/state** (`plan`, `isPro`,
   `user.entitlements`, `features:[...]`) → re-render unlocks the UI.
5. **Add the feature flag/param to a request** the front-end normally attaches for
   paying users (e.g. `isPro:true`, `plan:enterprise`) and the server trusts it.

## Reusable checklist

1. **Discover the client gate**: Inspect the UI for `disabled`, `data-feature`,
   `data-plan`, `.locked`, `display:none` premium menus, or a JS `plan`/`features`
   object in localStorage/sessionStorage/Redux.
2. **Remove/bypass the client block** and confirm the button/feature becomes usable
   (no server error on click).
3. **Try the direct-endpoint route**: if you can find the premium action's
   request/URL, call it without any entitlement — does it succeed server-side?
4. **Confirm impact** across MULTIPLE premium features (not just one) — several
   unlocked = a systemic backend validation gap (stronger report).
5. **Scope**: does the enabled feature expose data or cause financial impact
   (paid-only exports, admin dashboards, enterprise integrations, usage limits)? That
   drives severity.
6. Use a free/basic test account; revert the UI change; never consume paid features
   beyond a small PoC.

## Reporting
- Classify as **Improper Access Control / missing backend authorization /
  business-logic entitlement bypass** (CWE-284 / CWE-862 / CWE-863). Severity by
  impact: free access to paid/Pro/Enterprise features (data, functionality, cost).
- Include: the client gate (disabled/data-feature="locked"), the Inspect change, the
  feature activating with a free account, and the business impact (premium features
  accessible; if data/pricing/limits involved, note the loss).
- Root cause: entitlement is enforced **only client-side**; the backend trusts the
  front end and never re-checks the authenticated user's subscription/plan on the
  gated action.
- Fix: enforce feature/plan authorization server-side on every gated action
  (derive plan from the authenticated subscription, not from client state or a
  client-supplied flag); treat client markers as cosmetic only; add server-side
  entitlement checks + tests.

## Gotchas
- Some features check the plan inside the endpoint but the UI hides them — test the
  **direct endpoint call** too; it may be the real hole even if the button is
  cosmetic.
- If the backend DOES re-check and rejects the free-user request even after the UI
  unlock → not a finding; step back.
- Only use your own free test account; don't actually run enterprise-only operations
  beyond a minimal confirmation.
- Cross-check other client-side controls: same root cause often affects hidden
  admin toggles, exporters, and plan-gated APIs.
