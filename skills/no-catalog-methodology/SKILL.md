---
name: no-catalog-methodology
description: The tester's own repeatable web-testing methodology — function-first logic-bug hunting driven by the app's own "NO"s. Understand the program as a total, pick ONE function and dissect it in depth (intercept every request behind every button and reload), then extract every business rule the app enforces — each rejection the app returns ("no out-of-stock products can be added", "no red-carded player can be added in fantasy", "minimum order $159", "only 99 items", "already claimed", "order does not exist") is a logic-bug hypothesis: how do I make the app say YES when it should say NO? For each NO, build pentest scenarios from the requests in front of you (XSS, SQLi, API/parameter testing, HTTP method switching, mass assignment, step-skipping, race, replay, auth) and try each scenario ALONE and in depth; if it fails, try a bypass or an alternate path; if still failing, record it as a verified non-finding and jump to the next scenario — keep going until the function is exhausted, then move to the next function. Triggers on: follow my methodology, logic bug hunting, what does the app say NO to, extract business rules, make the app say yes when it should say no, function-first testing, rejection catalog, no-catalog testing, out-of-stock can't be added, red-carded player can't be added, per-request scenario battery, try each scenario then bypass or jump.
---

# The NO-Catalog Methodology (function-first web testing)

Your repeatable method. One function at a time. Listen to what the app tells you
it will NOT do — every "NO" is a business rule, and every business rule is a
potential bug. Then try to make the app say YES.

> The app says NO to things for a reason. That reason is a business rule.
> Your job: find where the rule is NOT enforced, or can be made to not apply.

## The loop (memorize this)

```
1. Understand the program as a total.
2. Pick ONE function. Dissect it in depth:
   click every button, reload every state, intercept ALL its requests.
3. Extract every "NO" the app says (rejections, constraints, rules, errors).
   -> each NO = a logic-bug hypothesis
4. From the requests in front of you, build a scenario battery:
   XSS, SQLi, API/param testing, method switching, mass assignment, races...
5. Try each scenario ALONE, in depth. Review the result.
   - Failed  -> try a bypass or an alternate path.
   - Still failed -> record it as a verified non-finding. MOVE ON.
6. Next scenario. Next NO. Next function. Until the surface is exhausted.
```

---

## Phase 0 — Understand the program as a total (once per engagement)

Before touching any endpoint, build the whole picture. This is the map you
return to so you never test in a vacuum.

- **What is the business?** What does it sell/provide, where does money move,
  what is free vs paid, what are the flows (browse → cart → checkout → pay →
  track; signup → verify → profile; coupon → claim → redeem)?
- **Access boundaries**: guest vs logged-in vs premium vs admin. What can each
  do that the others cannot, and WHY (the business reason)?
- **Auth model**: how does the server know who you are AND what you may do?
  (cookie, JWT, header, body flag, opaque session token, sign header…)
- **Integration surface**: payment providers, OAuth, webhooks, 3rd-party APIs.
  Every integration is a trust boundary.
- **Architecture / stack**: CDN, gateway, backend services, versioned APIs,
  staging clones. Write it in the target's `notes.md`.

Read the target's `notes.md` + `findings.md` FIRST if this is a continuing
engagement — never re-test a verified non-finding without new evidence.

## Phase 1 — Pick ONE function and dissect it in depth

The unit of work is a **function** (a user-facing feature), not an endpoint.

1. Choose a function with real business value or an unresolved open question.
2. **Use it as a normal user.** Click every button. Reload every page state.
   Trigger every branch you can find (empty state, happy path, error path,
   logged-out vs logged-in, different roles).
3. **Intercept/capture every request** the UI emits — proxy history, browser
   network log, or direct replay. For each captured request record:
   - method, full URL, headers, body/params, response + status
   - which UI action fired it (button click, page load, form submit, autosave)
4. **Map the function end-to-end**: every step, every request, every state
   transition. Note which checks happen where: client-side gate, server-side
   enforcement, or hidden parameter. Note IDs/keys you see (they are later
   scenario fuel).
5. Write the request map into the target notes (or a scratch file) — this is
   the raw material for Phase 3.

Deliverable: a numbered request map of the function with UI-action → request
pairs and the state transitions between them.

## Phase 2 — Extract the NO catalog (the heart of the method)

The app refuses things all the time. Collect EVERY refusal:

- error messages ("Some items are out of stock!", "Only 99 items can be added",
  "Not Applicable", "already claimed", "Order does not exist")
- error codes (3004, 3007, 6012, 10000…)
- field validations (phone must be 10 digits, name 1-20 letters)
- business constraints (coupon min $159, 2-for-$59 only pairs, BOGO needs a
  paid trigger, new-user-only offer, one spin per account, max qty 99)
- disabled/hidden UI that implies a rule (greyed button = a NO to find)
- state rules (free gift bound to cart; coupon bound to order threshold)

For each NO write one line in the catalog:

```
NO #: "Only 99 items can be added to the shopping cart"
  Where: server (code 3007), per-cart cap
  Trigger request: POST /mall-order/cart/change-goods  qty=100
  Hypotheses: exceed cap per-SKU instead of per-cart? multi-SKU split?
              free/BOGO units not counted? qty as string/decimal/exponent?
              different type/method param skips the check? race the check?
```

**Every NO is a logic-bug hypothesis.** The rule exists because violating it
costs the business money or exposes data. So the scenario question is always:

> "How do I make the app say YES when it should say NO?"

Also note which layer enforces it: if the NO comes only from the UI (button
disabled, client-side check), that's already a finding candidate — call the API
directly and see if the server agrees.

## Phase 3 — Build the scenario battery

Two scenario sources:

**(A) One scenario per NO** (from Phase 2). Ways to make the NO go away:
- step-skipping (do the final action without the gate step)
- change HTTP method (the rule may be bound to POST; try GET/PUT/PATCH/DELETE/OPTIONS)
- tamper the parameter that carries the constrained value (qty, id, price,
  coupon, currency, flag) — including types (string vs int, decimal, exponent,
  negative, null, huge int)
- switch context: apply the rule's object in another context (other cart,
  other order, another user's id, another region/currency, guest vs logged-in)
- replay a validated request into an ineligible context
- race the check (parallel requests during check→use gap)
- mass-assign extra fields (role, isVerified, price, id…)
- find the legacy/alternate endpoint that skips the check (JS, old versions,
  staging)

**(B) Standard request-level scenarios** for each interesting request in the
Phase-1 map:
- XSS (reflected/stored/DOM) at every input reflected in a response
- SQLi at every id/param (numeric + string, error-based/blind)
- API testing: parameter pollution, hidden params, enum/flag flipping,
  JSON type confusion, extra fields
- Method switching and verb tampering on the same path
- Auth: does the request need auth at all? Does it enforce ownership?
- Rate limiting / no-limit repeats on value-bearing actions
- Replay / idempotency violations

Write each scenario as a one-liner with its expected "YES means bug" outcome so
you can judge results objectively.

## Phase 4 — Execute each scenario ALONE, in depth

Discipline that makes this method work:

1. **One hypothesis per run.** Send the request. Capture the exact
   request + response pair (status, body, headers that matter).
2. **Judge the result against the expected bug outcome.** Did the app say YES
   when it should say NO? Did it recompute server-side? Did it no-op silently?
   Note: a silent no-op with a success code is NOT a bypass — verify the state
   changed (read-back) before calling it a bug.
3. **If it failed → try to bypass or find another way:**
   - different encoding (unicode, case, null byte, double-encode, type swap)
   - different method / different endpoint version / alternate path
   - move the check: apply at a later step (checkout vs cart vs payment)
   - chain it: use this primitive to enable another
   - 3-5 genuinely distinct bypass attempts is the budget. If all fail, the
     rule is server-enforced — that is a **verified non-finding**, which is
     valuable: it stops you and everyone else from re-testing it.
4. **Review depth over breadth:** a scenario "reviewed in depth" means you
   understood WHY it failed (which layer enforced it), not just that it failed.

## Phase 5 — Record and move on (until the surface is exhausted)

- Confirmed bug            → write DRAFT finding with exact request/response
                             evidence; reproduce once more to confirm.
- Verified non-finding     → log it (target `findings.md` non-findings section)
                             so it is never blindly re-tested.
- Open / needs more setup  → log as OPEN follow-up (e.g. "needs paid order",
                             "needs new-user email flow") and continue.
- Then: next scenario → next NO → next function. Do not rabbit-hole; the loop
  is designed to keep you moving across the whole surface.

---

## Gotchas (learned the hard way)

- **UI "NO" ≠ server "NO".** Find which layer actually enforces before spending
  bypass attempts. Client-side-only rules are usually instant findings.
- **Success code ≠ success.** A 200 with `code:0` that silently drops the write
  (ownership enforced, echo of your input id) is NOT an IDOR. Always read back
  to verify the state actually changed.
- **Client price/flag fields are often decorative.** If the server recomputes
  from the catalog, price tampering is a verified non-finding — note the design
  smell (defense-in-depth) and move on; revisit only if a new endpoint trusts
  the field.
- **Order/state re-validation:** carts/orders are often snapshotted and
  re-validated on any cart change — desync attempts fail cleanly. That IS the
  finding (server-side enforcement), recorded as non-finding.
- **Enumeration ≠ impact.** Enumerable IDs need a missing authz check to matter;
  guessable order numbers need a missing email/ownership check. Test the pair.
- **Owned accounts only.** Every live request uses owned test accounts; abort
  any pattern that would touch third-party data. No destructive payloads.

## Evidence standard

- Preserve minimal evidence: initial state, the action (exact request), the
  result (exact response), read-back verification.
- Save to `test_results/` and the target's `findings.md` / `notes.md`.
- Classify every result: Confirmed / Verified non-finding / Open follow-up.
- Never commit test credentials; keep them in the target's gitignored
  credentials file.
