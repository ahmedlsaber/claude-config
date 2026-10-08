---
name: functionality-confusion
description: Functionality-confusion / invalid-input persistence testing. Exploits fields that accept an invalid-but-accepted value (e.g. "title": null, empty string, wrong-type object/array, negative/NaN number, or a random value into a CONTROLLED enum/state field like reactions/status) which the backend persists without validating, then breaks the whole feature for every user. Two impact modes: (A) display-value corruption -> blank page; (B) state/enum-field corruption -> permanent feature lockout (comment section / status permanently unusable by everyone, no in-app fix). Persistent denial-of-availability / data-poisoning, especially when triggered by a low-privilege write against a shared/higher-privilege read. Methodical field-by-field abuse of create/update/react endpoints where the server stores what the client sent instead of validating it. Triggers on: CRUD endpoints with user-controlled fields, "send null to a field", random value into reactions/status enum, "break/lock the comment section", invalid-input persistence, functionality confusion, DoS via bad data.
---

# Functionality Confusion — invalid-input persistence → feature-wide breakage

A system receives an unexpected input it fails to process correctly, reacts
unpredictably, and ends up breaking the feature for everyone. Often the backend
**accepts and persists** a value it never validated, and the frontend (or a
downstream consumer) chokes on it → blank page, list-failure, workflow error.

The highest-impact version is **persistent + shared**: one bad record poisons a
list that every user of the project/workspace loads, so a single low-privilege
write bricks the page for everyone (including admins). That's a genuine
availability finding, not just a client-side quirk.

## The core primitive

A create/update endpoint stores a user-controlled field verbatim when the value is
*technically parseable* but *semantically invalid* — so no 400 is returned, and the
record is saved in a confused state.

```json
POST /api/v1/projects/{id}/reports
{ "title": "report name" }        // normal
{ "title": null }                 // the trigger
```

If the backend saves the report with `title: null` and returns 201/200, then any
code that later assumes `title` is a string (rendering, sorting, search,
serialization, a `.toUpperCase()` / length / template) crashes or renders a blank
screen. Every user opening the Reports page loads all reports → hits the poisoned
one → page fails → **feature fully broken for the project**.

## Field-by-field abuse plan (methodical)

For every user-controlled field in a create/update body, try:

| Input | Why it matters |
|-------|----------------|
| `null` | un-validated primary; breaks string consumers, breaks non-null DB columns on read |
| `""` (empty string) | empty title/name; may pass required-checks that only test for presence |
| `0`, `-1`, `NaN`, huge number | for numeric/amount/qty fields; negative/overflow breaks math, charts, balances |
| `"true"`/boolean / `0`/`1` for booleans | type confusion into role/isAdmin/isPublic flags |
| object `{}` or array `[]` where a scalar is expected | nested-value confusion; persisted as a blob the UI can't render |
| **random value into a CONTROLLED enum/state field** | corruption of a stateful field (e.g. `reactions`, `status`, `state`, `kind`) that permanently breaks the feature see below |
| strings that collide with reserved/sentinel values | `"undefined"`, `"null"`, `"NaN"`, SQL-ish, control chars, very long strings (> field limit) |
| unicode/emoji/control characters | break regex, validators, length displays |

For each: send it, note the **response code** (did it persist?), then **verify the
breakage** by loading the list/detail page (or a downstream consumer) and checking
for blank screen / 500 / infinite spinner.

## Sub-case A — display-value corruption (blank page)
Sending `"title": null` (or wrong-type) breaks the *rendering* of the record — the
page loads the poisoned row and goes blank. Impact: feature unusable while the row
is present; deleting/editing the row usually restores it.

## Sub-case B — state/enum-field corruption (permanent feature lockout)
Sending a **random value into a CONTROLLED enum/state field** (reactions, status,
state, kind, mode, visibility) can flip a record into an *invalid persistent state*
that the app then refuses to touch — **locking the feature permanently for everyone**.

Worked example:
1. Feature: an item/board with a **comment section**, and a **react** action on
   comments that POSTs a field like `"reactions": <value>`.
2. Intercept the react request and send a **random/invalid value** for `reactions`
   (not one of the valid reaction enum values).
3. The backend **accepts and persists** it (no validation / no 400).
4. **Refresh**: the comment section is now **locked permanently** — every member
   (and admins) can no longer access/comment/react, and there is no way to fix it
   (the invalid state blocks edits/rendering).

Why it's worse than the null-title case: the poisoned value is in a **state field
the app uses to gate the feature**, so it's not just a display glitch — it's a
persistent denial of the capability for the whole team, with no in-app recovery.

### Distinguish the two sub-cases when reporting
- **Display corruption** (null title) → blank page; restore by editing/deleting the row.
- **State/enum corruption** (random value in `reactions`/`status`) → permanent
  lockout; no in-app fix. Higher impact — call out that it's not recoverable via the UI.

For both, the write can be done by **any member** (lowest privilege), and the
breakage hits **everyone** including the owner/admin.


## Confirming it's persistent + shared (the real impact)

A confusing null that only breaks your own row is low. The finding needs:
1. **Persisted** — the bad value actually saved (re-fetch the record / reload list).
2. **Shared breakage** — a different user (View Only, other role, even Admin) or a
   different path (report detail, export, PDF generation, dashboard widget) also
   breaks when they load the poisoned data.
3. **Impact surface** — is the poisoned list project-scoped (all users of the
   project) or global (everyone)? Project-scoped is still usually reportable as a
   data-integrity/availability bug; global is more severe.

Test as a **low-privilege user** (the write) against a target consumed by **higher /
other-privilege users** (the read) — that's the escalation: a restricted actor
bricks the feature for everyone including admins.

## Reporting / classification

- Report as a **business-logic / hardening / DoS** finding: *unvalidated input is
  persisted and breaks the feature for all users*.
- Include: the exact payload, the accepted response code, the broken page/error,
  and that a low-privilege user (any member) can trigger it.
- Distinguish the impact mode: **blank page (display corruption, row-editable)** vs
  **permanent lockout (state/enum corruption, no in-app fix)** — the latter is the
  stronger finding.
- Note the root cause honestly: server accepts + stores invalid data instead of
  validating/400ing; the frontend also lacks a defensive fallback for the poisoned
  value. Both are legitimate; server-side validation (including enum whitelist) is
  the primary fix.
- Clean up: delete/restore the poisoned record after confirming, to restore the feature for
  other (owned) test users.

## Gotchas
- Some backends normalize `null`/`""` to a default or reject with 400 — that's the
  *good* case; move on.
- Verify the breakage on the actual consumer (the page that renders the list), not
  just the API response. Persist + break = finding; persist + API-fine = still check
  the UI/export.
- Try BOTH a wrong-type value (null/object) AND a random string into enum/state
  fields — they hit different consumers (render vs. state-gating).
- If the field is display-only (title/name), the impact is the blank page. If it's a
  money/quantity/role field, it may enable value tampering (different bug class) —
  check both.
- Only test on your own owned/authorized project(s); always clean up the poisoned row.
