---
name: unauth-id-pii-and-archive-id-harvest
description: Unauthenticated sensitive-data disclosure reached by an object id (request/booking/order id), where the id is high-entropy (hash/UUID, not brute-forceable) but leakable from historical records (Wayback Machine, Internet Archive, Google cache, referrer logs, shared links, error pages). Two-part technique: (A) find an endpoint that returns PII (email, home address, service/booking details) keyed ONLY by an object id and with NO authentication token required — replay it unauthenticated to confirm; (B) when the id is a high-entropy hash, harvest real ids from archive/Wayback/URL-cache/other-user-shared sources rather than brute force, then use them to pull victims' PII. Triggers on: unauthenticated API returns email/address, getHelpFlow/booking SOS endpoint no auth, request_id leaked in Wayback/Internet Archive, sensitive data keyed by a non-enumerable id but reachable via harvested ids.
---

# Unauthenticated PII via an Object Id + Harvesting Non-Enumerable Ids from Archives

Two clean techniques that combine into a high-impact PII leak even when the object
id is NOT brute-forceable:

1. An endpoint returns sensitive data (email, home address, service/booking details)
   keyed ONLY by an object id, and requires **NO authentication token** — a broken
   object-level authorization with zero authz.
2. When the id is a **high-entropy hash/UUID** (random, unique — brute force is not
   feasible), **do not brute force**: harvest real ids from
   **Wayback Machine / Internet Archive / Google cache / URL logs / shared links /
   error messages / third-party aggregators**, then use them against the endpoint.

## Part A — the unauthenticated endpoint

While testing a booking/service flow, review the request behind a sensitive feature
(here: an **SOS** feature active only during a booking):

```json
POST https://api.redacted.com/api/v2/help-recovery/gethelp/getHelpFlow
{
  "user_type": "customer",
  "flow_type": "request",
  "request_id": "<booking_id>",
  "group_key": "customer_sos_group",
  "mode": "published"
}
```
Response discloses the **email address, home address, and service details** of the
user whose booking `request_id` matches.

**Confirm the authz gap:** replay the exact request with **NO authentication token**.
If it still returns the PII → the endpoint is unauthenticated (the id is the only
key). That's the bug's ceiling once you have any valid id.

## Part B — obtaining non-enumerable ids (the real challenge)

The `request_id` is a **random, uniquely generated hashed string** → brute forcing is
not feasible. When the id isn't enumerable, look for places real ids are exposed:

- **Wayback Machine / Internet Archive** (`web.archive.org`) — archived URLs often
  contain booking/request ids in paths or query strings. Search `http://web.archive.org/cdx/search/cdx?url=redacted.com/*/...` and the calendar.
- **Google cache / search results** — `site:redacted.com` and quoted strings.
- **Referrer headers / analytics** that logged deep links with ids.
- **Shared/opened links** by other users, notifications, email trackers.
- **Error messages / debug / support tooltips** that echo an object id.
- **Third-party page crawlers / URL shorteners** that captured the ids.

In the worked example, the Internet Archive surfaced **~100 real `request_id` values**
— enough to demonstrate access to ~100 victims' email/home-address/service PII via
the unauthenticated endpoint.

## Reusable checklist

1. **Find a sensitive-data endpoint** keyed only by an object id (booking, order,
   ticket, help/SOS, invoice, message).
2. **Replay it unauthenticated** (drop the session/token/cookies) → does it still
   return PII? If yes, that's the authz gap.
3. **Determine id entropy**: sequential/UUID/hash? If sequential → mass-enumerate.
   If high-entropy hash/UUID → do NOT brute force.
4. **Harvest real ids** from archives/cache/URLs/logs/shared sources (Wayback CDX
   API is the highest-yield for sites with history).
5. **Map ids → PII**: for a handful of harvested ids, confirm the endpoint returns
   distinct victims' data (redact; only pull enough to prove impact).
6. Test the same id-keyed access on **related endpoints** (update, cancel, mark-read)
   — often they share the no-auth / no-authz flaw (may allow modification too).

## Reporting
- Classify as **Broken Object Level Authorization / improper access control /
  sensitive data exposure (PII)** — CWE-639 / CWE-284 / CWE-200. High if email +
  physical home address of many users is disclosed with no auth.
- Include: the unauthenticated request + response (PII present), the id entropy
  (high-entropy → not brute-forceable), and the archive-harvesting step showing a
  meaningful number of real ids (do not enumerate to get more than needed).
- Root cause: the endpoint never enforces authentication/authorization and trusts a
  client-supplied object id; PII includes physical address → additional sensitivity.
- Fix: require authenticated + authorized access tied to the authenticated user's
  own bookings; scope object access to the principal; don't rely on id secrecy
  (Id is not a secret); protect PII (esp. home address).

## Gotchas
- **Unauthenticated + PII** is usually more severe than a normal IDOR (no session
  needed). Confirm by replaying with token removed AND from an incognito/no-cookie
  context.
- Don't actually fetch a large PII set; pulling a handful of archive-derived ids is
  enough to prove impact. Note the archive count (~100) as evidence of reachable
  victims without dumping them.
- If the id is a sequential integer, skip the archive step and note it is directly
  mass-enumerable (bigger impact).
- Only use your own bookings for the first confirm; for the harvest step, cap to a
  small number and describe, don't exfiltrate, the PII.
