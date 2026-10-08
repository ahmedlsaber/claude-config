---
name: js-hidden-endpoint-mass-pii
description: Discover hidden/management endpoints by reviewing JS files, then get massive PII disclosure via an enumerable numeric ID parameter (mass IDOR/BOLA). Workflow: (1) find an unadvertised endpoint in the app's JS (e.g. /user_management.edit_user_new?p_usr_id=-1) that errors without session cookies, (2) replay it with a valid session, (3) flip a numeric id parameter from -1/0 to a positive value (p_usr_id=1, user_id=1, id=1) to dump other users' PII (names, emails, phones) — often 100K+ rows when the id is a sequential database integer. Also covers the low-effort sibling: HTML injection (HTMLi) into emails via a forgot-password/request-user form (injected HTML renders in admin + employee notification emails -> phishing). Second pattern (search-engine indexed path -> fuzzed report export): Google dorking finds an indexed path that dirsearch/wordlists miss, a custom 403 signals an app-level restriction, fuzzing the discovered application root finds an unprotected report endpoint, and its download functionality exposes a large XLSX/CSV containing mass PII. Triggers on: hidden endpoint in JS, user/edit management endpoint with numeric id, p_usr_id/user_id mass enumeration, mass PII disclosure, IDOR on management API, HTML injection in email, mail template injection, indexed path via Google dorking, custom 403 app-level restriction, unprotected report/export endpoint, mass PII in XLSX/CSV download.
---

# Hidden-Endpoint Discovery in JS → Mass PII Disclosure (numeric-id IDOR)

The highest-yield chain on internal/employee subdomains: the "missing treasure" is
often a management endpoint that's live but not linked in the UI, discoverable by
reading the app's JS files, then mass-PII'd through an enumerable `id` parameter.

## Step 1 — find hidden endpoints in JS

When passive recon runs dry, review the target's **JavaScript** (the source often
reveals internal/management routes the UI never links).

- Fetch the JS bundles; grep for endpoints, route strings, and parameter names:
  `grep -oE "(/api/[a-z_/]+|\.(php|js|do|action)[^\"']*)" app.js`
  or use sources with a full-content search for `/user`, `/admin`, `/management`,
  `edit_`, `_edit`, `?.*id=`.
- Look for routes with **numeric id params initialized to `-1` or `0`** (a "new"
  sentinel) — these management forms are great IDOR targets.
- Combine with tools (js-collector / js-analyzer if available) to enumerate all
  endpoint candidates.

## Step 2 — test with a valid session (the cookie/hidden-gate)

A hidden endpoint often returns an error like "you should have a necessary cookie"
when opened cold. Replay it **from a logged-in session** (the cookie the login page
sets) — this is just a session check, not an authorization check, so a low-priv user
session may suffice.

Example finding:
```
/user_management.edit_user_new?p_inst_id=316569953&p_usr_id=-1
```
opens (with a session) a "request user" management form with a `p_usr_id` (or
`user_id`) parameter.

## Step 3 — mass PII via the numeric id

Management endpoints that edit/fetch a user by a **sequential database id** often
have no per-row authorization. Flip the parameter from `-1`/`0` to a positive value:

```
?p_usr_id=1     ?p_usr_id=2    ...   ?p_usr_id=<N>
```

- If each returns another user's record (name, email, phone, address, role) →
  **IDOR / BOLA with mass PII** (here: 100K+ employees & customers).
- Enumerate a small, bounded range to confirm, then stop (do not dump the full DB;
  a few confirming rows is enough to prove the bug).

## The sibling: HTML injection into emails (HTMLi)

While on the login/support subdomain, a **forgot-password / request-user** form
that emails the admin + the requester often reflects user input into the mail
template **without escaping**:

- Inject `"><img src=x onerror=alert(1)>` or similar into a name/description field.
- The HTML renders in the **email** sent to the admin and the employee → persistent
  phishing/malicious-content vector (HTMLi in mail). Low effort, often a separate
  report.

## Reusable checklist

1. **JS review**: enumerate endpoints from all JS bundles; flag numeric-id params
   (esp. `-1`/`0` sentinels) and management routes.
2. **Session-gated endpoints**: any hidden endpoint that errors "need cookies" —
   replay with a valid session (low-priv ok).
3. **Numeric id flip**: `-1`/`0` → `1`, `2`, … for `user_id`/`p_usr_id`/`id`/`uid`;
   confirm distinct users returned.
4. **Authz check**: is it only a "logged-in" check, or per-row ownership? Low-priv or
   cross-tenant access = real BOLA.
5. **HTMLi in emails**: test every user-input field that feeds a notification/reset
   email for reflected HTML.
6. **Bound the enumeration**: confirm with a handful of ids (1..5), then stop; never
   harvest third-party PII.

## Reporting
- **Mass PII disclosure** = IDOR / BOLA / broken object-level auth, typically High-
  Critical (all user PII). Include the endpoint, the numeric-id flip, and 2-3
  confirming distinct records (redacted).
- **HTMLi in email** = medium; include the injected payload and the mail rendering.
- Root cause: management endpoints lack per-object/row authorization and expose
  enumerable sequential ids; mail templates don't escape user input.
- Fix: authorize per resource (session/org vs. row), use non-guessable ids or
  server-side scoping, and HTML-escape all user input in email templates.

## Gotchas
- The "necessary cookies" error is a session check, not authz — don't mistake it for
  a safe gate; retest with a low-priv session.
- Only enumerate a small bound to prove impact; stop on third-party data and never
  exfiltrate a large PII range (authorized engagement; report the vuln, not the data).
- These management endpoints often exist on internal/employee subdomains that other
  hackers miss — active recon (subdomain fuzzing) + JS review is the edge.

## Companion chain: search-engine-indexed path → fuzzed report export (mass PII in XLSX/CSV)

A distinct high-yield chain on the same class of internal/employee subdomains: a search
engine has indexed an application path that dirsearch/wordlists miss, the app answers
it with a **custom 403** that signals an app-level restriction (not an edge/WAF block),
fuzzing the discovered **application root** turns up an unprotected report endpoint,
and its **download** functionality exposes a large XLSX/CSV containing mass PII.

### Step A — find the indexed path (search-engine dorking)

Wordlists miss it, but search engines found it — dork before/alongside dirsearch:

- Query the in-scope root with site operators + report/export keywords and file-type
  filters: `site:target.com filetype:xlsx|csv|xls|pdf "report"`,
  `site:target.com "export"`, `site:target.com inurl:admin|report|download|export`.
- Check `cache:` results and snippets; an indexed URL that returns 403/redirect for a
  normal browser but 200 for crawlers is a top candidate.
- Record the dork query, indexed URL, snippet, and crawl date as evidence — the path
  being indexed is part of the impact.

### Step B — interpret the custom 403 (app-level restriction signal)

Not all 403s are equal — classify before fuzzing:

- **Edge/WAF 403** — generic/blank body, CDN/WAF markers, consistent on every path,
  IP/geo-blocked → nothing app-level behind it; move on or rotate source.
- **Custom/app-level 403** — branded error page, app-specific wording, origin HTML/JS,
  different response timing, app headers (`X-Powered-By`, framework cookies) → the
  origin application itself rejects the request at routing/middleware → **the path
  exists behind the gate** and is worth fuzzing around.

### Step C — fuzz the discovered application root (iterative, after path discovery)

The indexed path is a starting point, not the prize. Fuzz from the discovered
application root to map sibling routes:

- Run a wordlist fuzzer against the discovered root prefix (not the site root), with
  status filtering that keeps non-2xx app responses visible (custom 403, 401, 405, 5xx).
- Iterate: every new path returning an app-level response seeds the next round
  (recursive fuzzing). Classify hits — custom 403 = exists but gated; 405/400 = exists,
  wrong verb; 5xx = exists and erroring (often the weakest gate).
- Prioritize report/export/download keywords: `report`, `export`, `download`, `csv`,
  `xlsx`, `file`, `print`, `generate`, `backup`.

### Step D — map and validate the report/download endpoint (safe, bounded)

Once an export candidate responds 200 without authorization, prove impact WITHOUT
downloading or retaining third-party bulk data:

- Issue the download request once (or with a bounded query — date filter, format param,
  a few-row page) and confirm the file type from headers alone:
  `Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`
  (XLSX), `text/csv`, and `Content-Disposition: attachment; filename=...`.
- If bytes are needed to prove format/columns, let the response start streaming,
  capture only the header row + a bounded slice (a few rows), redact samples, then
  abort the transfer. Never save the full file to the repo/evidence folder and never
  retain the bytes after validation.
- Capture scale server-side instead of downloading: async job metadata (export status
  endpoint returning row count / file size), `Content-Length`, or truncated length.
- Map the export family for the report: report UI page; export/download endpoint with
  format param (`?format=xlsx|csv`); async generate-then-fetch job
  (`POST /report/generate` + `GET /report/download?file=`); period-keyed exports
  (`?month=YYYYMM`); generic `download?file=` handlers.

### Report/download endpoint mapping quicklist
- `GET /report` → report UI page
- `GET /report/export|download` (+ `?format=xlsx|csv|excel`) → direct export
- `POST /report/generate` then `GET /report/download?file=<id>` → async pair
- `GET /export/<jobId>` → async job result / generated file
- `GET /download?path|file|name=` → generic (also test for path traversal)
- `GET /admin/report?month=YYYYMM` → period-keyed exports (enumerable periods widen scope)

### Authorized workflow
- Confirm the subdomain/root is in scope before dorking; exclude out-of-scope or
  third-party-hosted copies that dork results may surface.
- Treat any response containing third-party PII as a stop condition: demonstrate the
  exposure with redacted samples, then stop — report the vuln, not the data.
- No full-download validation, no retention of exported data, no period/row enumeration
  beyond the bounded proof.

### Reusable checklist (export chain)
1. **Dork first**: `site:root` + `filetype:xlsx|csv` + report/export keywords before or
   with wordlist fuzzing; record indexed URLs as evidence.
2. **Classify 403s**: edge/WAF vs app-level custom 403; only app-level 403s mark live
   application paths worth fuzzing.
3. **Fuzz from the discovered root**: recursive, status-aware; iterate on every
   app-level hit; prioritize report/export/download keywords.
4. **Probe exports safely**: single request, bounded query, headers + a redacted slice,
   abort the transfer; use server-side row counts for scale.
5. **Stop on third-party data**: never download, retain, or store bulk PII.

### Impact / reporting (export chain)
- Mass PII in an export file = sensitive data exposure, High–Critical. Chain the
  evidence: indexed URL (dork result) → custom 403 → fuzzed endpoint → export headers →
  columns + row count (redacted samples).
- A search-engine-indexed path raises severity: anyone can discover it, not just an
  attacker who guesses the URL.
- Root cause: report/export endpoints lack authorization, rely on "hidden" URLs, and
  export unfiltered-by-role data from an indexed application path.

### Remediation
- **Remove indexing**: `X-Robots-Tag: noindex` (or `noindex, nofollow`) on
  app/management roots, robots disallow for authenticated-only sections, require auth
  before crawler-visible pages, and audit/expire search-engine caches after the fix.
- **Authorization + access controls**: enforce session + role checks at the routing
  layer (default-deny) for the whole application path, not just in the export handler.
- **Object-level authorization**: scope export queries to the caller's
  tenant/org/role server-side; never trust a client-supplied scope as the only filter.
- **Least-privilege export**: only the fields/rows the requesting role needs; require a
  separate permission for bulk/report endpoints.
- **Redaction**: redact or restrict sensitive columns (email, phone, address) in
  exports, or require an explicit, logged reason for full-PII exports.
- **Logging / rate limits**: log every export (who, scope, row count) and add export
  quotas/rate limits so mass downloads are detectable and slow.

### CWE mappings (export chain)
- CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor (mass PII in the
  exported file).
- CWE-284 / CWE-862 — Improper Access Control / Missing Authorization (report endpoint
  reachable without authorization).
- CWE-639 — Authorization Bypass Through User-Controlled Key (client-supplied
  scope/format/period params).
- CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or
  Directory (indexed path / export artifact).
- CWE-359 — Exposure of Private Personal Information (the PII payload itself).
