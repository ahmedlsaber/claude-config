---
name: blind-sqli-origin-pivot
description: Blind/time-based SQL injection reached through an infrastructure pivot — wildcard and subdomain enumeration surfaces an SSO-gated internal subdomain, DNS/origin-IP analysis bypasses the SSO front door to expose a raw backend PHP endpoint, and an asset_id parameter answers time-based injection probes under controlled, repeatable delay. Covers the authorized workflow (scope review, passive recon, owned sessions only, throttled requests), wildcard and subdomain enumeration with validation against false positives, live-host triage and SSO-gate identification, origin-IP discovery with validation caveats (CDN vs origin, Host-header trust, certificate transparency, historical DNS, port filtering), exposed infrastructure and legacy PHP endpoint discovery, request and parameter mapping to shortlist injection candidates, time-based confirmation with baseline measurement and repeatable delay proof, DBMS fingerprinting from sleep/benchmark/comment-syntax differentials, safe bounded proof that never dumps databases (single low-sensitivity boolean-oracle extraction, capped request budget, no heavy functions), evidence and reporting with request/response pairs and timing tables, and remediation (parameterized queries, WAF rules, network segmentation, origin access control). Triggers on blind SQL injection, time-based SQLi, subdomain enumeration, wildcard DNS, SSO-gated subdomain, origin IP discovery, CDN bypass, exposed PHP endpoint, asset_id parameter, sleep payload, benchmark fingerprinting, boolean oracle extraction, safe bounded SQLi proof, infrastructure pivot.
---

# Blind SQLi via Origin-Pivot Infrastructure

A high-signal chain when the main application is hardened: the public site is
behind a CDN/WAF and an SSO gateway, but subdomain enumeration reveals an
internal-facing host, and origin-IP analysis lets you reach a raw backend
endpoint that the SSO layer was meant to protect. That endpoint runs a legacy
PHP script whose `asset_id` parameter is concatenated into a SQL query. Because
no error or boolean output is returned, the injection is confirmed with
**controlled timing** — a repeatable, measurable delay — and impact is proven
with a **bounded, safe extraction** that never dumps databases.

```
wildcard/subdomain enumeration
→ SSO-gated subdomain identified
→ DNS/origin-IP pivot reaches raw backend
→ exposed PHP endpoint (asset_id) found
→ request/parameter mapping shortlists the sink
→ time-based confirmation (controlled delay)
→ DBMS fingerprinting
→ safe bounded proof (no DB dumps)
```

## Authorized workflow and safety

Before any request:

- **Scope first.** Read the program scope and rules of engagement: in-scope
  hosts and subdomains, wildcard policy, rate limits, and what proof payloads
  are permitted. A subdomain reached by origin-IP pivot is still in scope only
  if it maps to an in-scope asset. Only touch in-scope assets.
- **Owned sessions only.** Use test accounts and sessions you control. Never
  send requests that could touch third-party data or real users.
- **Throttle everything.** Time-based testing is noisy by design — keep delays
  short (0–5 s), space requests out, and cap the total number of injected
  requests. Stop if the target shows signs of instability.
- **No harmful payloads.** No `SELECT *`, no `LOAD_FILE`, no `INTO OUTFILE`,
  no stacked statements that write, no mass extraction. No blind scripted
  dumps of tables/columns/rows.
- **Do not dump databases.** Proof is a single low-sensitivity value (a
  version string, a session-owned flag, a row count of an owned record)
  extracted through a boolean/time oracle with a small request budget.
- **Log evidence as you go.** Save request/response pairs and timing
  measurements; you will not get a second chance to re-prove safely.

## Step 1 — Wildcard and subdomain enumeration

Start passive, then active. The goal is a shortlist of live hosts, with special
attention to hosts that look internal (dev/staging/admin/api labels).

```bash
# Passive: certificate transparency + search engines + DNS
curl -s "https://crt.sh/?q=%25.{target}&output=json" | jq -r '.[].name_value' | sort -u
subfinder -d {target} -all -silent
# Active: brute force with a good wordlist, validate each hit
puredns bruteforce all.txt {target} -r resolvers.txt
# Wildcard check: does a random subdomain resolve?
dig +short random-string-{nonce}.{target} A
```

**Wildcard caveats:** many targets answer `*.{target}` with a catch-all A/AAAA
record. A resolution is not a live host. Filter aggressively:

- Resolve each candidate and drop any IP that is identical to the random
  wildcard probe's IP (unless it is the same shared front).
- Cross-check `dig` answers against `crt.sh`/`subfinder` data — names that
  appear in multiple passive sources are more likely real.
- Probe HTTP(S) on each unique IP and deduplicate by response signature
  (status, title, `Server` header, body hash) before testing anything.

## Step 2 — Live-host triage and SSO-gate identification

For each surviving host, classify the front door:

```bash
curl -skI https://{host}/ | grep -iE 'server|location|set-cookie|www-authenticate'
curl -sk https://{host}/ -o /dev/null -w '%{http_code} %{redirect_url}\n'
```

Signals that a host sits behind an SSO/login gateway:

- Redirect to a central login/identity domain (`sso.`, `login.`, `auth.`,
  `idp.`, `accounts.`) with a `return`/`redirect` parameter.
- `www-authenticate` headers, SAML/OAuth markers, or a login wall on every
  path.
- 200 on the login page but 302/403 on everything else for unauthenticated
  requests.

An SSO gate is a **tripwire, not a dead end** — the underlying service still
exists behind it. Do not stop here; pivot (Step 3) before brute-forcing the
gate itself.

## Step 3 — Origin-IP discovery and validation caveats

The SSO gate usually fronts a CDN/proxy. Find the real origin to reach the raw
service:

- **Certificate transparency / TLS SANs:** query `crt.sh` for all issued certs
  on the domain; origin hosts often share a cert or an internal name.
- **Historical DNS:** `SecurityTrails`, `ViewDNS.info`, `crt.sh` history —
  pre-CDN records frequently point straight at the origin.
- **DNS of the bare domain / apex:** sometimes the apex or `direct.`,
  `origin.`, `backend.`, `api-internal.` records bypass the CDN.
- **Mail/SPF/DMARC records:** SPF includes often leak origin IP ranges;
  `dig +short TXT {target}` and expand the `include:` chains.
- **Error-page leaks:** trigger a 404/500 and inspect for origin IPs in
  headers or body (`X-Served-By`, `Via`, stack traces).
- **IPv6 / direct-connect probes:** try the AAAA record and the CDN IP's
  neighbors/anycast region — origin listeners sometimes answer on alternate
  records.
- **Port scanning the suspected origin** (only in-scope IPs): a web server on
  an uncommon port that the CDN does not proxy is often the raw backend.

**Validation caveats — verify before testing anything on an origin IP:**

- The IP must resolve to (or be plausibly part of) an **in-scope asset**.
  Reverse DNS, `whois` org, and certificate SANs are evidence; a shared-hosting
  IP belonging to a different tenant is out of scope — abort.
- Test the pivot carefully: send the **same Host header** you would use for the
  in-scope host. Many backends are virtual-host bound; a bare-IP request may
  hit an unrelated vhost.
- The CDN may still filter requests to the origin by Host or by header.
  Accept that some pivots fail; do not try to defeat network-level controls
  beyond normal web-request behavior.
- Record **how** the origin was found (crt.sh entry, SPF record, historical
  DNS) — this is the pivot evidence for the report.

## Step 4 — Exposed infrastructure and PHP endpoint discovery

Once the raw origin is reachable, look for the legacy/unprotected surface:

- Directory/endpoint fuzzing against the origin with a small, polite wordlist:
  `admin`, `api`, `internal`, `debug`, `test`, `old`, `backup`, `cron`,
  `upload`, `export`, plus PHP-specific names (`*.php`, `*.php.bak`).
- Use a **distinct canary value** per host/path in `User-Agent` or a header so
  WAF/CDN filtering and backend hits are distinguishable in your logs.
- Fingerprint the stack: `X-Powered-By`, `Server`, error pages, cookie names,
  and file extensions. A raw `PHP/7.x` `Server` header or `X-Powered-By: PHP`
  on the origin (when the CDN strips it on the public host) is a strong
  exposed-infrastructure signal.
- Look for endpoints that accept an object identifier and return a
  representation: `get_asset.php?asset_id=1`, `fetch.php?id=`, `detail.php?n=`,
  `download.php?file_id=`. These are the SQLi shortlist.

## Step 5 — Request and parameter mapping

Map the discovered endpoint completely before injecting:

- Enumerate **all parameters** (visible and hidden): query string, POST body,
  cookies, and headers the endpoint consumes.
- For each parameter, record its **data type and semantics** (numeric id vs
  string, whether it is reflected, used in a `WHERE`, `ORDER BY`, `LIMIT`,
  `INSERT`, or `UPDATE`).
- Identify the **injection surface**: `asset_id`-style numeric identifiers
  are prime candidates because legacy PHP commonly does
  `"SELECT ... WHERE asset_id = " . $_GET['asset_id']`.
- Test each candidate parameter **one at a time**, keeping every other
  parameter at its baseline value so a positive result is attributable.
- Baseline first: fire the parameter with its normal value 5–10 times and
  record response time and body size so you know the natural variance (see
  Step 6).

## Step 6 — Time-based confirmation (controlled timing)

Time-based blind SQLi proves execution by making the database sleep for a
measurable, controlled duration. The payload must be **syntactically valid in
the query context** — an `asset_id` used in a numeric context is commonly
injected as:

```text
asset_id=1 AND SLEEP(3)
asset_id=1 AND (SELECT SLEEP(3))-- -
asset_id=1; SELECT SLEEP(3)          # stacked — only if supported, avoid by default
```

Confirmation protocol (repeat for reliability):

1. **Baseline:** time the normal request 5–10 times. Record mean and spread.
   Abort the test if baseline variance already exceeds ~1 s (network jitter,
   load) — timing proof will be unreliable.
2. **Single delay:** one request with `SLEEP(3)` (keep it ≤ 5 s). If the
   response is ~3 s longer than the baseline mean, that is one datapoint.
3. **Controlled contrast:** a request with `SLEEP(0)` (or the unmodified
   parameter) must return at baseline speed. This rules out "the whole server
   is slow" as the cause.
4. **Replicate:** repeat the delayed request 3–5 times interleaved with
   baselines. Consistent ~3 s delta while baselines stay fast is a confirmed
   oracle.
5. **Vary the delay once:** `SLEEP(4)` should scale ~proportionally (≈4 s).
   A correlated delay proves the query's execution time is under your control.

Record a timing table for evidence:

```text
request                    | response time
---------------------------|--------------
baseline (asset_id=1)      | 0.42 s
SLEEP(0)                   | 0.45 s
SLEEP(3) #1                | 3.41 s
SLEEP(3) #2                | 3.38 s
SLEEP(3) #3                | 3.44 s
SLEEP(4)                   | 4.37 s
```

If the delay never appears, test syntax variants for the DBMS (comments,
quoting, `AND` vs `OR`) — and remember `OR`-based payloads can change query
semantics (rows returned); prefer `AND` when the base query returns rows.

## Step 7 — DBMS fingerprinting

Fingerprint before extracting so oracle payloads use correct syntax. All of
these are **bounded, side-effect-free**:

- **MySQL:** `SLEEP(n)` works; `BENCHMARK(n, MD5('x'))` also delays. Comment
  styles `-- `, `#`, `/* */` all work.
- **PostgreSQL:** `pg_sleep(n)`; `-- ` comments; `SLEEP` does not exist.
- **MSSQL:** `WAITFOR DELAY '0:0:3'`; `-- ` comments; `SLEEP` does not exist.
- **Oracle:** `DBMS_PIPE.RECEIVE_MESSAGE(('a'),n)`; `-- ` comments.
- **SQLite:** no sleep primitive — a heavy expression
  (`1 AND RANDOMBLOB(500000000)`) can be used as a weak timing oracle; treat
  results cautiously.

Syntax differentials that do not sleep:

```text
# MySQL accepts backtick and # comments; others do not
asset_id=1 AND 1=1#          -> MySQL-style comment
asset_id=1 AND 1=1-- -        -> standard SQL
asset_id=1 AND 1=1-- x        -> MySQL (requires space or char after --)
```

Pair timing results with the fingerprint: a working `SLEEP` strongly implies
MySQL; `WAITFOR DELAY` implies MSSQL; `pg_sleep` implies PostgreSQL. Note the
observed DBMS in the report — it also tells the vendor which backend is
exposed.

## Step 8 — Safe bounded proof (no database dumps)

Impact proof is **one low-sensitivity value** via the boolean/time oracle,
extracted with a strict budget. Never dump schemas, tables, credentials, or
user data.

Boolean-oracle extraction (each bit/char is a yes/no question):

```text
# True/false probe (MySQL, asset_id in numeric context)
asset_id=1 AND (SELECT SUBSTRING(VERSION(),1,1))='8' AND SLEEP(2)
asset_id=1 AND (SELECT SUBSTRING(VERSION(),1,1))='5' AND SLEEP(2)
```

- Prefer the **time oracle over the boolean oracle** when output is fully
  blind — the delay answers the question directly.
- **Budget the proof:** cap extraction at ~8–16 characters of one value
  (for example the first segment of `VERSION()` or `@@version`). Two or three
  characters is often enough to prove impact; resist the pull to keep going.
- **Pick a non-sensitive value:** DBMS version, `CURRENT_USER` without
  privileges data, or the row count of an object you own. No passwords, no
  PII, no other users' rows.
- **Prefer binary-search over linear** to halve requests; keep total injected
  requests under a few dozen.
- Verify the extracted value against a **public/independent source** where
  possible (e.g., version banner already observed in headers) so the proof is
  self-checking.
- Stop at first confirmed proof. Screen-record or save the request/response
  pairs with timestamps, then write the report.

## Evidence and reporting

Include in the report:

- **Scope and authorization** note (program, in-scope host, rules followed).
- **Pivot chain:** enumeration output → SSO-gated host → origin-IP evidence
  (crt.sh/SPF/historical DNS entry) → raw PHP endpoint URL.
- **Endpoint and parameter:** full request with `asset_id` highlighted; the
  exact SQL context inferred (e.g., `WHERE asset_id = {input}`).
- **Timing table** (Step 6) proving controlled delay; the fingerprint evidence
  (Step 7).
- **Bounded proof:** the one extracted value, the oracle payloads used, the
  request count, and confirmation it matches an independent source.
- **Impact statement:** what the vulnerable query serves (asset records?),
  what the SSO gate was protecting, and the realistic worst case if chained
  (e.g., blind extraction of more data).
- **Remediation asks** (below). Redact any incidentally observed sensitive
  data; never include raw database contents.

## Remediation

- **Parameterized queries / prepared statements** for every SQL statement —
  `asset_id` included. No string concatenation of user input into SQL.
- **WAF + input validation:** reject non-numeric values for numeric parameters
  server-side; add SQLi signatures at the edge, but treat WAF as defense in
  depth, not the fix.
- **Network segmentation:** the raw PHP backend must not be reachable from the
  internet; allow only the CDN/proxy and internal networks to reach it, and
  enforce this at the origin (not just at the CDN).
- **Origin access control:** require the proxy to pass an unforgeable
  header/secret (e.g., `X-Origin-Token`) that the origin validates; reject
  direct Host-less or unexpected-Host requests.
- **Harden the SSO gate's purpose:** the gate is bypassable because the origin
  accepts direct connections — closing the origin gap restores the gate's
  value.
- **Rotate/patch the legacy PHP app:** move the endpoint behind the current
  stack, remove unused admin/internal scripts, and retire outdated PHP
  versions.

## CWE mapping

| CWE ID | Title |
| ------ | ----- |
| CWE-89 | SQL Injection (improper neutralization of special elements in SQL) |
| CWE-200 | Exposure of Sensitive Information (origin/internal infrastructure leaked) |
| CWE-284 | Improper Access Control (SSO gate bypassed via direct origin access) |
| CWE-16 | Configuration (exposed backend, weak network boundary) |

## Checklist

- [ ] Scope reviewed; only in-scope assets touched; owned sessions only
- [ ] Subdomain/wildcard enumeration done; wildcard false positives filtered
- [ ] SSO-gated host identified but not brute-forced
- [ ] Origin IP found and validated as in-scope (crt.sh/SPF/historical DNS)
- [ ] Raw PHP endpoint discovered; `asset_id` (or equivalent) parameter mapped
- [ ] Baseline timing recorded before any injection
- [ ] Time-based confirmation: controlled delay, contrast, replication, scaling
- [ ] DBMS fingerprinted with syntax differentials
- [ ] Safe bounded proof: one low-sensitivity value, budget capped, no DB dumps
- [ ] Evidence saved (requests, responses, timing table, pivot chain)
- [ ] Report written with remediation guidance