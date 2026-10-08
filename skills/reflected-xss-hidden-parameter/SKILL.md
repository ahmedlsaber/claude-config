---
name: reflected-xss-hidden-parameter
description: Reflected cross-site scripting (XSS) found through an external discovery pipeline — subdomain enumeration, live-host triage, content and endpoint fuzzing, hidden-parameter discovery, and unencoded reflection in HTML title and error contexts. Covers the safe authorized workflow (scope review, passive recon, owned sessions only, no harmful payloads), subdomain harvesting and HTTP probing to shortlist live hosts, fuzzing paths and query parameters for reflection sinks, brute-forcing hidden parameters that reach server-side templates, reflection-context analysis that separates weaponizable unencoded title/error reflections from encoded or attribute-only dead ends, minimal harmless proof payloads that prove execution without damage, triaging one sink across many endpoints to maximize impact, reporting evidence (request/response pairs, context proof, impact), and remediation (context-aware output encoding, CSP, input validation). Triggers on reflected XSS, hidden parameter discovery, endpoint fuzzing, subdomain enumeration, HTML title reflection, error page reflection, unencoded reflection, XSS triage, cross-site scripting hunt, bug bounty XSS methodology.
---

# Reflected XSS via Hidden Parameters

A common high-signal path to reflected XSS: a host is discovered through
subdomain enumeration, fuzzing reveals an endpoint that consumes an
out-of-band or hidden parameter, and that parameter is reflected **unencoded**
into an HTML context such as the `<title>` tag or an error banner. Because the
parameter is hidden (not present in the UI), automated scanners and manual
testers often miss it — which makes the finding both real and reportable.

This skill walks the full pipeline end to end and stops at the first
minimal, harmless proof on an owned account.

## When to use

- Starting a reflected-XSS hunt on a target with a large or unknown attack
  surface (many subdomains, legacy and new hosts mixed).
- The app reflects user input in titles, error messages, breadcrumbs, or
  404/500 pages and you want a systematic way to find every sink.
- Standard parameter testing already done on visible params with no results —
  hidden parameters are the next layer.
- Triaging a single discovered reflection across all live hosts to maximize
  report impact.

## Authorized workflow and safety

Before any request:

- **Scope first.** Read the program scope and rules of engagement: in-scope
  hosts, whether auth is required, rate limits, and what proof payloads are
  permitted. Only touch in-scope assets.
- **Owned accounts only.** Use test accounts you control. Never send requests
  that would touch third-party data or real users.
- **Prefer safe primitives.** Fuzzing with GET requests, canary values, and
  harmless markers. Throttle requests; respect `robots.txt` and rate limits.
- **No harmful payloads.** No cookie theft, no external redirects, no
  `alert()` against live targets unless the program explicitly permits it.
  Prove execution with a marker or a benign DOM write on your own account.
- **Record everything.** Save request/response pairs and evidence as you go —
  reports are written from these, not from memory.

## Phase 1 — Subdomain enumeration

Goal: build the full candidate host list for the target domain.

- Passive sources: Certificate Transparency logs (crt.sh), search engines,
  `subfinder`, `amass` (passive), `assetfinder`, `gau`/`waybackurls` for
  historical subdomains.
- Active: DNS brute force with a good wordlist, zone transfer attempt
  (almost always fails, free to try).
- For each candidate, resolve and record: IP, CNAME, and whether it is
  third-party hosted (e.g., `*.s3.amazonaws.com`, `*.cdn.` — often out of
  scope or a different owner; verify before testing).

Output: a deduplicated host list annotated with ownership and resolvability.

## Phase 2 — Live-host triage and HTTP probing

Goal: shortlist hosts that are worth fuzzing, and skip noise.

- Probe every host with an `httpx`-style pass: HTTP status, `title`, server
  header, redirect chain, and technologies.
- Classify each host:
  - Static/CDN or SPA (Next.js/React/etc.) — most logic is client-side;
    reflection sinks are rarer but JS-bundle mining applies (see
    `js-hidden-endpoint-mass-pii`).
  - **Server-rendered** — prime XSS territory: templates interpolate request
    data directly into HTML.
  - Hosts with custom 404/error pages — error templates are classic unencoded
    reflection sinks.
- Note hosts that echo the requested path or a query value into the page
  title or an error banner; that is a reflection sink worth chasing.
- Also record response headers: presence/absence of CSP, `X-XSS-Protection`,
  and cookie flags — they shape impact and weaponizability.

## Phase 3 — Content and endpoint fuzzing

Goal: enumerate routes and query parameters, and detect reflection.

- Discover endpoints: wordlists (`raft-large`, `common`) with a fast fuzzer
  (ffuf), `sitemap.xml`, `robots.txt`, and **JS bundle mining** for
  route/API names the UI never links to.
- For each discovered endpoint, fuzz query parameters with a canary value and
  grep the response for an unencoded echo:
  - Canary: a unique token with markup, e.g. `zxq<h1>POC</h1>` — a single
    value tests both reflection and encoding in one pass.
  - Check every parameter position: `?q=`, `?page=`, `?id=`, and so on.
- Mark each endpoint+param that returns the canary, and record the **exact
  context** it appears in (title, body, attribute, script, JSON).

## Phase 4 — Hidden parameter discovery

Goal: find parameters the app consumes but the UI never sends.

- Hidden parameters are commonly named after template variables and error
  strings: `callback`, `next`, `redirect`, `page`, `msg`, `message`, `error`,
  `title`, `name`, `template`, `theme`, `debug`, `preview`, `id`, `ref`.
- Brute force parameter names on the interesting endpoints with `Arjun` or
  ffuf using a parameter wordlist; compare responses with and without each
  candidate param for behavioral change (reflection, different status, extra
  HTML).
- Fuzz both query string and POST body for the same names; some frameworks
  (PHP, ASP.NET, Java) differ in which source wins.
- Try parameter pollution (`?title=x&title=y`) and case/encoding variations
  (`%54itle`, `TiTlE`) — hidden-parameter handling is often case-insensitive
  server-side while the visible UI param is different.

## Phase 5 — Reflection-context analysis

Goal: determine whether a reflection is weaponizable, and craft the minimal
payload for its exact context.

Classify the sink first — this decides everything:

- **HTML element text**: `<p>INJECTED</p>` — needs `<` to break out.
- **Title context**: `<title>INJECTED</title>` — needs `</title>` to escape
  the tag; the rest of the document follows, so
  `</title><script>...` works if unencoded.
- **Attribute**: `value="INJECTED"` — needs `"` or `'` breakout plus an
  event handler or `>` close.
- **Script block**: `var x = "INJECTED"` — needs quote/`</script>` breakout.
- **Error/404 template**: often interpolates the bad value or path raw into
  a banner or the `<title>` — same rules as element/title context.

Encoding check — the make-or-break test:

- Is `<>"` returned raw, or HTML-encoded (`&lt;`), JS-escaped, or
  URL-encoded? Test each character class separately with a payload like
  `zxq<>"'&`.
- **Raw / only partly encoded** (e.g., `<` blocked but `>` and quotes pass) →
  weaponizable; build the context-appropriate payload.
- **Fully encoded** → mostly a dead end. Try double-encoding and polyglots
  once; if still encoded, record it as a verified non-finding and move on —
  do not burn the engagement on it.

For title/error contexts specifically, the unencoded reflection pattern that
wins is: `</title><script>/*proof*/</script>` inside a `<title>`, or
`<script>/*proof*/</script>` inside an unencoded error banner. The script
block after `</title>` runs in the document body context.

## Minimal harmless proofs

Prove each step with the least harmful primitive that demonstrates it:

1. **Reflection**: unique canary text (`zxq7391`) — shows the value is echoed.
2. **HTML parsing**: `<h1 id="poc-xss">POC</h1>` — shows unencoded tags are
   parsed as elements, no script involved.
3. **Execution**: only if the program permits scripting proof, prefer a
   benign marker over `alert()` — e.g. `document.title='POC-XSS'` or
   `console.log('POC-XSS')` on an owned account. If `alert()` is explicitly
   allowed, keep it to `alert(document.domain)` so the proof identifies the
   origin without touching data.

Stop at the first execution proof on an owned account. Do not escalate to
cookie theft, keylogging, or anything touching real users.

## Multiple-endpoint triage

The same hidden parameter or reflection pattern frequently repeats across
hosts — one codebase family shares templates.

- Re-run the winning parameter and context checks against every live host in
  the Phase 2 shortlist.
- Aggregate results into a table: host / endpoint / parameter / context /
  encoded-or-raw / proof status.
- Prioritize by impact: authenticated pages and the primary www host beat
  low-traffic public subdomains; `www` reflection can steal sessions, a
  subdomain reflection may be limited to subdomain cookie scope.
- Report the class with the strongest examples; one confirmed sink plus
  several partial reflections shows breadth without padding.

## Impact assessment

- Reflected XSS on an authenticated host → session theft, account action on
  behalf of the victim, CSRF-free data reads.
- On subdomains: check cookie `Domain` scope, `postMessage` targets, and any
  `document.domain` relaxation to parent origin — sometimes a subdomain
  reflection escalates to the main site.
- Mitigating factors to verify and note: strong CSP (no `unsafe-inline`),
  HttpOnly+Secure+SameSite cookies, and whether the vulnerable page requires
  user interaction (usually the link-click in reflected XSS).

## Reporting evidence

- **Request**: method, full URL including the hidden parameter and payload,
  relevant headers (cookie for auth where applicable).
- **Response**: snippet showing the exact reflection context (the `<title>`
  or error banner line) with the payload unencoded, plus the status code.
- **Proof**: screenshot or DOM snapshot of execution on the owned account,
  and the benign payload used.
- **Root cause**: sink interpolates request data without context-aware output
  encoding.
- **Classification**: CWE-79 (reflected XSS) and CWE-116 (improper encoding
  or escaping) as the root cause; note severity per program rating guidance
  (session theft on www is typically High).

## Remediation

- **Context-aware output encoding at every sink**: HTML element, attribute,
  JS, and URL contexts each need their own encoder — including in `<title>`
  and error templates, which are routinely forgotten.
- **Input validation/allowlists** where the parameter has a constrained
  domain (ids, enums, slugs).
- **CSP** with no `unsafe-inline`/`unsafe-eval` to blunt execution even if a
  sink is missed.
- **Cookie hardening**: HttpOnly, Secure, SameSite.
- **Regression tests**: add the hidden parameter + title/error reflection
  cases to the security test suite so the sink stays covered.

## Related techniques

Cross-reference `recon-methodology` (Phase 1-2 foundation),
`js-hidden-endpoint-mass-pii` (JS-bundle endpoint mining),
`nextjs-testing` (framework-specific sinks), `web-cache-testing`
(reflected-only flaws weaponized via cache), `null-byte-injection` and
`unicode-homoglyph-bypass` (filter/WAF escape angles), and
`stored-xss-idor-ato-chain` (post-XSS impact chains).