# 01 — Recon, Oracles & Key-Handling Probes (Phase A & B)

Everything here is the entry point for ANY cache test. Do it fully before choosing an attack.

## Table of contents
- [Detect cache & fingerprint](#detect-cache--fingerprint)
- [Cache-buster techniques](#cache-buster-techniques)
- [Select an oracle](#select-an-oracle)
- [Probe key handling](#probe-key-handling-the-heart-of-phase-b)
- [Bypassing uncacheable queries](#bypassing-uncacheable-queries-to-reach-the-backend)
- [Identify cache rules](#identify-cache-rules)
- [Identify framework & delimiters](#identify-origin-framework--delimiters)
- [Identify normalization](#identify-path-normalization-behavior)

## Detect cache & fingerprint

**Cache-presence headers:**
```
X-Cache: hit | miss | dynamic | refresh
CF-Cache-Status: HIT | MISS | DYNAMIC | BYPASS
X-Cache-Status: HIT | MISS
Age: 0
Cache-Control: public, max-age=3600
Server-Timing: cdn-cache; desc=HIT        (Akamai — oracle even when MISS/NO-STORE)
Akamai-Cache-Status: Hit from child
X-Amz-Cf-Pop / Via: ... cloudfront          (CloudFront)
X-Served-By / X-Cache-Hits / Via: varnish   (Fastly/Varnish)
```

**Timing oracle:** repeat identical requests; cache HITs return faster than cache-busted uniques.

**Malformed-header oracle (unauth):** send an invalid header name (`\\: garbage`). If the CDN caches the resulting `400`, it stores errors and lacks header validation. (Akamai limits 400-cache to ~5s → maintain with a null-payload barrage.)

**TTL fingerprint:** 200 static ≈ 1 day · 404 ≈ 10s · 400 ≈ 5s · 301/302 varies (long if `public`). Use to time attacks.

**Akamai cache-key extraction oracle:**
```
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
→ X-Cache-Key / X-True-Cache-Key: <the key>   (often disabled on mature targets)
```

**Host-casing test (CF/Varnish/Fastly):** `Host: TARGET.COM` — if origin differs on casing and the cached lowercase-keyed variant deviates, poisoning is possible.

**Scanner-UA oracle:** `User-Agent: Fuzz Faster U Fool` / `Nuclei` — if origin returns a cacheable `403`, that's a 1-request persistent DoS (see ref 06).

**Normalization-before-rules by provider:** CloudFront/Azure/Imperva = YES; Cloudflare/Google Cloud/Fastly = NO.
**Origin normalization:** Nginx YES · IIS YES(+backslash) · OpenLiteSpeed YES · Node YES · Apache complex.

## Cache-buster techniques
```
?cb=12345
?utm_content=12345          (often excluded from key → also a poison vector)
Accept-Encoding: gzip, deflate, cb123
Accept: */*, text/cb123
Cookie: cb=123
Origin: https://cb123.target.com     (CF keys Origin by default)
```

## Select an oracle
Requirements: (1) endpoint is cacheable, (2) you can tell HIT vs MISS (header / dynamic change / timing), (3) ideally it reflects the whole URL + ≥1 query param. The implementation quirks vary per site — understand *this* cache before attacking.

## Probe key handling (the heart of Phase B)
Ask each question with two slightly-different requests; a HIT on the second = same key = that component was transformed/dropped.

- **Port exclusion:** `Host: redacted.com:1337` then `Host: redacted.com` → poisoned port persists in redirect = port unkeyed.
- **Query-string exclusion:** `/?q=canary&cb=1` then `&cb=2` both HIT = entire query unkeyed (dynamic page looks static → masks XSS from scanners).
- **Parameter exclusion:** send `utm_content=1` vs `=2`; both HIT = UTM unkeyed. Repeat for `utm_source/medium/campaign/term`, `fbclid`, `gclid`, `ref`, `referral`.
- **URL-decoding:** `/?x=%22%3E%3Ctest%3E` then `/?x="><test>` → if 2nd HITs 1st, cache decodes the key (enables encoded-XSS collision, ref 04-E).
- **Normalization:** `//`, `/%2F`, `/%5c`(`\`), `/aaa/..%2fprofile` — compare cache vs origin resolution.
- **Method keyed?** GET vs POST same key = unkeyed method (ref 04-C).
- **Body included?** fat GET (ref 04-D).

## Bypassing uncacheable queries to reach the backend
When the query is excluded, `?cb=` busters are useless:
1. **Header busters:** `Accept-Encoding: gzip, deflate, nwf4ws` · `Accept: */*, text/nwf4ws` · `Cookie: nwf4ws=1` · `Origin: https://nwf4ws.example.com`.
2. **PURGE/FASTLYPURGE** (live only, races — not automation).
3. **Path-normalization busters:** Apache `//`→`/` · Nginx `/%2F`→`/` · PHP `/index.php/xyz` · .NET `/(A(xyz))/`. Use `//` as your poison path so genuine `/` traffic is untouched.

## Identify cache rules
- **Static extensions:** `.css .js .png .jpg .ico .html .txt .xml .json .svg` — hit `/dynamic/test.css`; if cached, extension rules exist.
- **Static directories:** `/static/ /assets/ /scripts/ /images/ /wp-content/ /media/ /templates/ /public/ /shared/`.
- **Static files:** `/robots.txt /favicon.ico /index.html /sitemap.xml`.

## Identify origin framework & delimiters
1. Non-cacheable baseline R0 (POST or `no-store` endpoint).
2. Suffix test: append `/homeabcd`; if == R0, suffixes ignored → good for delimiter testing.
3. Delimiter test: insert candidate before suffix; if == R0, delimiter is processed.

| Framework | Delimiter | Example |
|-----------|-----------|---------|
| Spring / Java | `;` | `/MyAccount;var1=val` → `/MyAccount` |
| Ruby on Rails | `.` | `/MyAccount.css` → `/MyAccount` |
| OpenLiteSpeed | `%00` | `/MyAccount%00aaa` → `/MyAccount` |
| Nginx (rewrite) | `%0a` | `/user/MyAccount%0aaaa` |
| Microsoft Azure | `#` | cache-key delimiter |

Automate with Intruder over an ASCII wordlist, encoded + raw.

## Identify path normalization behavior
- Origin: `/aaa/..%2fprofile` — if == `/profile`, origin normalizes (use non-cacheable + buster).
- Cache: repeat cacheable; compare `X-Cache`/`Cache-Control`.
- The **direction** of the mismatch decides the technique (ref 02 static-dir A vs B, ref 06/05 key manipulation).
