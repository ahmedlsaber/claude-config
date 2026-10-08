# 06 — Cache-Poisoned DoS (CPDoS) & Persistent DoS

**A single crafted request caches an error under a healthy resource's key**, denying it to all users. Always test with `?dontpoisoneveryone=<uuid>` and confirm persistence on that key (poison+verify) — modern CDNs (Cloudflare default, Varnish w/431) frequently DON'T cache errors, so **verify before believing**.

## Attack flow
Attacker sends request w/ malicious header → cache forwards (looks benign) → origin errors → cache stores the error under the target key → all users get it.

## CPDoS classes (Nguyen & Lo Iacono)

### HHO — HTTP Header Oversize
Header bigger than origin's limit (~8KB Apache) but under the cache's (~20KB CloudFront). Send one huge header or ~200 small ones. Origin `400`, cache stores it. **Correct defense = `431` (never cached).** If you see `431`, that host is safe.

### HMC — HTTP Meta Character
Cache forwards meta chars, origin rejects: `\n`(`%0a`), `\r`(`%0d`), `\a`, `%00`, other controls.
```
X-Meta: value\r\nmalicious-header: value    → origin error → cached
\\: garbage                                   → illegal header name → 400 (Akamai ~5s, barrage to hold)
```

### HMO — HTTP Method Override
`X-HTTP-Method-Override: POST` / `X-HTTP-Method: POST` / `X-Method-Override: POST` — cache sees GET, origin runs overridden method → 404/error cached (Play 1, Flask; GitLab/GCS HEAD → empty JS, ref 05-E2).

## Vulnerability matrix (Cache × Origin)
| Cache | Vulnerable to | With origins |
|-------|---------------|--------------|
| CloudFront | HHO, HMC | Apache, IIS, Varnish, S3, GitHub Pages, Heroku, Spring Boot |
| CloudFront | HHO | Nginx, Tomcat, Rails, Laravel, Symfony, Django |
| CloudFront | HMC | GitLab Pages, BeeGo, Express, Gin, Meteor, Rails, Symfony |
| CloudFront | HMO | Play 1, Flask |
| Akamai | HHO, HMC | IIS, ASP.NET |
| Akamai | HMO | Play 1, Flask |
| Varnish | HMO | Play 1 |
| Azure | HHO | IIS, ASP.NET |
| Fastly | HHO | IIS, ASP.NET |
Highest impact: CloudFront+Apache, CloudFront+IIS, CloudFront+Play1, Akamai+IIS.

## Single-request persistent-DoS vectors (Kettle & others)
| # | Vector | Payload | Result |
|---|--------|---------|--------|
| A | WAF block page (Tesla $300) | `Any-Header: burpcollaborator.net` | cacheable 403 "Access Denied" |
| B | Invalid port (HackerOne $2,500) | `X-Forwarded-Port: 123` | 302 to dead port → timeout |
| C | Invalid Transfer-Encoding (PayPal $9,700) | `Transfer-Encoding: invalid` | 501 cached for `.js` |
| D | Underscore header (Instagram $1,000) | `Accept_Encoding: br` | brotli cached, old clients break |
| E | Invalid Range (Twitter) | `Range: bytes=cow` | 400 cached for `.js` |
| F | Scheme contradiction (Bitbucket $1,800) | `X-Forwarded-SSL: off` | "contradictory scheme" 400 |
| G | Old/odd User-Agent ($7,500) | IE9 UA | "update your browser" cached |
| J | Scanner UA | `User-Agent: Fuzz Faster U Fool` | cacheable 403 |
| K | Invalid Content-Type (GitHub $7,500) | `content-type: iustin` | 406 for unauth users |
| L | Cloudflare 403 default (pre-2021-08-03) | bad `Authorization` on S3/Azure | 403 cached |

**More headers to try:** `Accept: invalid/mime-type`, `Upgrade: invalid-protocol`, `Origin: malformed`, `Max-Forwards: 0`, `Transfer-Encoding: chunked, invalid`. Param Miner "twitchy cache poison" raises sensitivity.

## Multi-edge propagation
Poison propagates from one edge to others but not all (routing-dependent). See ref 08 for CF-RAY/edge enumeration and proving global impact.

## Policy nuance
"Forbids launching DoS" → you may REPORT (don't launch). "Excludes all DoS" → don't report. Web-cache DoS is single-request application-level, not volumetric — frame it that way.

## Correct-status reference (for triage pushback)
RFC 7231 only lets caches store errors `404, 405, 410, 501` by default; `400` should never be cached; `431` is never cached by any system. WAF must sit **before** the cache, or its block pages get cached.
