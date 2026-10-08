# 09 — Tooling, Pitfalls, Verification & Reporting

## Tools
- **Burp** + **Param Miner** (unkeyed input discovery; "Add cachebuster" in headers; Fat-GET detection; "twitchy cache poison"). Merged 2,917-header wordlist (Param Miner + HTTP-Archive Vary).
- **Web Cache Deception Scanner** BApp; **Burp Comparer**; **Intruder** (delimiter fuzz).
- **Burp MCP** (this environment): `send_http1_request`/`send_http2_request` for raw crafted requests browsers won't send (malformed headers, fat GET, fragments, delimiters); `get_proxy_http_history[_regex]` to mine live traffic for oracles; `generate_collaborator_payload`+`get_collaborator_interactions` for OOB confirmation; `create_repeater_tab`/`send_to_intruder`.
- **Playwright / Chrome MCP**: victim simulation — confirm XSS actually *executes* and WCD leaks from an unauthenticated session.
- **PortSwigger Web Security Academy** labs to rehearse each technique.

## Bundled scripts (`scripts/`)
- `discover-subdomains.py` — passive forgotten-subdomain enum (Shodan CTL + crt.sh + Wayback CDX). CTL is the reliable source. **Forgotten/neglected wildcard subdomains are where misconfigs survive — enumerate first.**
- `live-oracle-recon.py` — mass read-only cache detection + oracle classification (real HIT / public-cacheable / cdn-cache timing). Trust this over static CDN guesses.
- `phase-b-probe.py` — safe cachebusted battery: query-keyed check, header reflection (XFH/X-Host/X-Forwarded-Server), 9-vector CPDoS with **poison+verify on the same key**, normalization. Writes crash-safe JSONL.

**Script gotchas (learned the hard way):**
- On Windows, Python text writes emit `\r\n`; piping a hostlist through bash `tr '\n' ' '` leaves a trailing `\r` → urlencodes to `%0d` → every request DNS-fails silently, faking a "clean" result. **Always `tr -d '\r'`** on hostlists.
- Long batch runs get torn down between sessions — write **line-buffered JSONL, flushed per host**, so nothing is lost.
- Add a **fast liveness gate** (1 request, short timeout) so dead hosts don't eat the whole run.

## "Works in Burp, not in browser" — the #1 failure mode
Cache keys differ between your two requests. Causes & fixes:
1. **Param Miner static `?cb=1`** injected in Burp only → disable "Add fcbz cachebuster" or match it in the browser.
2. **Burp "Remove unsupported encodings"** rewrites `Accept-Encoding` → disable, or match both.
3. **Truncated fragments** — browsers drop `#…` → use `%23` or a proxy.
4. **Cookie differences** — session cookies change the key → test both states, compare byte-for-byte with Logger++.
5. **CF edge routing** — different `CF-RAY` → target a direct IP / VPN / confirm CF-RAY matches.

## Verification protocol (all six before reporting)
1. Cache HIT confirmed (`cf-cache-status: HIT` / `x-cache: HIT` / `Age`>0).
2. Baseline vs poisoned differ meaningfully.
3. **Persistence** — a clean request on the same key gets the poison.
4. Multi-edge tested (CDN) — ref 08.
5. Real impact demonstrated (token/PII/XSS-exec/redirect), not mere reflection.
6. Collateral avoided (`dontpoisoneveryone` throughout; no root/asset poisoning).
**Kill false positives by hand** — flaky baselines fake CPDoS; re-request and confirm the "error" actually persists on a clean key. The poison+verify discipline is what separates real bugs from origin quirks.

## Reporting for acceptance
1. **Lead with impact** ("single-request persistent DoS on checkout"), not "cache header discrepancy".
2. **CVSS**: unauth cache attack ≈ `AV:N/AC:L/PR:N`; set C/I/A by actual impact; don't inflate AC for multi-edge.
3. Include **multi-edge / CF-RAY** evidence.
4. Note the **purge** path (e.g. `PURGE /path`) so the team can clear it.
5. Cite research: Kettle 2018/2020, Doyhenard BH2024, CPDoS (Nguyen & Lo Iacono), the specific disclosed report #.
6. Show the **cachebusted** PoC and explain how removing the buster makes it live — don't launch the live version.

## Defensive recommendations (include in reports)
Disable caching if not needed; cache only truly-static responses; never build dynamic content from headers/cookies (`X-Forwarded-*`, `Origin`, `Referer`); audit with Param Miner; strip dangerous headers at the edge (`X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `X-Forwarded-Host/Scheme`, `X-Host`, `Fastly-host`); mark dynamic responses `no-store`; rewrite requests at the edge instead of dropping key components; return `431` (never `400`) for oversized headers; disable error-page caching (CloudFront/Akamai/Varnish/CF); WAF **before** cache; consistent URL parsing between cache and origin; fix client-side sinks regardless of current exploitability.
