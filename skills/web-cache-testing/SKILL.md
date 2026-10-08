---
name: web-cache-testing
description: >-
  Comprehensive, safe, end-to-end methodology for testing web applications for
  ALL classes of web cache vulnerabilities — Web Cache Deception (WCD), Web Cache
  Poisoning (WCP), cache-key transformation/entanglement bugs, implementation-flaw
  poisoning, Cache-Poisoned DoS (CPDoS), cache-key injection, fragment/internal
  cache poisoning, and multi-input chaining. Use this skill WHENEVER the task
  involves testing, hunting, probing, or auditing for cache bugs, cache poisoning,
  cache deception, CPDoS, unkeyed headers, cache-key issues, CDN misconfigurations,
  Akamai/Cloudflare/Fastly/CloudFront/Varnish caching behavior, `X-Cache`/`CF-Cache-Status`/
  `Age`/`Server-Timing` analysis, or "is this page cacheable / poisonable?" — even
  when the user doesn't say the words "cache vulnerability." It gives a phased
  workflow (recon → oracle → key-probing → gadget → poison+verify → report),
  a full technique catalog so no trick is missed, ready-to-run recon/probe scripts,
  and strict non-destructive testing rules for authorized bug bounty / pentest work.
---

# Web Cache Testing — Comprehensive Methodology

This skill turns the PortSwigger-derived web-cache research corpus into a repeatable,
**safe**, no-technique-missed testing workflow. It exists so that when you test a target
for cache bugs you follow a *complete* checklist — every delimiter, every unkeyed input,
every CPDoS vector, every normalization discrepancy — instead of ad-hoc guessing.

> **Authorization & safety come first. Read [Rules of Engagement](#rules-of-engagement) before sending a single active request.** This is for authorized bug bounty / pentest testing only.

## How this skill is organized

- **This file (SKILL.md)** = the operational spine: the phased workflow, the decision tree, the safety rules, and a compact index of every technique.
- **`references/`** = the full technique catalog. Each file is a self-contained menu of tests + payloads for one bug class. Open the relevant one when you reach that phase — *don't* try to hold all of it in your head.
- **`references/00-full-methodology.md`** = the complete, unabridged source methodology (2,900+ lines, all case studies, all payloads). This is the canonical fallback: **if anything here is ever ambiguous or you suspect a technique is missing, grep/read this file — nothing was dropped from it.**
- **`scripts/`** = working Python tools for the mechanical phases (mass recon, oracle detection, active probing battery, passive subdomain discovery).

### Reference map (open the file for the phase you're in)

| File | Covers | Open when |
|------|--------|-----------|
| `references/01-recon-and-oracles.md` | Cache detection, oracle selection, key-handling probes, framework/CDN fingerprinting, delimiter & normalization discovery | Phase A & B (always start here) |
| `references/02-web-cache-deception.md` | WCD: static ext/dir/file tricks, delimiters, armor bypass, cookie/CSRF/PII theft | Victim-visits-link scenarios, authed endpoints |
| `references/03-web-cache-poisoning.md` | WCP: unkeyed headers, route/tenant poisoning, DOM/JSON poisoning, OG hijack, Vary, UTM/param pollution | Unkeyed input reflected/used by origin |
| `references/04-key-transformations.md` | Entanglement: unkeyed query, parameter cloaking, unkeyed method, fat GET, key normalization (URL-decode), cache-key injection, RPO, internal caches | A keyed input is transformed differently by cache vs origin |
| `references/05-implementation-flaws.md` | Port, query exclusion, path-splitting, method-override, host-casing, Fastly-Host, encoded-dup-param, storage-bucket auth, backslash, ATS fragment | Key-generation / forwarding discrepancies |
| `references/06-cpdos-and-dos.md` | CPDoS (HHO/HMC/HMO), cacheable errors, WAF-block/scanner-UA/bad-header DoS, multi-edge | Any input that yields a cacheable error |
| `references/07-chaining-and-cache-what-where.md` | Cache-what-where, redirect hijacking, nested internal→external, WCD+WCP+XSS→ATO chains | A single vector is "useless alone" |
| `references/08-info-leakage-and-multiedge.md` | Age/max-age timing, Vary analysis, CF-RAY/edge enumeration, cross-cloud poisoning | Timing an attack / proving global impact |
| `references/09-tooling-pitfalls-reporting.md` | Param Miner, Burp/Collaborator/Playwright usage, "works in Burp not browser" pitfalls, report optimization, defenses | Verifying, reproducing, and writing up |

## The core mental model

**Every cache vulnerability is a disagreement between what the CACHE thinks the request is and what the ORIGIN thinks it is.** The cache stores a response under one interpretation of the request; the origin generates that response under a different interpretation. Your entire job is to find where those two interpretations diverge, then trap a harmful response in the cache.

Classify every request component on two axes (Kettle 2018):

|  | **Keyed** (in cache key) | **Unkeyed** (ignored by cache) |
|---|---|---|
| **Used by origin** | normal behavior | **→ Web Cache Poisoning** |
| **Unused by origin** | harmless | harmless |

WCD is the special case where the input *is* the URL (always keyed) but cache and origin **parse the same URL differently** (delimiters, normalization, encoding).

## The phased workflow

Run these in order. Each phase has a dedicated reference file with the full test list — **open it, don't improvise.**

### Phase A — Recon: is there a cache, and what is it?
→ `references/01-recon-and-oracles.md` §"Detect cache & fingerprint"
- Detect cache headers: `X-Cache`, `CF-Cache-Status`, `X-Cache-Status`, `Age`, `Cache-Control`, `Server-Timing: cdn-cache`, `X-Amz-Cf-Pop`, `Akamai-Cache-Status`.
- Fingerprint CDN (Cloudflare/Akamai/Fastly/CloudFront/Varnish/Azure/Imperva) and origin framework (Rails/Spring/PHP/Nginx/Apache/IIS/Node/OpenLiteSpeed). **The stack dictates which delimiters/normalizations are even possible — never skip this.**
- **Trust live probing over static guesses.** Name-based CDN classification is frequently wrong.
- Tool: `scripts/live-oracle-recon.py` for mass detection; `scripts/discover-subdomains.py` to find forgotten wildcard hosts first (that's where misconfigs survive).

### Phase B — Oracle & key-handling: what does the cache key on / transform?
→ `references/01-recon-and-oracles.md` §"Select an oracle" + §"Probe key handling"
- Pick a **cache oracle**: cacheable endpoint + observable hit/miss + ideally reflects the URL/a param.
- Probe with paired requests, watching for an unexpected HIT: is the **port** excluded? the **whole query string**? **specific params** (`utm_*`, `akamai-transform`)? does the key **URL-decode**? does it **normalize** `//`, `/%2f`, `\`, `..%2f`? is the **method** keyed? is a **body** included (fat GET)?
- Fingerprint framework **delimiters** (`;` Spring/Java, `.` Rails, `%00` OpenLiteSpeed, `%0a` Nginx, `#` Azure) and **normalization** behavior (which of cache/origin resolves traversal first).
- Tool: `scripts/phase-b-probe.py` runs a safe, cachebusted battery (query-keyed check, header reflection, 9-vector CPDoS with poison+verify, normalization).

### Phase C — Gadget hunt: what harmful response can you induce?
→ pick the reference file matching what Phase B revealed (see decision tree below)
- Map **unkeyed used inputs** → reflection/redirect/import/route/DOM sinks (`references/03`, `04`).
- Map **URL parse discrepancies** → WCD static ext/dir/file (`references/02`).
- Map **cacheable errors** → CPDoS (`references/06`).
- Remember: **gadget quality determines severity.** The same primitive is $10k or $0 depending on the gadget you chain it to. Reflected XSS masked by an unkeyed query becomes full-site takeover.

### Phase D — Poison, verify, and confirm impact (the discipline that gets it accepted)
→ `references/09-tooling-pitfalls-reporting.md`
1. Send the poison **with a unique `?dontpoisoneveryone=<uuid>` cachebuster** so only your own key is ever affected. **Never** poison a bare root path or live asset during testing.
2. Confirm the payload lands in isolation.
3. Send a **clean** request on the same key → it must receive the poisoned response (`X-Cache: HIT` / `Age`>0). This is what separates a real bug from an origin quirk.
4. For XSS/redirect, confirm real victim impact with a browser (Playwright/Chrome MCP) — a payload that "reflects" but doesn't execute isn't the finding.
5. Note `Age` + `max-age` (attack window) and `CF-RAY`/edge (multi-edge caveat, `references/08`).
6. **Verify by hand before believing any automated hit** — flaky baselines produce false CPDoS positives. Re-request; if the "error" doesn't persist on a clean key, it's not cached.

## Decision tree (which technique, given what you found)

```
Can you control response content via an UNKEYED input?
├─ reflected in body            → XSS / resource-import / DOM         (ref 03, 04-RPO)
├─ affects a redirect           → open-redirect / defacement / DoS    (ref 03-D, 05-A, 07)
├─ cookie reflected/keyed off   → session theft / language poison     (ref 03-C, 02-cookie)
├─ OG / social meta tag         → Open Graph hijacking                (ref 03-I)
├─ JSON/translation/data-attr   → DOM-based poisoning                 (ref 03-G)
└─ internal routing header      → route/tenant poisoning              (ref 03-F, 05)

Is the input the URL, parsed differently by cache vs origin? → WCD (ref 02)
├─ different delimiter (;/./%00/%0a/#)   → static-extension WCD
├─ different normalization (..%2f)       → static-directory WCD
├─ different encoding (%23/%3f/%253F)    → double-decode chains
├─ armor present                         → .avif/.woff2/semicolon-prefix bypass
└─ authed endpoint leaks cookies/CSRF/PII→ deception → token theft → ATO

Is a KEYED input transformed by the cache? → Entanglement (ref 04)
├─ whole query string excluded  → query-XSS full-site takeover
├─ param excluded (utm/akamai)  → parameter cloaking (; delimiter, malformed ?)
├─ method unkeyed / fat GET     → body/param override
├─ key URL-decodes              → encoded-XSS normalization collision
├─ key injectable (bad escaping)→ composite cache-key injection
└─ internal/fragment cache      → whole-site poison (attacker-owned host ONLY)

Key-generation / forwarding flaw? → Implementation (ref 05)
├─ port excluded · query excluded · path-splitting · method-override
├─ host-casing · Fastly-Host · encoded-dup-param · backslash · ATS fragment
└─ storage-bucket Authorization 403

A "useless" isolated vuln, or single vectors that don't work alone?
├─ cacheable error              → CPDoS: HHO / HMC / HMO, bad Range/TE/CT, scanner-UA, WAF-block (ref 06)
├─ self-XSS / Referer reflected → cache-what-where stored XSS (ref 07)
└─ multiple weak unkeyed inputs → chain them: host+scheme→redirect, path-override+redirect→hijack (ref 07)
```

## Rules of Engagement

These are non-negotiable for safe, authorized testing:

1. **Authorization**: only test assets explicitly in scope for a program you're authorized on. Confirm scope before *active* (non-recon) requests.
2. **`dontpoisoneveryone`**: every active/poison request carries a unique `?dontpoisoneveryone=<uuid>` (or an equivalent cachebuster in the keyed component). This confines the poison to your own cache entry.
3. **Never poison shared keys during testing**: no bare `/`, no real static assets, no high-traffic paths. Use `//`-style situational-awareness variants when demonstrating.
4. **Only ever point unkeyed hostname inputs at domains YOU control** (your Collaborator). Never route a target's users to a third party.
5. **Internal/fragment caches can't be poisoned safely** — one probe may poison the whole site with no undo. Only probe them with attacker-owned hostnames and be ready to stop.
6. **DoS/CPDoS**: most programs allow *reporting* single-request CPDoS but forbid *launching* volumetric DoS. Demonstrate with a cachebuster; explain (don't perform) the live version. Check the program's exact DoS wording.
7. **Report faithfully**: verify persistence and real impact before reporting; kill false positives by hand. A cache-header curiosity is not a vulnerability.

## Non-destructive verification protocol (before any report)

From `references/09`: (1) cache HIT confirmed, (2) baseline vs poisoned meaningfully differ, (3) persistence — clean request gets the poison, (4) multi-edge tested if CDN, (5) real impact demonstrated (token/PII/XSS-exec, not just reflection), (6) collateral avoided. If all six don't hold, keep testing — don't report.

## When in doubt

Read `references/00-full-methodology.md`. It is the complete source with every case study (GitHub $10k fat GET, Lyst WCD, Mozilla update takedown, Adobe WP-Rocket internal cache, Tesla/PayPal/GitHub CPDoS, etc.), every payload variant, and every CDN/framework behavior table. This SKILL.md and the other references are an *organized index into it* — the source itself drops nothing.
