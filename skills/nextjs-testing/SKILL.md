---
name: nextjs-testing
description: Next.js-specific web application security testing methodology (full-stack React framework, ~2.3% of websites). Covers the Next.js anatomy (SSR getServerSideProps / SSG getStaticProps / ISR revalidate / middleware / API routes / Server Actions), SSTI/CSTI/XSS considerations (React escaping, dangerouslySetInnerHTML, __NEXT_DATA__ props leakage), cache poisoning/deception (Vary/Cache-Control), source-map reversal, image-optimizer SSRF (/_next/image, remotePatterns, dangerous SVG => XSS, open-redirect follow), Server Actions attack surface (Next-Action header, CVE-2024-34351 blind/full read SSRF, action hash enumeration via productionBrowserSourceMaps / NextjsServerActionAnalyzer), dependency confusion (package files), and CSRF (not immune by default). Use when the target is built on Next.js. Triggers on Next.js, getServerSideProps, Server Actions, _next/image SSRF, __NEXT_DATA__, Next-Action header, dangerouslySetInnerHTML, dependency confusion in a Next app.
---

# Next.js Web-App Security Testing

Next.js is a full-stack React framework used on ~2.3% of all websites (20M+). High
frequency, so worth a framework-specific checklist. Everything here is a black-box
test guided by how Next.js works.

## Understand the anatomy (where server vs client code runs)

- **SSR** — `getServerSideProps` runs on EVERY request, generates HTML server-side.
- **SSG** — `getStaticProps` builds once at build time (static).
- **ISR** — SSG with `revalidate` (rebuilds periodically).
- **Middleware** — runs pre-request on server/edge (auth, redirects, rewrites);
  not visible to the client.
- **API routes** — `/pages/api/*` or `app/api/*` = server-side Node endpoints.
- **Server Actions** — `"use server"` async fns invoked from client, run server-side,
  dispatched via a `Next-Action` token/header (POST).

Browser gets **HTML + client JS bundles**; the rest is server-only.

## SSTI / CSTI / XSS

- **Not inherent**: Next.js SSR renders React/JSX compiled to JS functions — no
  EJS/Handlebars-style templating, so `{{7*7}}` isn't interpreted by Next itself.
- **But still test SSTI** in black box: a developer may use an explicit template
  engine (EJS/Handlebars/Pug) or `eval`/`Function()` on the server. Try
  `{{7*7}}`, `<%=7*7%>`, `#{7*7}`, `${7*7}` — see if rendered to `49`, a template
  error, or just reflected.
- **CSTI/XSS** — React escapes `<`,`>`,`&` by default. Real risk only via:
  - `dangerouslySetInnerHTML={{__html: userInput}}` (raw HTML injection → XSS),
  - a bundled client template engine (Handlebars/Vue) without sanitization.
  - Find these sinks in bundled JS: `dangerouslySetInnerHTML`, `__html`,
    `innerHTML`, `insertAdjacentHTML`, `setInnerHTML`. Hotspots: rich-text/WYSIWYG
    editors, blogs, CMS, comments, Markdown renderers.
  - Sinks usually under `_next/static` or `/static`. Inspect the element: raw
    `<img src=x onerror=alert(1)>` in the DOM = injected (no escape); escaped
    `&lt;img...&gt;` = safe.

## Sensitive data leakage via __NEXT_DATA__
SSR props can carry secrets (API keys, internal URLs, tokens). Parse the page
source for `<script id="__NEXT_DATA__">` and inspect the JSON for credentials /
internal endpoints.

## Cache poisoning / cache deception
SSR/SSG/user pages cached by CDN/reverse-proxy with weak `Vary`/`Cache-Control`.
- Check cache headers; test caching another user's sensitive data (deception) by
  visiting from a second account.
- Test poisoning the cache with attacker content served to others.

## Source-map reversal
Minified bundles reference `.map` files via
`//# sourceMappingURL=...file.js.map`. If present, download map + bundle, restore
original sources/names (e.g. tool `reverse-sourcemap`). Note: Next.js production
builds usually DON'T ship browser-bundle source maps (missing/stripped) — only if
the dev enabled them.

## Image-optimizer SSRF (/_next/image)
- `images/remotePatterns` config may allow `*` (any host) → request image from any
  source (SSRF-ish) and have it proxied back.
- Even if restricted to subdomains, the optimizer **follows redirects** → combine
  with an open redirect on an allowed subdomain to reach internal services.
- `dangerouslyAllowSVG` → point at a malicious SVG on your domain → **XSS**.
- Test: change `url`, `w`, `q` in `/_next/image?url=...&w=512&q=75`.

## Server Actions (/ Next-Action) — CVE-2024-34351 SSRF
- Server Actions post via a `Next-Action` header/token; server dispatches on that,
  ignoring the path.
- **CVE-2024-34351 (pre-v14.1.1)**: with a leading-slash `Next-Action` value, the
  server builds an internal URL from the attacker-controlled **Host** header and
  fetches it → **blind SSRF**. Escalation: reply to the preflight HEAD with
  `200` + `Content-Type: text/x-component` → server follows with an internal page
  fetch and renders it back → **full read SSRF**. Mitigated in v14.1.1 — still test.
- If `productionBrowserSourceMaps` is enabled, chunks map action hashes → function
  names; use the Burp plugin `NextjsServerActionAnalyzer` to enumerate action hashes.

## Dependency confusion
- Next.js ships many npm packages (next, react, react-dom, + transitive). If a real
  package is deleted/typo'd, an attacker can squat the name in the registry.
- Try to fetch (brute-force) these files and analyze with `confused`:
  `package.json`, `package-lock.json`, `yarn.lock`, `.yarnrc.yml`,
  `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.npmrc`.

## CSRF
- Next.js is **not immune by default** — test CSRF on state-changing endpoints.
  Defense to look for: CSRF token in body (not just cookie), an extra CSRF header,
  `SameSite=Strict/Lax` on session cookies, Authorization-header auth.

## Reusable checklist
1. Fingerprint Next.js; note version (`_next/static`, `__NEXT_DATA__`, built pages).
2. **__NEXT_DATA__** leak → read the JSON for secrets/internal URLs.
3. **SSTI** on any server-rendered/reflected input (`{{7*7}}` etc.) + look for an
   explicit template engine.
4. **CSTI/XSS**: search bundles for `dangerouslySetInnerHTML`/`__html`/`innerHTML`;
   test rich-text/WYSIWYG/CMS/Markdown fields; check React escaping on output.
5. **_next/image** SSRF: `url` param, wildcard remotePatterns, redirect-follow,
   dangerous SVG → XSS.
6. **Server Actions**: capture a `Next-Action` request, replay it; test Host-header
   SSRF (CVE-2024-34351 pattern incl. preflight bypass); enumerate action hashes.
7. **Cache** misuse: headers + dual-account cache deception test.
8. **Source maps** if present → reverse.
9. **Dependency confusion**: probe package files.
10. **CSRF** on all state-changing actions.
11. Use owned accounts; never target third-party data.

## Gotchas
- Only pure-Next.js is "immune" by default; any added template engine / unsafe sink
  reintroduces the bug — always test even when "sure" (black box).
- `dangerouslySetInnerHTML` without sanitize = XSS; with a sanitizer, test for
  sanitizer bypass (mXSS, event handlers, protocol-relative).
- Server-action requests: preserve the exact `Next-Action` header + body to trigger
  the action; the path may be ignored.
- Respect the target's rules (SSRF to localhost/internal, dependency-confusion
  research, CSRF) — stay within in-scope, authorized targets and owned accounts.
