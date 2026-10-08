---
name: magic-link-redirect-token-theft
description: Magic-link and login-token theft via an attacker-controlled redirect URL accepted by naive hostname suffix validation. The app validates the redirect/callback destination by checking whether the host string ends with or contains the trusted domain (for example a bare `endsWith` check against the trusted domain), so an attacker-registered domain such as `attackerexample.com` or an attacker-controlled subdomain such as `example.com.evil.com` passes. When the magic-link or post-login flow redirects the browser to that destination, the login token, one-time code, or session material arrives at the attacker host. Covers discovery of weak hostname checks in client JS and token flows, exact URL-parsing pitfalls (suffix without label boundary, substring checks, userinfo, ports, subdomains), safe owned-account validation with canaries, impact, remediation, and CWE tags. Triggers on magic link redirect token theft, open redirect leaking login token, naive suffix validation, endsWith hostname allowlist bypass, attacker domain suffix, callback URL hostname bypass, password reset link redirect, token in redirect query.
---

# Magic-Link / Token Theft via Naive Hostname Suffix Validation

Magic-link and password-reset flows authenticate the user by emailing a link that
carries a login token or one-time code. If the flow also accepts a client-supplied
redirect/callback parameter (common for post-login deep links), the token is appended
to that redirect URL. A naive hostname validation — checking whether the host string
*ends with* or *contains* the trusted domain instead of comparing the parsed hostname
— lets an attacker-controlled domain pass, so the magic-link token is delivered to the
attacker instead of the intended app.

## How the flaw works

1. The trusted origin is, say, `example.com`.
2. The app validates the redirect host with a check like:
   ```js
   host.endsWith("example.com")          // naive: no label boundary
   url.includes("example.com")           // naive: substring match on raw string
   url.startsWith("https://example.com") // naive: prefix match on raw string
   ```
3. The attacker registers `attackerexample.com` — a completely different registrable
   domain whose name happens to end with the characters `example.com` — or uses an
   attacker-controlled subdomain such as `example.com.evil.com` (a subdomain of the
   attacker's `evil.com`).
4. The naive check passes, so the magic-link/login flow redirects the browser to the
   attacker host with the token attached: `https://attackerexample.com/?token=<login-token>`.
5. The attacker's server logs the request and replays the token against the real app
   to authenticate as the victim.

The severity comes from the *chain*: a weak open-redirect check on a flow that appends
a credential. Standalone open redirects are often low; token theft in a magic-link or
reset flow is account takeover.

## Discovery

1. **Map token-bearing flows.** Login, magic-link email, password reset, email change,
   OAuth/SSO callback, and post-logout redirects. Identify parameters that control the
   destination: `redirect`, `continue`, `next`, `returnUrl`, `callback`, `callbackUrl`,
   `target`, `href`, `url`, `link`, `redirect_uri`.
2. **Find the validation logic.** Grep client JS bundles and replay server responses
   for hostname checks: `endsWith`, `startsWith`, `includes`, `indexOf`, `split("/")`,
   `substring`, regex like `^https://example\.com`, `url.host` vs `url.hostname`, and
   allowlist arrays. Confirm *which URL component* is validated — the full raw string,
   the host, host:port, or the parsed hostname — and whether a label boundary is enforced.
3. **Check what rides along.** For each redirect-bearing flow, determine whether a
   token, one-time code, or session value is appended to (or placed after) the redirect
   URL — in the query string, fragment, or path.
4. **Test each payload class** (section below) against a **canary domain you own**, one
   payload per request, comparing the resulting redirect Location / generated email link.
5. **Cross-check the same validation** across related flows — the check is usually one
   shared helper, so a bypass found in the reset flow often applies to login and email
   change too.

## Exact URL parsing pitfalls

The trusted domain is `example.com`. The table shows what each naive check does with
each payload class and where the browser actually goes:

| Payload | Real destination | `endsWith("example.com")` | `startsWith("https://example.com")` | `includes("example.com")` | Correct label-boundary check |
|---|---|---|---|---|---|
| `https://example.com/` | example.com (trusted) | PASS | PASS | PASS | ACCEPT |
| `https://attackerexample.com/` | attackerexample.com (attacker) | **PASS (flaw)** | FAIL | PASS | REJECT |
| `https://example.com.evil.com/` | example.com.evil.com (attacker subdomain of evil.com) | FAIL | **PASS (flaw)** | PASS | REJECT |
| `https://example.com@evil.com/` | evil.com (attacker; userinfo) | FAIL | **PASS (flaw)** | PASS | REJECT |
| `https://example.com:8443/` | example.com (trusted, non-default port) | FAIL (host:port) | PASS | PASS | ACCEPT |
| `https://sub.example.com/` | sub.example.com (trusted only if intended) | PASS | PASS | PASS | ACCEPT only if intended |

### 1. Suffix without a label boundary (`attackerexample.com` vs `example.com`)

`"attackerexample.com".endsWith("example.com")` is `true`, because the suffix check
does not require a dot boundary. `attackerexample.com`, `notexample.com`,
`findexample.com`, `myexample.com` are all *different registrable domains* the attacker
can register, and all pass. The correct check requires the boundary:
```js
const ok = host === "example.com" || host.endsWith(".example.com");
```

### 2. Substring / `includes` checks

`"https://example.com.evil.com/".includes("example.com")` is `true` — the trusted name
appears as a label prefix inside a domain the attacker fully controls (`evil.com`).
Substring checks also pass for `https://evil.com/?redirect=example.com`,
`https://evil.com/#example.com`, and `https://evil.com/example.com`. The check
validates *text*, not the destination host.

### 3. Userinfo (`example.com@evil.com`)

`https://example.com@evil.com/` — the browser treats `example.com` as a username and
connects to `evil.com`. A raw-string `startsWith("https://example.com")` check passes
because the prefix matches. Variants: `https://example.com:443@evil.com/` (userinfo
plus attacker port). Note: many HTTP clients reject URLs with userinfo — always verify
what the *actual* client (browser, mail renderer) does before claiming impact.

### 4. Ports

`new URL(u).host` includes the port (`example.com:8443`), so comparing `host` to the
bare `example.com` rejects legitimate URLs — which pushes developers to loosen the
check to `startsWith`/`includes` and reintroduce the bugs above. Validate
`url.hostname` (no port), and treat `https://example.com:8443/` as fine: the port
belongs to the trusted host, so it is not attacker-controlled by itself. The dangerous
port cases are combinations: `https://example.com@evil.com:8443/` (userinfo +
attacker host + port). Also watch for a trusted hostname that itself runs an open
redirect service — an attacker can chain `https://example.com/redirect?to=evil.com`.

### 5. Subdomains

`endsWith(".example.com")` correctly allows `sub.example.com` — but only if *every*
subdomain of the trusted domain is under the same trust boundary. Attacker-controllable
subdomains (user-generated content, staging, dangling DNS) become valid redirect
targets and defeat the check. Two subtler failures:
- The reverse miss: bare `example.com` fails `endsWith(".example.com")` (no leading
  dot), so developers relax the check to the buggy no-dot variant — do not report that
  as a flaw, but note it drives the bug.
- Attacker-controlled parent: `example.com.evil.com` is a *subdomain of evil.com*, not
  of example.com. Only a label-boundary check (or exact match against the allowlist)
  rejects it.

### 6. Bonus pitfalls (check, do not rely on)

Trailing dot (`example.com.`), case (`EXAMPLE.COM`), IDN/unicode lookalikes
(`examplé.com` vs `example.com`), and embedded whitespace/control characters. Always
parse with the platform URL parser and compare the normalized `hostname`.

## Safe owned-account validation

- **Never point canaries at third-party targets or other users.** Every redirect test
  must terminate at infrastructure you own.
- Own the canary domain (register it) or use a Burp Collaborator client; give each test
  a unique subdomain + per-test path so responses are attributable: `https://canary-<n>.example.net/ml/<test-id>`.
- Record **Host header, full path, and query string** — the token usually arrives in the
  query of the canary request.
- Use only owned test accounts for the magic-link/reset flow. Request the email, follow
  the generated link, and confirm the token appears in the canary log.
- **Prove the chain once:** take the token captured on your canary and redeem it against
  the real app using your own test account, confirming it grants an authenticated
  session. This distinguishes real token theft from a dead open redirect.
- Verify token properties before assigning severity: single-use vs reusable, bound to
  the requesting account or not, honored only at the intended origin or from any host.
- Rotate canary paths between tests and programs; never reuse a canary value across
  engagements (prevents false attribution and cross-contamination).

## Impact

- **Account takeover (High/Critical):** the attacker harvests a magic-link or
  password-reset token and authenticates as the victim; with a reset flow the attacker
  can also reset the victim password.
- **Session/credential disclosure:** one-time login codes, session tokens, or OAuth
  authorization codes leak to the attacker host (CWE-200).
- **Email-change / privilege flows:** the same naive check on email-change or
  invite/registration links lets an attacker claim links meant for another account.
- Severity depends on flow and token binding; an unauthenticated magic-link ATO is
  typically High, Critical when the account has admin/privileged access.

## Remediation

- Parse the URL with the platform URL parser and validate **only `url.hostname`** —
  never raw strings.
- Use an exact allowlist match, or a dot-boundary suffix: `host === "example.com" ||
  host.endsWith(".example.com")`.
- Reject URLs containing userinfo (`url.username` / `url.password` non-empty), or strip
  it before validation.
- Compare `hostname` (not `host:port`); normalize case, trailing dot, and punycode
  (reject raw IDN lookalikes).
- For OAuth `redirect_uri`, require an exact match on scheme + host + port + path.
- Bind magic-link/reset tokens to the requesting account and session; make them
  single-use and short-lived; honor them only at the intended origin.
- Centralize the allowlist in one shared, unit-tested helper so every flow (login,
  reset, email change, OAuth) uses the same check.

## Reporting

- Classify as magic-link/token theft via open redirect (CWE-601), with the naive
  comparison as the root cause (CWE-697) and token disclosure as the impact (CWE-200);
  CWE-640 when a password-reset/magic-link flow is the carrier.
- Include: the exact validation code or location, the bypass payload, the before/after
  request pair, the generated email link, the canary-server request log showing the
  token arriving, and the owned-account redemption proving the session works.
- Describe the check that failed (endsWith vs startsWith vs includes vs userinfo) and
  the exact payload class that bypassed it — this is what the fix must address.

## Reusable checklist

1. Map redirect-bearing flows: login, magic link, password reset, email change, OAuth,
   logout.
2. Locate hostname validation: grep for `endsWith` / `includes` / `startsWith` /
   `indexOf` / `split` / regex in client JS and server responses.
3. Determine what is validated: raw string, `host`, `host:port`, or `hostname`; is a
   label boundary enforced?
4. Test each payload class — suffix, substring, userinfo, port, subdomain — against an
   owned canary.
5. Confirm the token/code actually travels to the canary (query, fragment, or path).
6. Redeem the token only against your own test account to prove ATO scope.
7. Verify token binding (single-use, account-bound, origin-restricted) before assigning
   severity.
8. Record before/after request pairs and the canary server log for the report.

## Safety

Use only owned test accounts, owned canary domains, and unique per-test paths. Never
send victim email addresses, never point redirects at third-party sites, and never
redeem tokens for accounts you do not control.