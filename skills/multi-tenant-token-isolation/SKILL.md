---
name: multi-tenant-token-isolation
description: Multi-tenant SaaS authorization isolation testing — cross-tenant access via token/tenant-bound flaws. Test cases when a tenant is separated by subdomain (b-one.app.com, b-two.app.com) routed to one central API with a client-supplied tenant header (Source: B-One) and no cryptographic token-to-tenant binding: (1) register the SAME email on two tenants (duplicate email => each tenant issues its own token but auth is keyed by email/username, not sub/unique id), (2) reuse a token issued for one tenant against another tenant (cross-tenant identity injection => read/act as that user), (3) OSINT an admin email and repeat to get ADMIN across tenants (view users, reset creds, logs, billing), (4) trust the client-supplied Source/tenant header for routing/authz. Root causes: JWT validated by email (not sub), no email verification, no tenant_id/aud/scope claim, trusted client header. Triggers on multi-tenant, cross-tenant access, tenant header Source, JWT by email, token reuse across subdomains, tenant isolation bypass, admin over multiple tenants.
---

# Multi-Tenant Token Isolation Testing (cross-tenant authz)

SaaS platforms split tenants by subdomain but often share ONE central API and rely
on a **client-supplied tenant header** + a token whose identity is keyed by
**email** rather than a unique `sub`/ID. If the JWT isn't cryptographically bound to
a tenant, and email isn't verified, an attacker can **reuse/forge tokens across
tenants** and escalate to **admin across the whole platform**.

## The architecture that breaks
```
b-one.target.com   ─┐
b-two.target.com   ─┼──> api.target.com   (single API, multi-tenant)
                    └──> Source: B-One     (client-supplied header picks the tenant)
```
- No cryptographic binding between token and tenant.
- No server-side check that a token issued to B-Two is being used on B-One.
- JWT identity is the **email / username**, not a `sub`/unique UUID.

## The exploit chain (worked example)

1. **Duplicate-email registration**: register `target@deepstrike.io` on **B-One**
   and again on **B-Two**. Both succeed (no email ownership/verification check that
   this email already has an account per-tenant — or even at all). Each returns a
   **different JWT** but with the **same `username`/email claim**.
   ```
   POST /users/sign-up  Host: api.target.com  Source: B-One { email, password }
   POST /users/sign-up  Host: api.target.com  Source: B-Two { email, password }
   => JWT_BOne {username:"target@deepstrike.io", id:...}, JWT_BTwo {username: same,...}
   ```
2. **Cross-tenant identity injection**: take `JWT_BTwo` and call **B-One**:
   ```
   GET /user/me  Host: api.target.com  Authorization: JWT_BTwo  Source: B-One
   ```
   → the API returns the **B-One user with the matching email**. The token wasn't
   scoped to a tenant; identity was resolved by email; the `Source` header is trusted
   verbatim. What should be per-tenant isolation becomes cross-tenant access by
   email reuse.
3. **Escalate to admin**: OSINT a real vendor email (Google/GitHub/WHOIS), register
   it on B-Two (if it isn't already — no email verification), get a JWT, use it on
   B-One → **admin across the platform**: view all users, reset credentials, read
   internal logs/config, access client billing + support data.

## Why it happens (root causes to look for)
1. **JWT validated by email/username**, not `sub`/unique ID — emails are duplicateable
   and spoofable.
2. **No email verification** on signup — anyone can register any email/domain.
3. **No tenant-bound claims** — the token lacks `tenant_id`/`aud`/`scope` restricting
   where it can be used.
4. **Trusted client-supplied tenant header** (`Source:`) — no server-side mapping /
   cryptographic enforcement.

## Reusable checklist
1. **Map the multi-tenant surface**: subdomains → central API; how tenant is selected
   (subdomain, header, path, request body).
2. **Register the SAME email on two+ tenants** — does it succeed? (If the "email
   already exists" check is per-tenant or absent → dup-email possible.) Note whether
   each returns its own token with a shared identity field.
3. **Decode the JWT** — is identity the email/username (not a unique `sub`)? Is there
   any `tenant_id`/`aud`/`scope`/`iss`-scoped claim?
4. **Cross-tenant replay**: use a token from tenant A against tenant B (vary the
   tenant header) → does it authenticate as A's user on B?
5. **Tenant-header spoofing**: change `Source:`/host to another tenant with a token
   not issued for it → cross-tenant read/action.
6. **Admin escalation**: find a real (public) admin/owner email; register/reuse it to
   hit admin paths across tenants.
7. Confirm with two OWN test tenants; never touch a real third party/tenant.

## Reporting
- Classify as **broken access control / insecure direct cross-tenant auth** /
  improper authorization + authentication (CWE-284 / CWE-287 / CWE-639 / CWE-565).
  Full admin-over-many-tenants = Critical/High.
- Include: the dup-email signups, the decoded JWTs (same email, no tenant claim), the
  cross-tenant `Source`-header request returning another tenant's data, and the admin
  escalation (users/reset/logs/billing access).
- Root cause + fix:
  - Validate tokens by a **unique `sub`/ID**, never email; require **email verification**.
  - Add **tenant context into the JWT** (`tenant_id`/`aud`/`scope`) and **enforce it
    server-side** on access.
  - Sign JWTs with tenant-specific keys (or bind tenant in HMAC/claims); rotate keys.
  - **Never trust client-supplied headers** (Source) for security decisions — resolve
    tenant from the verified token + server context; log/alert cross-tenant reuse.
  - Test cases that simulate token reuse across tenants; run a tenant-segmentation
    red team test.

## Gotchas
- Some platforms key auth by email but also by `id`; read the token to see which
  claim the API actually uses (replay a token with a modified email to confirm).
- Per-tenant duplicate emails may be intentional (separate accounts); the flaw is
  that a token/cookie is then usable across tenants, or that identity resolution by
  email lets you impersonate.
- If the API derives tenant from the subdomain (not the header), test token reuse
  across subdomains directly.
- Only use your own two test tenants and your own (or public, in-scope) emails; do
  not actually access real third-party tenants/clients.

## JWT security checklist (defense / audit a SaaS multi-tenant app)
**Token design**
- Use immutable identifiers (`sub` / `user_id`) for validation — never rely on
  `email`/`username`/mutable claims for authorization.
- Bind tokens to tenant: include `tenant_id`, `aud`, or `scope` claims and enforce
  them server-side.
- Set a reasonably short `exp`; validate it.
- Sign with strong asymmetric algos (RS256/ES256); reject `none` and algorithm
  confusion (HS256 vs RS256 — see `oauth-security`).

**Email handling**
- Require email verification before account activation / token issuance.
- Prevent duplicate-email registration across tenants unless explicitly designed.

**Multi-tenant isolation**
- Use per-tenant signing keys or key rotation.
- Ensure the token's `tenant_id` matches the request context (e.g. subdomain).
- Never trust client-supplied headers (`Source`, `X-Tenant-ID`) without
  cryptographic verification.
- Validate and log cross-tenant token reuse; alert anomalies.

**App / API security**
- Enforce strict header sanitization + validation.
- Audit/monitor for token misuse across tenants.
- **During pentest, specifically test token replay across subdomains** (see the
  exploit checklist above) and token/header spoofing on every tenant-facing endpoint.
