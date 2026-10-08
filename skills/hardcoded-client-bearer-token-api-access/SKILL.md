---
name: hardcoded-client-bearer-token-api-access
description: Hardcoded bearer/API token exposed in publicly loaded JavaScript, source maps, config, or web assets, where the token has broader privileges than a normal user session. Test by searching Burp/JS for token, bearer, authorization, apikey, jwt, secret; safely validate against owned endpoints; compare normal user 403 on collection/foreign-object endpoints with exposed-token 200. Impact can include all chats, users, records, or admin APIs. Covers client-side secret exposure, service-token scope mismatch, broken access control via leaked token, and mass data disclosure. Triggers on hardcoded bearer token in JS, exposed API key, authorization token in frontend bundle, all chats accessible with token, service credential in source map.
---

# Hardcoded Client Bearer Token → Broad API Access

A browser-delivered JavaScript file contains a hardcoded `Bearer`/API token. The
frontend is public, so anyone can retrieve the token. The token may be a service,
internal, demo, or over-privileged credential with access far beyond the normal user
session.

## Discovery

Search loaded JS, source maps, manifests, inline configuration, and network history
for:
```
token  bearer  authorization  apikey  api_key  jwt  secret  client_secret
```
Common sources: `/_next/static`, `/static`, webpack bundles, `.map` files,
`runtime-config`, public environment configuration, and embedded SDK setup.

## Privilege-differential validation

1. Establish the normal-user baseline:
   ```http
   GET /api/v1/chats/<owned-id>
   Authorization: Bearer <normal-user-token>
   ```
2. Test a second owned object or collection endpoint; confirm normal user receives
   403/limited results (`GET /api/v1/chats` or another user's chat is denied).
3. Safely use the exposed token against a minimal read-only owned endpoint.
4. Compare scope: does the exposed token return a collection or other users' objects?
   Example:
   ```http
   GET /api/v1/chats
   Authorization: Bearer <exposed-token>
   ```
   If it returns all users' chats/PII while normal sessions get 403 → token scope /
   broken access-control failure.
5. Stop at minimal proof; do not dump the entire dataset or access third-party chats.

## Impact

Depending on token privileges:
- All chat conversations and sensitive content.
- All users, records, files, or tenant data.
- Write/admin endpoints reachable with the same token.
- Cross-tenant data if the service token is not tenant-scoped.

## Checklist

- Search all client assets and source maps for credential-like strings.
- Determine whether the token is static, expired, environment-specific, or rotated.
- Decode JWT claims if applicable: `sub`, `aud`, `iss`, `scope`, `exp`, `tenant_id`.
- Compare normal user vs exposed token on owned object, foreign object, collection,
  and one low-impact write endpoint only if explicitly authorized.
- Check whether the token works on alternate API hosts and versions.
- Verify revocation/rotation after disclosure through the program.

## Reporting and remediation

Classify as **sensitive credential exposure + broken access control / excessive token
privilege** (CWE-798, CWE-312, CWE-200, CWE-862). Include the asset containing the
redacted token, baseline 403, exposed-token 200, and minimal impact proof.

Never ship bearer tokens or client secrets in browser assets. Use a backend proxy,
short-lived audience-bound tokens, least-privilege scopes, tenant-bound claims,
secret rotation, and server-side authorization on every object and collection.
Revoke the exposed token immediately; removing it from JavaScript alone does not
invalidate copies in caches, history, or downloaded bundles.

## Safety

Use only authorized test accounts and a redacted token sample in reports. Do not
collect or publish chat contents, secrets, or bulk third-party records.
