---
name: oauth-security
description: Comprehensive OAuth 2.0 / OIDC / social-login security testing methodology. Covers OAuth actors (resource owner, client, authorization server, resource server), all grant types (authorization code, implicit, ROPC, client credentials, device, refresh), token types (access/refresh), and vulnerabilities per component: CLIENT (client-secret leakage, insecure redirect_uri/open redirect, weak/missing state -> login-CSRF, missing PKCE), AUTHORIZATION SERVER (parameter/redirect_uri validation, token expiration, refresh-rotation), RESOURCE SERVER (scope/audience/issuer validation, revocation/introspection, granular permissions), and TOKENS (leakage in logs/localStorage/URL hash, replay, JWT algorithm confusion HS256/RS256/alg=none). Cross-ref oauth-misconfiguration (tampered-callback ATO), sso-postmessage-pkce, and 2fa-bypass (social-login ATO). Triggers on OAuth, OIDC, social login, redirect_uri, client secret, PKCE, state param, JWT algorithm confusion, access/refresh token, account linking.
---

# OAuth 2.0 & Social-Login Security Testing

OAuth = **authorization** (delegated access with scoped tokens), not authentication.
It's everywhere (incl. social logins). Test every component and every grant flow.

## OAuth actors & where the trust breaks
- Resource Owner = the user (grants access).
- Client = the app wanting access (holds a client_id; confidential clients hold a
  secret).
- Authorization Server (AS) = authenticates owner, issues tokens.
- Resource Server (RS) = holds the data; validates tokens (local JWT verify or
  introspection) + checks scope/claims.

## Grant types (test each wherever used)
- **Authorization Code**: one-time code → access+refresh. (Add PKCE check.)
- **Implicit** (SPA): token direct in URL (hash) → leakage/old-style; discouraged.
- **ROPC**: user passes password to the client — high risk, only trusted clients.
- **Client Credentials**: M2M, client auto-auth.
- **Device Code**: user enters code on another device; device polls.
- **Refresh Token**: re-up access; must be **rotated** each use.

## Tokens (types & how they're handled)
- AccessToken (short-lived) / RefreshToken (long-lived "backstage pass").
- Where they live & leak: query param/fragment, LocalStorage/SessionStorage (JS-
  readable → XSS steals them), server/analytics logs (URL logging), Referer, browser
  history (hash). Opaque vs JWT (JWT = self-contained).

## Vulnerabilities by component

### 1) OAuth Client
- **Client-secret leakage**: hard-coded in front-end JS (DevTools-rippable), or
  committed to a repo. → impersonate the client.
- **Insecure redirect_uri / open redirect**: if `redirect_uri` isn't an exact
  registered match (wildcards, sloppy subdomain match) or the client site has an open
  redirect, the attacker injects their domain → the code/token is delivered to them →
  token theft / ATO.
- **Weak/missing `state`**: state prevents login-CSRF / code-swapping. Missing or
  static (`abc123`) state → session hijack / code-swap (see login-CSRF).
- **Missing PKCE** (public clients — SPA/mobile): without the code-verifier binding,
  a stolen authorization code can be redeemed by anyone.

### 2) Authorization Server
- **Shoddy validation**: not verifying `client_id`+`redirect_uri` match the DB; bad
  scope handling.
- **Token expiration fails**: non-expiring/long-lived tokens; no **refresh-token
  rotation** (attacker with a stolen refresh token re-ups forever).

### 3) Resource Server
- **Weak scope/role validation**: a read-only token able to write; not checking
  issuer/audience → any token from anywhere can pass.
- **No revocation**: logout/revoke not honored (esp. stateless JWTs) — token keeps
  working.

### 4) Tokens
- **Leakage**: full-URL logging (tokens in query/fragment end up in logs/analytics/
  error monitors); LocalStorage (XSS-read); Implicit hash in history/Referer.
- **Replay**: no TLS, no PKCE/client-binding → intercepted token replayed.
- **JWT algorithm confusion**: server trusts the token's `alg` header. If it expected
  RS256 (asymmetric) but accepts HS256 (symmetric) or `alg:none`, an attacker signs a
  forged token (e.g., with the public key / empty) → forged identity/authorization.
  Always pin the algorithm + verify signature with the right key; reject `none`.

## Using OAuth for AUTHENTICATION (social login) — risk areas
OAuth is not authn; using it as such adds attack surface. Test social-login ATO:
1. **Tamper the identity in the callback** (see `oauth-misconfiguration`) — the app
   trusts client-supplied email/name/id → register/login as the victim.
2. **Account linking by email** — linking to an existing account by IdP email alone,
   or linking a new external identity without owner confirmation (see `2fa-bypass` #9,
   `oauth-misconfiguration`).
3. **Login-CSRF / state**: attacker starts OAuth with their IdP acct, victim's browser
   consumes it → links victim's account to attacker's identity.
4. **ID token misuse in OIDC**: must validate the ID token (it is the authn result);
   not just the access token. Missing `nonce`, `azp`/`aud`, alg confusion.
5. **Open redirect on the client** + OAuth → token steering.

## Reusable OAuth test checklist
1. **Enumerate OAuth endpoints**: `/.well-known/oauth-authorization-server`,
   `/oauth/authorize`, `/oauth/token`, `/userinfo`, `/.well-known/openid-configuration`;
   grep JS for client_id/redirect_uri/authorize/token/scope.
2. **redirect_uri**: try exact, wildcard, open-redirect, path traversal, `//`,
   `%2f`, `@`, port variations → does the AS deliver code/tokens to an attacker URL?
3. **state**: missing / static / guessable → login-CSRF.
4. **PKCE**: does the code flow implement and enforce PKCE? Try redeeming a code
   with a wrong/no verifier.
5. **Client secret**: present in JS/committed? (public client with a secret = leak).
6. **Code/token leakage**: fragment/query/hash/localStorage/logs; Referer.
7. **Token endpoint**: is `client_id`+`redirect_uri`+code bound? Code replay, refresh
   rotation, expiry, scope to the token.
8. **Resource server**: test scope/audience/issuer enforcement (read token doing
   write; cross-client access).
9. **JWT**: algorithm confusion (HS256/RS256/none), signature verification, exp/aud.
10. **Social login / OIDC**: ID-token validation, callback email tampering, account
    linking, login-CSRF. Use two OWN test accounts.

Cross-reference: `oauth-misconfiguration`, `sso-postmessage-pkce`, `2fa-bypass`,
`account-takeover-flows`.

## Defenses (what to check is present)
- Exact redirect_uri whitelist (no wildcards), always https.
- Random, long, per-session `state`, verified on callback.
- PKCE on all public clients.
- Client secrets server-side only, rotated.
- Short access-token life + refresh rotation + revocation/introspection.
- JWT: pin algorithm, verify signature/issuer/audience/scope.
- Store tokens in secure HttpOnly cookies (not LocalStorage), never query/fragment.

## Gotchas
- Implicit flow leaks via URL hash → history/Referer/logs; treat as a finding when
  used for authn.
- LocalStorage + XSS = token theft; check storage location and any XSS sink.
- Refresh tokens must rotate — a reusable refresh token is a finding.
- Only use owned test accounts / your own OAuth apps; don't harvest real users'
  codes/tokens.
