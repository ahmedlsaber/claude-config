---
name: client-side-path-traversal
description: Client-side path traversal in JavaScript-constructed API paths -> unauthorized access/action. When client-side JS builds a request URL/path by concatenating a user-controllable value (e.g. sessionId from a query string) into a template literal such as `/api/users/sessions/${sessionId}`, injecting `../` traversal sequences redirects the request to a different resource (e.g. `/api/users/profile`) — and if the server does not normalize the path or enforce authz on every endpoint, actions like DELETE can hit unintended targets (account/profile deletion). Methodical hunting: scan JS for sensitive verbs (delete/post/put/patch) with template-literal or string-concatenated paths, identify user-influencable params, inject `../` + endpoint variants, and observe whether the server executes the redirected request. Root cause: unsanitized user input + no server-side path normalization + weak per-endpoint authorization. Triggers on client-side path traversal, ../ in JS API path, sessionId ../ profile deletion, template literal /api path injection, delete session -> delete account, JS-sink path manipulation.
---

# Client-Side Path Traversal (in JS-built API paths)

A server-side flaw reached through a **client-side injection**: the app's JavaScript
builds an API path by concatenating a user-controlled value, so an attacker can make
the client (or a crafted request) target a **different endpoint** than intended —
and if the server doesn't normalize the path or enforce authorization per endpoint,
a sensitive action (DELETE/POST) lands on an unintended resource (e.g. account
deletion).

## The vulnerable pattern

```js
if (userConfirmed) {
  fetch(`/api/users/sessions/${sessionId}`, { method: "DELETE", credentials: "include" })
    .then(res => { if (res.ok) alert("Session deleted"); ... });
}
```
`sessionId` is taken straight from the query string and concatenated **unvalidated**
into the URL path. Inject traversal:
```
https://app.example.com/delete-session?session=../profile
→ DELETE /api/users/sessions/../profile  →  (normalized) DELETE /api/users/profile
→ {"message":"Account deleted successfully"}
```
Instead of deleting a session, the request deletes the user's **profile/account**.

Also note: an open redirect / path confusion can combine — if a "safe" path had a
redirect or the resource id is guessable, account deletion of OTHER users is possible.

## Why it works (root causes)
1. **Unsanitized user input** concatenated into a path (no allowlist / ID validation).
2. **No server-side path normalization** (`..`/`%2e%2e` not resolved/rejected).
3. **Weak per-endpoint authorization** — the server executes the redirected endpoint
   as if authorized by the original context.

## Methodical hunting (client-side JS review)
1. **Scan for sensitive verbs**: search the JS for `delete`, `put`, `patch`, `post`
   fetches that touch user data / files.
2. **Spot concatenated paths**: find template literals or string concat with a
   user-influencable variable in the URL:
   - `` fetch(`/api/users/sessions/${x}`,...) ``
   - `` fetch('/api/' + id + '/delete') ``
   - `url = base + param`
   Where does the variable come from (query string, body, route param, another
   response)?
3. **Test traversal injection**: set the variable to `../endpoint`, `..%2fendpoint`,
   `%2e%2e%2f...`, nested `../../...`; also try `%252e` double-encoding. Observe if the
   resulting request targets a different, sensitive endpoint and the server executes it.
4. **Check server reaction**: if it responds as if the redirected endpoint ran
   (e.g. no 400/404 normalization error, and a side effect happens), it's vulnerable.
5. Confirm scope: the reached endpoint may be a different user's object if ids are
   guessable — test only on your own accounts.

## Reusable checklist
1. Read the app's JS (bundles, `_next/static`, `/static`) for fetch/XHR calls with
   verbs and dynamic paths.
2. Identify which path segments are user-influenced and concatenated.
3. Inject `../` (and encoded variants) to redirect the request to nearby sensitive
   endpoints; note which endpoints resolve without normalization.
4. Verify the redirected action actually executes (side effect / response) and its
   impact (delete profile/account, read other resource, etc.).
5. Consider chaining: open redirect, path confusion, guessable ids → other users.
6. Use own accounts only; abort on third-party data.

## Reporting
- Classify as **path traversal / improper input validation → unauthorized access or
  object deletion** (CWE-22 / CWE-20 / CWE-284 / CWE-863). Account deletion = High.
- Include: the JS snippet (unvalidated `sessionId` in a DELETE path), the crafted
  `?session=../profile` URL / `DELETE /api/users/sessions/../profile`, and the
  server's executed deletion response.
- Root cause + fix: validate/allowlist the id (isValidSessionId) before building the
  path; **normalize paths server-side** and reject `..`/encoded traversal; run
  **authorization per endpoint** so a redirected request can't hit a sensitive one;
  prefer a server-side logout that clears the session rather than a session-id-in-URL
  delete.

## Gotchas
- The traversal is a **client-side** input that becomes a **server-side** path flaw;
  the finding is real even if "just" the request path is changed, provided the server
  honors it without normalization/authz.
- Some frameworks normalize `..` and fail the request (400/404) — that's the safe
  case; confirm the server actually resolves/executes the redirected path.
- If ids are guessable and the endpoint authorizes by id only (no ownership), this
  can extend to other users — test on your own two accounts and report the scope.
