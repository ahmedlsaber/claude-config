---
name: graphql-testing
description: GraphQL API penetration-testing methodology. Covers GraphQL basics (schema/resolvers/queries/mutations/scalars/fragments/aliases), INFO GATHERING (endpoint fuzzing paths /graphql /graphiql /api/graphql etc., graphw00f fingerprinting), INTROSPECTION (enabled -> dump schema with InQL/Voyager; DISABLED bypasses: regex/newline manipulation, POST->GET, error-message field disclosure, auto-suggestion field brute-force/Clairvoyance, capture frontend requests), RATE-LIMIT BYPASS via aliases/batching, DoS (circular/deeply-nested queries, large lists, field duplication, alias/batch abuse, introspection abuse), INFORMATION DISCLOSURE (field stuffing/guessing, debug errors, query tracing/extensions, PII over GET, exposed GraphiQL playground, sensitive default queries), AUTH & AUTHORIZATION (no-auth check, restricted-field access, GET vs POST differences, alias/array brute-force of login), and CSRF (x-www-form-urlencoded abuse, SameSite/CORS/token mitigations). Triggers on GraphQL, introspection, /graphql endpoint, graphiql playground, alias rate-limit bypass, GraphQL schema dump, GraphQL IDsOR/authz, GraphQL CSRF.
---

# GraphQL API Pen-Test Methodology

GraphQL is a query language + runtime for APIs. Clients pick exact fields; one query
can pull related data. The attack surface is different from REST: a single endpoint,
schema introspection, flexible (alias/batch) querying, and resolvers that may
bypass authz. Framework-agnostic, so this is its own skill (like `nextjs-testing`).

## 1 — Discovery & fingerprinting
Fuzz these paths for a GraphQL endpoint:
```
/graphql /graphiql /graphql.php /graphql/console /api /api/graphql
/graphql/api /graphql/graphql /v1/graphql /v2/graphql /graphql/v1 /gql
/graphql-playground /playground /altair /query /graphql/query /graphql-explorer
/api/v1/graphql /api/v2/graphql /public/graphql /private/graphql /internal/graphql
```
Fingerprint the engine with `graphw00f -t https://target.com/graphql` (identifies
engine + known misconfigs).

## 2 — Introspection (enabled or disabled)
**Enabled** — dump the schema (lists every query/mutation/type/field/arg):
```gql
{ __schema { types { name fields { name args { name type { name } } } } } }
```
(or the full-dump query with fragments). Tools: InQL (Burp), GraphQL Voyager.
This reveals sensitive ops (deleteUser, resetPassword, getAllUsers, passwordHash).

**Disabled** — bypass to recover the schema:
1. **Regex manipulation** — block filters often strip `__schema`/`__type` strictly;
   add a space/comma/newline after `query{`: `"query{ __schema{queryType{name}}}"`
   and `"query{\n__schema{...}}"` (newline may bypass a naive regex).
2. **Switch POST→GET** — if blocked on POST, try
   `https://target/graphql?query={__schema{queryType{name}}}`.
3. **Error-message disclosure** — send an invalid field; errors reveal valid
   fields/types: `{ "query": "query { randomField }" }` → "randomField does not
   exist, but `userProfile` does".
4. **Auto-suggestion brute-force** — if errors return "did you mean" suggestions,
   reconstruct the schema: tool `Clairvoyance <url> -w <dict> -o out.json`, or
   manually submit candidate fields and read the hints.
5. **Capture frontend requests** — the app must call GraphQL; intercept the web/mobile
   API calls with Burp to learn real queries/mutations.

## 3 — Rate-limit bypass via aliases / batching
One HTTP request can carry multiple queries. If the limiter counts requests (not
operations), alias every query:
```gql
query { user1: getUser(id:"123"){} user2: getUser(id:"123"){} ... user8: getUser(id:"123"){} }
```
8 executions counted as 1 request → fetch way more than the limit. Also try
**array-based batching** `[{query:...},{query:...}]`.

## 4 — DoS / query abuse
- **Circular/deeply nested** queries: `friends { friends { friends { ... } } }` →
  unbounded recursion consuming CPU/memory.
- **Large lists**: `users(first:10000){...}` — fetch thousands of rows.
- **Field duplication**: repeat the same field thousands of times.
- **Alias abuse / batch** — same query under many aliases, or many different queries.
- **Introspection abuse** — hammer `__schema` repeatedly.
Mitigations to test/find: query-depth/complexity limits, per-resolver/operation caps,
value limits, alias/batch detection.

## 5 — Information disclosure
- **Field stuffing/guessing** — request many candidate fields (`password`,
  `passwordHash`, `token`, `email`, `admin`); if the server returns them → PII/
  secret leak. Also `__typename` probing.
- **DebLabels / debug errors** — malformed queries return stack traces, DB queries,
  paths (Syntax Error + stack). Use to learn the backend.
- **Query tracing / extensions** — some servers add `extensions.tracing`
  (per-resolver timings), complexity, versions, cache status. Analyzable.
- **PII over GET** — `?query={user(id:"1"){name,email,address}}` → data in URL/logs/
  history/proxies.
- **Exposed GraphiQL/Playground** in production → interactive IDE for anyone.
- **Sensitive default queries** — e.g. `allUsers { id name email passwordHash }`
  may be pre-wired.

## 6 — Authentication & authorization
- **No-auth check** — send a query/mutation with NO Authorization header; if data
  returns → auth not enforced.
- **Restricted-field access** — request `user(id){ passwordHash }`; if it returns →
  authorization flaw (resolver doesn't scope by viewer).
- **GET vs POST behavior** — same query both ways; differing auth = misconfig.
- **Brute-force via batching** — alias/array login attempts:
  ```gql
  query { a1: login(user:"admin",pass:"p1"){token} a2: login(user:"admin",pass:"p2"){token} }
  ```
  If no rate limit on operations → brute-force.

## 7 — CSRF
GraphQL is NOT CSRF-immune. Risks when the API accepts
`application/x-www-form-urlencoded` or `text/plain` with cookie/session auth:
- **x-www-form-urlencoded abuse**: encode the mutation as form data; an HTML form
  auto-sends the victim's same-origin session cookies → state-changing mutation
  executes on the victim. Test: change a legit mutation's Content-Type to
  `application/x-www-form-urlencoded` + reformat body; if it runs → CSRF.
Mitigations to look for: JSON-only enforcement (reject form/text), CSRF tokens on
mutations, `SameSite=Strict/Lax`, no `ACAO:*`, frame-busting (`X-Frame-Options
DENY` / CSP).

## 8 — Reusable checklist
1. Discover + fingerprint the endpoint (paths, graphw00f).
2. Introspection (or a disabled-introspection bypass: regex/newline, GET, errors,
   suggestions/Clairvoyance, capture frontend).
3. Dump schema; map queries/mutations + args; flag sensitive ops/fields.
4. Authz: no-auth requests, restricted-field access, GET vs POST, nested/alternate
   paths, IDOR on id args (see IDOR skills).
5. Rate-limit: alias/batch bypass on login/OTP/reset/read.
6. DoS/query-abuse: deep nesting, big lists, dup fields, aliases, introspection.
7. Info disclosure: field stuffing/guessing, debug errors, tracing/extensions,
   PII over GET, exposed IDE, default queries.
8. CSRF: form-urlencoded mutations with session cookies.
9. Own accounts only; don't mass-dump real users' data.

## Gotchas
- Introspection disabled is not "safe" — errors/suggestions/frontend capture still
  leak the schema.
- Aliases/batching can amplify both brute-force AND DoS — respect rate limits and
  caps; stop before real impact.
- Watch for per-operation cost/query-complexity limits added to mitigate alias/DoS —
  test whether they're actually enforced.
- CSRF needs cookie/session auth + a non-JSON content type accepted; if it's
  JSON-only with no cookie auth, CSRF is mitigated.
