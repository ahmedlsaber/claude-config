---
name: supabase-rls-misconfiguration
description: Supabase/PostgREST REST API exposure caused by missing Row Level Security (RLS) on database tables, enabling unauthorized table-wide reads and powerful filter-based enumeration with the public anon key. When a table is created without ENABLE ROW LEVEL SECURITY (or with a permissive USING (true) policy), the publicly embedded anon key - and any authenticated user JWT - can SELECT/INSERT/UPDATE/DELETE every row through the PostgREST API (/rest/v1/<table>), and use PostgREST filters and operators (eq, ilike, in, or, order, limit, offset, embedded select=related(*), Prefer: count=exact) to enumerate records without dumping the table. Covers passive Supabase fingerprinting (X-Client-Info header, <ref>.supabase.co hostnames, /rest/v1/ + /auth/v1/ + /realtime/v1/ paths, @supabase/supabase-js createClient in JS bundles and package manifests, anon apikey JWTs), distinguishing missing RLS (exposure) from missing policies (deny-by-default, not a finding) and endpoint/path assumptions (schemas, views, SECURITY DEFINER rpc functions, related-table embedding), safe authorized validation on owned test projects/accounts with minimal metadata and one-record proofs only, strict prohibitions (no bulk dumps, no third-party or live victim records, no arbitrary public supabase.co targets, never service_role keys), impact/reporting, remediation with RLS enablement + least-privilege policies + FORCE ROW LEVEL SECURITY + grant hygiene + schema restriction, JWT/auth role considerations (anon vs authenticated vs service_role, auth.uid()/auth.jwt()), CI tests/monitoring, and CWE tags. Triggers on Supabase, PostgREST, /rest/v1/, missing Row Level Security, RLS bypass, anon key, supabase.co, table-wide read, PostgREST filter enumeration, supabase-js createClient, realtime postgres_changes, exposed database API.
---

# Supabase / PostgREST Exposure via Missing Row Level Security (RLS)

Supabase projects expose the Postgres database as a REST API through PostgREST.
Every table, view, and function in the exposed schema becomes an HTTP endpoint
under `/rest/v1/`. Access is gated by Postgres **Row Level Security (RLS)** plus
table privileges. When RLS is missing on a table, the **public anon key** — which
is embedded in every frontend by design — can read (and often write) every row,
and the API's filter operators turn into an enumeration oracle.

**The vulnerability is the missing RLS, not the API features.** PostgREST's
select/filter operators are normal, intended functionality; they only become
attack primitives when RLS is not enforced.

## 0 — Why this happens (the primitive)

1. Supabase = Postgres + PostgREST (auto REST API) + GoTrue (auth) + Realtime +
   Storage + Edge Functions.
2. Requests authenticate with:
   - `apikey` header or `Authorization: Bearer <jwt>` containing the **anon key**
     — a public, project-scoped JWT shipped in every client bundle; or
   - a signed-in user's JWT (role `authenticated`).
3. RLS is **off by default** for tables unless explicitly enabled with
   `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`.
4. With RLS disabled, PostgREST serves every row the role's table privileges
   allow. For the `anon` role that is the entire table.
5. The anon key is public by design, so "readable by anon" = readable by anyone
   on the internet. No authentication bypass needed — the key is right there in
   the frontend.

## 1 — Passive indicators (fingerprint only — NO testing implied)

Use these to identify that a target uses Supabase. **Fingerprint alone is not a
finding** — a supabase.co hostname, an anon key, or a `/rest/v1/` endpoint is
normal Supabase operation.

- **Hostnames**: `<project-ref>.supabase.co` (e.g. `abcdefghijklm.supabase.co`),
  or a custom domain pointing at Supabase.
- **Paths**: `/rest/v1/...` (PostgREST), `/auth/v1/...` (GoTrue),
  `/storage/v1/...`, `/realtime/v1/websocket` (Realtime).
- **Request shape**: `apikey: <anon-jwt>` header, `Authorization: Bearer <jwt>`,
  `X-Client-Info: supabase-js/2.x.x`, `Prefer: ...`, `Range: ...`,
  `Accept-Profile` / `Content-Profile` (schema selection).
- **JWT claims**: `"iss": "supabase"`, `"ref": "<project-ref>"`,
  `"role": "anon" | "authenticated" | "service_role"`, `"aud": "authenticated"`.
- **Response headers**: `Content-Profile`, `Content-Range`, `Content-Location`
  (PostgREST signatures).
- **Client code**: `@supabase/supabase-js`, `createClient(url, anonKey)`,
  `supabase.from('todos').select(...)`, `supabase.channel(...).on('postgres_changes', ...)`.
- **Package manifests**: `"@supabase/supabase-js"` in `package.json`, any
  `@supabase/*` dependency.
- **Realtime**: `/realtime/v1/websocket?apikey=...&vsn=1.0.0` —
  `postgres_changes` subscriptions stream row changes when replication is enabled
  for a table.

**Correct the unsafe claims**: never infer exposure from the fingerprint; never
probe arbitrary public supabase.co projects; only pursue a target you own or that
is explicitly in scope for an authorized engagement.

## 2 — Authorized scope & safety rules

- Test only Supabase projects/apps you own, or that are explicitly in scope for
  an authorized engagement.
- Use owned test projects first (local `supabase start` / `supabase db reset`, or
  a disposable project) to learn the response semantics safely.
- On an authorized target, use only **owned test accounts** and **owned test
  data** — one owned record, nothing else.
- **Prohibited**: bulk data dumps, paging through the dataset, reading or
  touching third-party/other-user records, using live victim data, and any
  write/delete proof against non-owned data.
- `service_role` keys bypass RLS **by design** and must never appear client-side;
  a leaked `service_role` key is a separate, more severe finding — do not use it
  to "prove" RLS exposure.

## 3 — Distinguish missing RLS vs missing policies (read the response)

The HTTP response tells you which state the table is in. Learn these semantics
before concluding anything:

| Situation | Response you get | Verdict |
|---|---|---|
| Table doesn't exist / wrong schema / wrong path | `404` (PGRST205 "Could not find the table") | Path assumption wrong — not a finding |
| Missing/invalid apikey | `401` | N/A |
| No privileges granted to the role | `403` / PGRST106 / error | Locked down |
| RLS **enabled**, zero policies (deny-by-default) | `200` with `[]` | **Not a finding** — over-locked |
| RLS **enabled**, restrictive policies | `200` with only matching rows | Normal |
| RLS **disabled** (never enabled) | `200` with all rows for anon | **Finding** |
| RLS enabled but permissive policy, e.g. `USING (true)` | `200` with all rows | **Finding** |

- **Missing RLS** (never enabled) = exposure. **Missing policies** (RLS enabled,
  zero policies) = deny-by-default, the opposite. Do not report the latter.
- An empty array `[]` with a valid anon key usually means RLS is ON and filtering
  everything out.
- Check which schema is actually exposed: `Accept-Profile: public` vs other
  schemas; the OpenAPI document served at `/rest/v1/` lists exposed relations and
  columns — treat it as metadata, not as a proof of exposure.

## 4 — Tables, views, functions, related tables

- **Tables**: `/rest/v1/<table>` — full CRUD when privileges allow.
- **Views**: also served at `/rest/v1/<view>`. Views have no RLS of their own;
  a `security_definer` view runs as its owner and **bypasses RLS**. Prefer
  `security_invoker` views (PG15+). Check the view's `security_barrier` /
  definer-vs-invoker setting before assuming a view is safe.
- **Functions**: `/rest/v1/rpc/<fn>`. `SECURITY DEFINER` functions execute as the
  owner and can bypass RLS or escalate privileges. Check function grants and the
  security context. PostgREST exposes only functions marked as such; a
  misconfigured RPC can be a write/read sink that RLS never guards.
- **Related tables (embedding)**: `?select=id,child(*)` follows foreign keys.
  PostgREST still applies the requesting role's permissions and RLS to embedded
  resources, so embedding only leaks when the related table's RLS is missing too.
  But a readable parent with an exposed child join is a common way "hidden" tables
  surface — enumerate FK relationships via the OpenAPI doc.

## 5 — PostgREST operators (API features, NOT vulnerabilities)

These are normal, documented query features of the API. Understand them so you can
(a) read evidence correctly and (b) design minimal proofs. **None of these is the
bug by itself**; they become enumeration primitives only when RLS is missing.

- **Projection / paging**: `select=col1,col2`, `order=col.asc`, `limit=`,
  `offset=`, HTTP `Range: 0-9` header, `Prefer: count=exact` (returns total row
  count in `Content-Range` without body rows).
- **Filters**: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `like`, `ilike`, `in`,
  `is` (null checks: `is.null`), `not`, `or=(...)`, `and=(...)`.
- **Set operators**: `cs` (contains), `cd` (contained in), `ov` (overlap).
- **Full-text**: `fts`, `plfts`, `phfts`, `wfts`.
- **Embedding**: `select=related(*)`.

Minimal-proof usage (see next section): a single filter (`?col=eq.<owned-value>`)
with `limit=1` returns exactly one owned record; `Prefer: count=exact` with `HEAD`
returns the row count with **no data body** — both are complete proofs that never
dump data.

## 6 — Safe validation (owned projects/accounts, minimal proofs)

1. **Reproduce on your own project**: create a table without RLS, call
   `/rest/v1/<table>` with the anon key, confirm all rows return. Learn the
   response semantics there, not on the target.
2. **On an authorized target with owned data**: register an owned test account,
   insert exactly **one** owned row.
3. **One-record proof**:
   `GET /rest/v1/<table>?select=<non-sensitive-col>&<owner-col>=eq.<owned-value>&limit=1`
   → confirm `200` and that the returned row is your owned row.
4. **Metadata-only proof**:
   `HEAD /rest/v1/<table>` with `Prefer: count=exact` → `Content-Range: */<N>`
   proves table-wide readability with zero PII transferred.
5. **Filter oracle proof** (still no dump):
   `?select=id&<col>=ilike.<pattern>&limit=1` → whether an arbitrary filter
   returns a row shows the filter is a usable oracle without pulling the dataset.
6. Save request/response pairs as evidence. Never page through the dataset, never
   request `select=*` on a large table for proof purposes.

## 7 — Impact & reporting

- **Confidentiality**: every table in the exposed schema readable by anyone with
  the anon key — PII, account data, business records, auth-adjacent data.
- **Integrity/availability** (when grants allow): anon INSERT/UPDATE/DELETE.
- **Function abuse**: overprivileged `SECURITY DEFINER` RPCs bypassing RLS.
- **Enumeration**: filters turn the API into a value oracle for arbitrary
  columns and patterns.
- **Severity**: depends on the exposed data — PII tables are High/Critical;
  non-sensitive tables may be Low/Medium. Report impact per table.
- **Report structure**: target + passive indicators (host, paths, headers,
  anon-key JWT claims), the minimal proof (one owned record and/or row count),
  affected tables/views/functions, root cause (RLS not enabled / permissive
  policy), remediation. Reference CWE tags (below).

## 8 — Remediation (RLS + least privilege)

- Enable RLS on every table:
  ```sql
  ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY;
  ```
- Table owners bypass RLS by default — force it for defense in depth:
  ```sql
  ALTER TABLE public.<table> FORCE ROW LEVEL SECURITY;
  ```
- Write least-privilege policies keyed to the authenticated identity:
  ```sql
  CREATE POLICY "own rows" ON public.todos
    FOR SELECT USING (auth.uid() = user_id);
  ```
- Audit and remove catch-all permissive policies (`USING (true)`,
  `WITH CHECK (true)`).
- Grant hygiene — revoke the broad defaults and grant only what each role needs:
  ```sql
  REVOKE ALL ON public.todos FROM anon;
  GRANT SELECT ON public.todos TO authenticated;
  ```
- Restrict the exposed schema in PostgREST config (`PGRST_DB_SCHEMAS` /
  `db-schemas`); never expose internal schemas.
- Views: use `security_invoker`; audit all `SECURITY DEFINER` functions; keep
  functions `SECURITY INVOKER` by default.
- Never ship `service_role` keys to clients.

## 9 — JWT / auth role considerations

- **Roles**: `anon` (unauthenticated), `authenticated` (signed-in user),
  `service_role` (server-only, bypasses RLS — never client-side).
- **JWT claims** used by policies: `sub` (= `auth.uid()`), `role`, `aud`,
  `ref`. Policies reference identity via `auth.uid()`, `auth.jwt()`,
  `auth.role()`, `request.jwt.claim.<name>`.
- If the app issues custom claims or multiple `aud` values, verify the policies
  resolve the correct identity; anon↔authenticated token confusion is its own
  class — cross-reference `multi-tenant-token-isolation`.

## 10 — CI tests & monitoring

- **SQL guard in CI** — these queries must return 0 rows to pass:
  ```sql
  SELECT tablename FROM pg_tables
   WHERE schemaname = 'public'
     AND rowsecurity = false;
  ```
  ```sql
  -- tables with RLS on but zero policies (over-locked, not exposure, but worth flagging)
  SELECT t.tablename FROM pg_tables t
   WHERE t.schemaname = 'public'
     AND t.rowsecurity = true
     AND NOT EXISTS (
       SELECT 1 FROM pg_policies p
        WHERE p.schemaname = t.schemaname AND p.tablename = t.tablename
     );
  ```
- **Policy unit tests**: as `anon`, expect `[]`/`0 rows` on tables that should be
  private; run with pgTAP or `supabase db test` in CI; fail the build on any
  RLS-less table.
- **Monitoring**: PostgREST access logs — alert on `?select=*` without
  `limit`/`Range`, large `Content-Range` counts, repeated filter-oracle patterns;
  Supabase audit logs for schema changes (`ALTER TABLE ... ENABLE ROW LEVEL
  SECURITY`); scheduled daily run of the RLS-check queries.

## Gotchas

- **Anon key exposure is by design** — a finding requires demonstrating readable
  rows, never just the key's existence.
- RLS enabled + zero policies = locked down (not a finding). RLS enabled +
  `USING (true)` = finding.
- Views have no RLS; `SECURITY DEFINER` views/functions bypass it.
- Embedding (`select=related(*)`) can surface "protected" related tables.
- Never dump, never page, never touch third-party data — one owned record or a
  row count is a complete proof.
- `Prefer: count=exact` + `HEAD` gives the row count with no data body — the
  cleanest minimal proof.
- Only test targets you own or that are in scope; never arbitrary public
  supabase.co projects.

## Related

- `multi-tenant-token-isolation` — cross-tenant/token-role isolation flaws
- `hardcoded-client-bearer-token-api-access` — leaked service/bearer tokens in JS
- `js-hidden-endpoint-mass-pii` — hidden API endpoints + mass PII disclosure
- `idor-methodology` — object-level authorization master methodology
- `mass-assignment` — bindable extra fields via API
- `unauth-id-pii-and-archive-id-harvest` — unauthenticated PII disclosure
- `graphql-testing` — adjacent auto-generated API surface (GraphQL)

CWE tags: CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive
Information), CWE-862 (Missing Authorization), CWE-639 (Authorization Bypass
Through User-Controlled Key).