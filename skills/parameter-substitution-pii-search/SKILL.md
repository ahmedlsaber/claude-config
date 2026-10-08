---
name: parameter-substitution-pii-search
description: Hidden parameter-name substitution on search endpoints. When the UI sends a generic parameter such as `keywords`, replace the parameter name with undocumented model/search fields such as `email`, `userId`, `username`, `phone`, or `role`; the backend may bind the new field and return user records or PII. Example: GET /user/api/search?keywords=amr&q=keywords -> change to /user/api/search?email=victim@gmail.com&q=email and receive the matching user's data. Covers hidden search parameters, model-field binding, user enumeration, email/PII disclosure, parameter-name fuzzing, and search authorization failures. Triggers on search endpoints, `q`/field selector parameters, keywords-to-email substitution, hidden email search, user enumeration via search API.
---

# Parameter-Name Substitution → Hidden Search / PII Disclosure

A search UI may expose only a generic field such as `keywords`, while the backend
accepts a client-controlled **field selector** or silently binds arbitrary parameter
names to model fields. Changing the parameter name can reveal undocumented search
modes and user data.

## Worked pattern

Normal UI request:
```http
GET /user/api/search?keywords=amr&q=keywords
```

Parameter-name substitution:
```http
GET /user/api/search?email=victim@gmail.com&q=email
```

If the second request returns the matching user's profile/PII, the endpoint exposes
an undocumented email-search capability that may be unavailable in the UI.

## Test method

1. Capture a normal search request and identify generic parameters (`keywords`,
   `query`, `q`) and any field selector (`q=keywords`, `field=name`).
2. Replace the **parameter name and selector together**:
   `keywords→email`, `name→username`, `query→phone`, `q=keywords→q=email`.
3. Try model-field candidates from JavaScript, response objects, and API naming:
   `email`, `userId`, `username`, `phone`, `role`, `organizationId`, `status`.
4. Confirm whether results expose data beyond the user's permitted scope.
5. Test authorization with a low-privilege account and stop after a few owned/test
   identities; do not mass-harvest PII.

## Impact

- User enumeration by email or username.
- Disclosure of names, emails, phones, roles, organization membership, or profile data.
- Cross-tenant search if tenant scoping is missing.
- Sensitive search fields exposed through an endpoint intended only for autocomplete.

## Root cause and fix

The backend accepts arbitrary field names or trusts a client-supplied field selector
without an allowlist or authorization check. Fix by allowing only explicit searchable
fields, applying per-tenant/per-user authorization to results, limiting result data,
and rejecting unsupported parameter names.

Cross-reference `js-hidden-endpoint-mass-pii`, `idor-methodology`, and
`tamperable-identity-cookie`.