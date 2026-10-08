---
name: unicode-homoglyph-bypass
description: Unicode normalization / homoglyph / full-width / IDNA bypass of domain and email blocklists, plus lookalike-account IMPERSONATION. Replace a letter with a visually-identical Unicode lookalike (e.g. 'İ' dotless/dotted I vs 'I'/'i', Cyrillic/Greek lookalikes, full-width letters, case-confusion) so a character-based deny/allow or duplicate/username check misses it, while the email/DNS/identity system normalizes (NFKC/IDNA punycode) it back to the real mailbox — bypassing owner rules like 'deny yopmail.com' OR creating homoglyph/case-confusion fake accounts that impersonate legitimate users (strangerwhite9 vs ѕtrangerwhite9). Triggers on: blocked-domain invite bypass, homoglyph, Unicode normalization attack, email punycode lookalike, IDN homograph, homoglyph/case-confusion username impersonation, duplicate-username bypass, 0xacb normalization table.
---

# Unicode Normalization / Homoglyph Bypass (domain & email blocklists)

Replace a letter in a blocked identifier (email domain, username, URL) with a
**visually-identical Unicode lookalike**, so a character-based filter (allow/deny
domain list, blocklist, profanity filter) doesn't match it — while the email / DNS /
identity system **normalizes** the address back to the real one (NFKC folding,
IDNA punycode for domains). Result: the blocked thing gets through anyway.

```
blocked:  "@yopmail.com"   (Deny-Only rule)
sent:     "@yopmaİl.com"    (İ = dotless i / U+0130 or U+0131 lookalike)
→ filter misses, but the mailbox resolves to the real yopmail.com account anyway
```

## The worked example (blocked-domain invite bypass)

1. Owner sets a **Domain Restriction** (Deny Only): block `yopmail.com`
   (Settings → Security → Domain Restrictions).
2. Try to invite anyone `@yopmail.com` → **error: blocked**.
3. Instead invite `email@yopmaİl.com` (replace the `i` in the domain with the
   Unicode lookalike `İ` / `ı`).
4. **Invite succeeds** and the invitation mail arrives **normally** at the real
   `@yopmail.com` inbox.
5. Impact: **breaks the owner's security rule** — a blocked domain is admitted to
   the project (rules violation / policy bypass).

## The homoglyph / Unicode normalization table

The canonical references for lookalike characters / generating variants:
- **https://0xacb.com/normalization_table** — Unicode normalization/lookalike table
- **https://www.irongeek.com/homoglyph-attack-generator.php** — homoglyph attack
  generator: paste a string, get lookalike/variant forms (and per-character confusables)
- Also "confusables" references: Unicode UnicodeConfusables.txt, IDN homograph resources

Key classes of lookalikes to try per target letter:
- **`i`/`I`**: `İ` (U+0130, Latin capital I with dot above), `ı` (U+0131, dotless
  small i), `í í`/`ì`/acute/grave i, Cyrillic `і` (U+0456), full-width `ｉ`
- **`o`/`O`**: `о` (Cyrillic small o U+043E), `ο` (Greek omicron), `0`, full-width
- **`a`/`A`**: `а` (Cyrillic a U+0430), `@`, full-width `ａ`
- **`e`/`E`**: `е` (Cyrillic e U+0435), `é`, full-width
- **`c`/`C`**: `с` (Cyrillic es U+0441), full-width
- **`p`/`P`**: `р` (Cyrillic er U+0440)
- **`m`/`M`, `n`/`N`, `s`/`S`, `t`/`T`**: Cyrillic/Greek/full-width alternates
- **Full-width forms**: `＠ｙｏｐｍａｉｌ．ｃｏｍ` (FF10-FF60 range)

Strategy: swap ONE letter in the blocked string for its lookalike, or convert the
whole string to full-width. The filter must then fail to match the lookalike, but
the platform/downstream must normalize (NFKC / IDNA) the address back to the real
one for delivery/auth.

## Reusable checks (where this applies)

1. **Email/domain allow- and deny-lists** — signup, invite, "restricted domain"
   rules, corporate domain whitelist. Replace a letter with a homoglyph or
   full-width form; check whether the user is created/emailed anyway.
2. **Profanity / moderation / keyword filters** — same-character trick bypasses the
   string match on content.
3. **URL/redirect host checks** — OAuth `redirect_uri`, SSRF host allowlists,
   open-redirect `next=` where the host is checked character-wise but the fetch/
   browser normalizes (IDNA punycode: `e␣xample.com` → `xn--...`).
4. **Username uniqueness / impersonation** — create a lookalike account of a
   privileged username/email.
5. **Password/policy or duplicate checks** comparing strings letter-by-letter.

## Application — lookalike-account impersonation (usernames) + case confusion

A high-impact use is creating **visually identical fake accounts** to impersonate a
legitimate user (phishing login, social engineering, confusion):

- **Homoglyph usernames**: The duplicate-username check compares raw code points, so
  these are "different" and both register:
  ```
  strangerwhite9          (Latin s, U+0073)
  ѕtrangerwhite9          (Cyrillic s, U+0455 — looks identical)
  ```
  Same for `twitter` vs `twіtter` (Ukrainian і U+0456). Generate variants with a
  homoglyph tool (IronGeek homoglyph generator / a normalization table) or by asking
  an LLM to produce a homoglyph variant of a username.
- **Case-confusion usernames**: if the platform treats usernames case-sensitively
  (uniqueness is	case-sensitive), `Support` and `support` / `Admin` and `admin` can
  BOTH be registered (2017 GitHub Octocat/octocat case). Users/admins may interact
  with the wrong (fake) account.

Impact: impersonation of a trusted/privileged user, phishing logins, confusion for
both users and admins, and social-engineering surfaces.

Test:
- Attempt to register the homoglyph/case variant of a target username; if both
  register → the uniqueness check is not normalization/case-aware.
- Check whether the platform surfaces any lookalike warnings or blocks mixed-script
  usernames. If not → report the impersonation/confusion gap (Medium; higher if it
  taints an admin/trusted identity or a login path).

For each: confirm the **downstream destination is identical** (email lands in the
same inbox, host resolves to the same server) — that's what makes it a real bypass
vs. a no-op or a typo'd wrong account.

## Reporting
- Report as a **policy/rules bypass** (or IDN homograph / input-validation) finding.
  The security impact is the *the owner's deny/access rules are bypassable*, enabling
  blocked domains/users/paths to be admitted.
- Include the exact lookalike, the blocked rule, and proof the delivery/action still
  resolved to the blocked target.
- Severity: often Medium (rules/policy violation) but can be High when it enables
  bypassing a security boundary (e.g. SSRF host allowlist, account-impersonation,
  domain-based trust).
- Root cause: filter compares on raw code points without Unicode/IDNA normalization,
  while the downstream normalizes. Fix = normalize both sides (NFKC + IDNA/punycode)
  before comparing.

## Gotchas
- If the filter normalizes on its side (NFKC/IDNA), the homoglyph folds back and is
  blocked — move on.
- Verify delivery actually reached the same inbox (some systems reject unknown
  normalized addresses).
- Test only on owned/authorized accounts and clean up test invites/accounts.
- Some anti-abuse systems specifically strip/handle common homoglyphs; if the simple
  swap fails, try the full-width form or a different lookalike letter.
