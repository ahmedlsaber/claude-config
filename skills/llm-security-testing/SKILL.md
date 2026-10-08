---
name: llm-security-testing
description: OWASP Top 10 for LLM / GenAI Applications (2026 edition) security testing methodology. Covers all ten risks and how to test each: LLM01 Prompt Injection (direct + indirect, incl. EchoLeak CVE-2025-32711), LLM02 Sensitive Information Disclosure (canary secrets, cross-user data, context exfil), LLM03 Excessive Agency (overprivileged tools, approval bypass, unsafe autonomous actions), LLM04 Supply Chain (model/dataset/adapter/dependency provenance), LLM05 Data and Model Poisoning (tampered RAG/fine-tune data, hidden triggers), LLM06 Unbounded Consumption (token/cost exhaustion, recursion, model theft), LLM07 Misinformation (false high-stakes output), LLM08 Hidden Context Exposure (system prompt, RAG schema, policy logic), LLM09 Vector and Embedding Weaknesses (cross-tenant retrieval, poisoned vectors, embedding inversion), LLM10 Improper Output Handling (XSS/SQLi/command injection from model output). Includes the agentic-AI note (prompt injection -> agency -> context leak -> unsafe output), how to test each risk, and layered defense. Triggers on LLM, GenAI, prompt injection, RAG, agent, fine-tuning, LLM security testing, OWASP LLM Top 10, AI security.
---

# OWASP Top 10 for LLM Applications (2026) — Testing Methodology

The LLM Top 10 is the AI-specific risk list (separate from the classic web-app Top
10). 2026 edition (Aug 4, 2026) moved 8/10 entries, pushed **Excessive Agency** to
#3, broadened System Prompt Leakage into **Hidden Context Exposure**, held
**Prompt Injection** at #1, and uses 7,714 real incidents + community vote. LLM apps
usually sit inside a web app, so AI-specific tests layer on top of normal web-app
testing.

## The ten risks & how to test each

**LLM01 — Prompt Injection** (root cause of most LLM attacks)
- Direct (user manipulates the model) and **indirect** (malicious instructions hidden
  in a web page, doc, email, image, or RAG source the model later reads).
- Test: inject instructions into prompts AND into any content the model ingests
  (retrieved docs, emails, pages, images); try escape/separator tricks, base64,
  roleplay, multi-turn. EchoLeak (CVE-2025-32711, CVSS 9.3) = real zero-click indirect
  injection against M365 Copilot → data exfiltration with no interaction.
- Fix: input/output filtering; separate trusted system instructions from untrusted
  content; constrain privileges; human-in-the-loop for high-impact actions; treat all
  external content as hostile.

**LLM02 — Sensitive Information Disclosure**
- Leaking PII/secrets/proprietary data via responses, memorized training data, or
  over-retrieved context.
- Test: canary secrets, cross-user data access attempts, training-data leakage,
  context exfiltration.
- Fix: DLP/redaction in+out; keep secrets out of prompts; differential privacy;
  per-user access control on what the model can retrieve.

**LLM03 — Excessive Agency** (the 2026 riser, #6→#3)
- An agent that can call APIs/run code/modify data takes more action than its task
  needs; over-broad tools/permissions turn a wrong output into a wrong action.
- Test: overprivileged tools, approval bypass, unsafe autonomous actions (prompt-
  injected agent chaining tool calls into real damage), excessive API permissions.
- Fix: least privilege on every tool/integration; minimize actions (not just
  permissions); human confirmation for high-impact ops; continuous logging/audit.

**LLM04 — Supply Chain**
- Risk from third-party models, datasets, fine-tuning adapters (LoRA), and ML deps.
- Test: model/adapter/dataset/dependency provenance, integrity, version pinning,
  malicious packages.
- Fix: SBOM for model+data provenance; sign/attest; pin+scan deps.

**LLM05 — Data and Model Poisoning**
- Tampering with training/fine-tuning/RAG data to plant behavior or backdoors.
- Test: tampered RAG data, poisoned fine-tuning sets, hidden triggers, post-deploy
  behavioral drift.
- Fix: data provenance; sandbox+monitor training; watch drift; anchor outputs with RAG.

**LLM06 — Unbounded Consumption**
- Runaway resource use: denial of wallet (cost), model DoS, model theft via querying.
- Test: variable-length input floods, deliberately expensive queries, extended-
  reasoning/token exhaustion, recursive agent/tool fan-out, model extraction.
- Fix: rate limits/quotas/timeouts; cap input/output; route by cost; alert on spikes.

**LLM07 — Misinformation**
- Model emits false/unsafe output (renamed from Overreliance).
- Test: high-stakes false outputs, fabricated citations, unsafe recommendations,
  weak grounding.
- Fix: ground with RAG over trusted sources; fact-check; cross-verify high-stakes;
  communicate limits.

**LLM08 — Hidden Context Exposure**
- Broadened from System Prompt Leakage: extract system prompt, RAG schemas,
  retrieved documents, hidden policy/routing logic.
- Test: extract internal rules to bypass filters, embedded credentials/keys, mapping
  retrieval schema to craft better injection.
- Fix: never place secrets/trust-critical logic in prompts/context; isolate sensitive
  instructions; design assuming context leaks; monitor extraction.

**LLM09 — Vector and Embedding Weaknesses**
- RAG/vector-store/embedding-specific attacks (attackers+defenses differ from prompt
  injection).
- Test: cross-tenant retrieval, poisoned vectors, unauthorized vector-store access,
  embedding inversion (reconstruct sensitive source data).
- Fix: fine-grained access control on vector DBs; validate what's embedded; isolate
  tenants; monitor KB integrity + retrieval logs.

**LLM10 — Improper Output Handling**
- Passing unvalidated model output into downstream systems (the LLM is an untrusted
  source → XSS/SQLi/command execution).
- Test: XSS, SQL injection, command execution, unsafe Markdown/HTML, downstream parser
  abuse.
- Fix: treat every model output as untrusted; sanitize/validate; parameterized
  queries + CSP; encode output for destination context.

## The agentic through-line
Prompt injection (LLM01) → drives a real action (LLM03 Excessive Agency) → using
leaked context (LLM08) → with unsanitized output (LLM10). Treat every API/plugin/tool
an agent can reach as an **untrusted, privileged surface** (least privilege + human
oversight). OWASP also keeps a companion **Top 10 for Agentic Applications**.

## Reusable LLM test plan
1. **Map the surface**: every model endpoint, RAG source, agent tool/API, and where
   model output flows downstream (web page, SQL, commands).
2. For each risk, run the test column above (injection, canary/data, agency/approval,
   provenance, poisoning, consumption, misinformation, context extraction, vector,
   output sanitization).
3. **Chain risks**: a single creative path often spans several categories (e.g. an
   injected doc (01) → agent tool call (03) → exfil (02/08)).
4. Combine automated guardrails with manual adversarial testing — the damaging
   failures are chained, not isolated.
5. Because LLM features ship inside web apps, layer **standard web-app testing** on
   top (XSS/IDOR/CSRF on the surrounding app).

## Layered defenses to check for
Input/output guardrails · least-privilege agents (approval on high-impact) · data
protection (redaction/DLP/access control) · supply-chain integrity (SBOM/provenance)
· RAG/vector security · monitoring/observability (semantic logs, consumption alerts)
· continuous adversarial red teaming.

## Fit with other frameworks
Use the LLM Top 10 for risk coverage, MITRE **ATLAS** for adversary behavior, NIST
**AI RMF** for governance, **CWE** for mapping to software weaknesses, and **AIVSS**
for scoring/remediation. Also relevant: `2fa-bypass`, `client-side-feature-gating`,
`multi-tenant-token-isolation` for the surrounding app, and the Command/agent testing
already in this engagement.

## Gotchas
- Prompt injection is the root of most LLM attacks — always test it first, direct AND
  indirect (content the model reads).
- Agentic apps amplify every risk; verify agent tools enforce the caller's permission
  (see the agent tool-calling authz work in this engagement — Command/Ask-Mercury).
- Don't assume the model is "just a chatbot" — map where its output is executed or
  where its tools can act; that's where Excessive Agency and Improper Output Handling
  bite.
- Only test on owned/in-scope deployments; don't exfiltrate real users' data or
  trigger destructive agent actions.
