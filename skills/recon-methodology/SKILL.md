---
name: recon-methodology
description: Scope-aware, passive-first reconnaissance for bug bounty and pentest engagements — asset discovery, subdomain/live-host mapping, ASN expansion, ownership validation, TLS/origin fingerprinting, CDN differentiation, bounded active probing, evidence rules; Part 2 adds Windows-aware active network/service mapping, vhost-vs-DNS subdomain discovery, bounded brute-force/permutation resolution, and unsafe-scan fencing.
category: information-gathering
version: "2.1"
tags: [recon, enumeration, osint, subdomain, tls, fingerprinting, cdn, origin-ip, asn, whois, passive, nmap, vhost, brute-force, active, windows]
cwe_ids: [CWE-200, CWE-16, CWE-319, CWE-326, CWE-327, CWE-425, CWE-538, CWE-615, CWE-345, CWE-441]
---

# Reconnaissance Methodology

Reconnaissance turns an authorized target into a mapped attack surface. This skill is **passive-first**: exhaust public and third-party data before sending a single packet, keep active probing bounded and rate-limited, and validate every candidate asset before treating it as in-scope.

The methodology is organized as: scope and target understanding → normal-user browsing → public-source portfolio expansion → passive mapping → ASN expansion → ownership validation → search-engine querying → TLS/origin fingerprinting → infrastructure differentiation → bounded active probing → evidence. **Part 2** extends the bounded active phase with Windows-aware network/service mapping, vhost-vs-DNS subdomain discovery, bounded brute-force/permutation resolution, and explicit fencing of unsafe scan techniques. A condensed **Repeatable Workflow** and a **Command Reference** (preserved tool-specific phases) are at the end.

## 1. Scope, Rules, and Target Understanding

### 1.1 Read the Program Scope First

Before any enumeration:

- List the **explicitly in-scope assets**: domains, `*.domain` wildcards, IP ranges, mobile apps, APIs. Treat anything not listed as out of scope unless the program says otherwise.
- Note **out-of-scope / excluded items**: specific subdomains, third-party SaaS (payment processors, CDN control planes, ticketing), acquired companies not yet migrated, rate-limited or no-DoS clauses.
- Record the program's **rules of engagement**: allowed testing hours, prohibited techniques (DoS, phishing, social engineering, data destruction), and any "use test accounts only" requirement.
- Save the scope to `notes.md` (see Evidence and Notes Guidance). Re-check it whenever a new candidate asset appears — scope changes.

### 1.2 Authorization Model to Carry Through Recon

- A wildcard scope entry such as `*.target.com` authorizes **subdomains of target.com**. It does **not** automatically authorize:
  - every IP in an ASN that also hosts target.com (see §5, §6),
  - domains sharing the same WHOIS registrant or certificate,
  - co-tenants on shared hosting or a shared CDN edge,
  - the origin server behind a CDN, unless bypassing the CDN is explicitly in scope.
- When a discovered asset sits on a boundary (shared IP, reseller, acquirer), **verify with the program or treat it as out of scope**. Never assume.

### 1.3 Target Understanding

Before tooling up, answer: What does the product do? Who are the user roles (guest, member, admin, vendor)? Where does money or sensitive data move? Which third-party services are integrated (OAuth, payments, email, CDN, analytics)? What is the likely tech stack (framework, hosting, CDN)? This context tells you which subdomains and services are interesting and which are noise. (Deep business-model mapping is covered by the `bugbounty-workflow` skill — run that after recon, not instead of it.)

## 2. Normal-User Browsing and Note-Taking

The cheapest, highest-signal recon step is using the product the way a normal user would, **before** any scanning.

1. Create owned test accounts as permitted. Register, log in, browse key flows: signup, login, profile, search, checkout/payment (if present), support/contact, mobile app if in scope.
2. Watch the network panel while browsing. Note the API gateway host, endpoint naming conventions (`/api/v1/...`), authentication mechanism (cookie, bearer, signed headers), and any `sign`/signature headers.
3. Collect the **entry surface**: main domains, regional mirrors, staging/dev subdomains referenced by the frontend, API documentation endpoints (`/docs`, `/openapi.json`, `/swagger`), and static/CDN asset hosts.
4. Take **structured notes** as you go (see 2.2). Screenshot key pages and capture request/response pairs for anything unusual. Everything here is evidence if you later find a bug.

### 2.1 What to Record in Notes

- Auth model: session cookie vs JWT vs signed headers; guest vs authenticated surfaces; whether the same cart/session mechanism is shared between guest and user.
- Architecture: frontend framework, API gateway, backend service names, CDN, regional endpoints, error responses that leak internal hostnames.
- Interesting parameters and object IDs (user IDs, order IDs, addresses) — candidates for later IDOR testing (hand off to `idor-methodology`).
- Third-party integrations and trust boundaries.
- Anything that looks like a hidden or internal endpoint referenced in JS bundles (hand off to the appropriate testing skill; do not poke out-of-scope infrastructure).

## 3. Acquisition and Portfolio Expansion via Public Sources

Programs often cover more than the flagship domain. Find related assets from **public sources only**, and only keep additions that fall inside the declared scope (or get explicit authorization):

- **Product surfaces**: privacy policy, terms, and footer links (often list related domains and acquired brands); app-store listings (developer account pages list other apps); mobile app deep links and manifest files.
- **Registrar/WHOIS history**: historical WHOIS (SecurityTrails, WhoisXML, DomainTools) can reveal additional domains registered by the same organization — treat as a **hint**, not proof of ownership, and validate against scope.
- **Code and company presence**: public GitHub orgs/repos, Docker Hub, npm/GitHub package namespaces, job postings (reveal tech and internal tooling), SEC filings (list subsidiaries), press releases for acquisitions.
- **DNS-adjacent public data**: SPF/DMARC records (`include:` and `ip4:` mechanisms reference other infrastructure — see §9), MX records (mail provider), NS records.

Additions must still pass the §6 ownership validation and the scope check before any probing. Portfolio expansion is about **finding the authorized surface**, not about expanding authorization.

## 4. Passive Subdomain and Live-Host Mapping

Collect subdomains **passively** (no direct queries to the target), then resolve and probe lightly to find live hosts. Full commands are in the Command Reference, Phase 1.

1. Certificate transparency: crt.sh, CertSpotter, Censys — query by `%target.com`, not only `target.com`.
2. Passive DNS and search-engine sources: SecurityTrails, VirusTotal, DNSDumpster, Google/Bing site: queries, commoncrawl.
3. Aggregators: `subfinder -d target.com -silent` (passive sources only), `amass enum -passive`, `github-subdomains`.
4. Historical URLs: `waybackurls`, `gau` — these also recover dead endpoints, parameters, and old technology.
5. Merge and dedupe (`anew`), then **resolve** (`dnsx`) and **probe for live hosts** (`httpx` with `-title -status-code -tech-detect`). Screenshot live hosts (`gowitness`).

The resolution/probing step is the first *active* traffic — keep it light (single HTTP request per host, default concurrency). Save every list; they are evidence of coverage.

## 5. ASN → CIDR → IP Expansion

Once you know the organization's owned networks, expand ASNs to CIDRs to IPs. This is for scoping the *network* surface and for origin-IP discovery (§9).

1. Find the org's ASNs: `bgp.he.net` search by org name, RIPEstat/RIPE data API, Team Cymru WHOIS (`whois -h whois.cymru.com " -v <ip>"`), `amass intel -org <name>`.
2. Expand ASN → prefixes: RIPEstat `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<number>` or `bgpview.io` API.
3. Expand CIDR → IP list: `mapcidr -cidr <cidr> -silent` (or `nmap -sL`).
4. **Do not scan everything yet.** First validate ownership (§6) and filter to the org's own prefixes.

Critical caveat: a single ASN frequently carries many unrelated tenants (hosting providers, other customers, transit). An IP being in the same ASN as the target **proves nothing** about ownership — it is the start of a validation, not the end.

## 6. Ownership Validation (WHOIS, BGP, Certificate Evidence)

Before considering any IP/ASN/domain in scope, corroborate ownership with **multiple independent signals**. No single signal is sufficient.

- **WHOIS**: registrant organization on the domain; IP WHOIS for the address block (netname/org). Note that WHOIS org names can be outdated, use intermediaries, or be shared by resellers.
- **BGP**: origin ASN of the prefix (`whois -h whois.cymru.com " -v <ip>"`, bgp.he.net, RIPEstat). The origin AS should match the org, not a hosting provider's aggregation AS.
- **Reverse DNS / PTR**: `host <ip>` / `dig -x <ip> +short` — a PTR containing `target.com` or an obvious org abbreviation is corroborating evidence.
- **Certificate fields (weak hint only)**: a certificate's Organization (O) field, issuer, or SAN list that includes the brand is a **weak hint — it does NOT prove ownership**. Shared hosting providers, resellers, SaaS tenants, parked-domain services, and third-party integrators routinely present certificates containing a customer brand. Use cert fields to generate *candidates*, never to *conclude* ownership.
- **Corroborate**: an IP is reasonably attributable when BGP origin AS, WHOIS netname/org, and PTR (or an exact-match certificate SAN) all agree. When signals conflict, treat the asset as out of scope and move on.

## 7. Shodan / FOFA / ZoomEye Query Distinctions

These three services index the same internet but differ in data sources, query syntax, and strengths. They are **snapshots**, not live truth — always re-verify against the target before acting.

| Service | Focus / strengths | Query style | Typical use in recon |
| --- | --- | --- | --- |
| **Shodan** | Port/banner-level; deep on services, TLS certs, industrial/IoT; strong API | `hostname:target.com`, `ssl.cert.subject.cn:target.com`, `http.title:"Target"`, `http.favicon.hash:<mmh3>`, `net:<cidr>` | Finding exposed services, origin IPs via favicon/cert, TLS data across the org's netblocks |
| **FOFA** | Web-focused, aggressive web-content indexing; strong coverage of Asia/CN; excellent favicon (`icon_hash`) and body/title search | `domain="target.com"`, `title="Target"`, `icon_hash="<favicon-hash>"`, `cert="target.com"`, `ip="1.2.3.0/24"` | Web asset discovery, favicon-based origin hunts, web-title clustering |
| **ZoomEye** | Hybrid port+web index; strong global coverage, UI + API | `site:target.com`, `app:"Nginx"`, `port:"443"` + host/cert filters | Cross-checking Shodan results, geolocation-based asset discovery |

Notes:

- **Favicon hashes differ per engine**: Shodan uses `http.favicon.hash` (mmh3-based), FOFA uses its own `icon_hash` algorithm. A hash computed for one engine will not match the other — compute per engine.
- Query on the **org's validated netblocks** (`net:`) as well as hostnames — services on "forgotten" IPs won't show up in hostname searches.
- Respect each service's rate limits and API terms; results are historical, so confirm current state with a single bounded request (§12).

## 8. TLS Certificate / SAN / JARM / JA3 Fingerprinting and Legacy TLS Triage

### 8.1 Certificate and SAN enumeration

- Enumerate SANs from CT logs and live certs — SANs frequently reveal staging, admin, and internal subdomains: `crt.sh` JSON output (Phase 1), `tlsx -san`, `openssl s_client -connect host:443 -servername host 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"`.
- Cluster hosts by certificate issuer and leaf identity — hosts sharing a cert or an org-wide CA are likely part of the same estate (still validate ownership per §6).

### 8.2 JARM and JA3/JA3S

- **JARM** fingerprints a *server* by its TLS responses to a set of crafted ClientHellos (TLS stack behavior, not config version). Stable across IPs on the same TLS stack — ideal for finding the "real" backend behind a CDN: `jarm -i hosts.txt` or `python3 jarm.py host:port`. Same JARM behind a CDN and an origin candidate is strong linking evidence.
- **JA3/JA3S** fingerprint *clients* (JA3) and the *server's* response (JA3S) by TLS handshake details. Useful for detecting known-bad clients on the target (C2, scanners) and for confirming your own tooling is consistent: `tlsx -u https://target.com -ja3 -ja3s`, Zeek/Suricata logs, or `ja3` Python package.
- JARM/JA3 are **correlation tools, not identity proofs** — TLS-stack fingerprints can collide across unrelated software versions.

### 8.3 Legacy TLS triage (do not auto-report)

- Detect protocol floors and cipher strength: `testssl.sh --fast host`, `sslscan`, `nmap --script ssl-enum-ciphers`.
- **Finding SSLv3/TLS 1.0/1.1 or weak ciphers is a hardening observation — it is NOT automatically a reportable vulnerability.** Whether it matters depends on: the program's stated policy on protocol/cipher findings (many mark them informational or out of scope), real exploitability (an actual attack path such as POODLE/DROWN/ROBOT against a service that still supports the protocol), and whether sensitive data actually transits the affected endpoint.
- Triage as a data point for the asset map; only escalate when you can articulate a concrete, in-scope, exploitable impact. See Remediation and Reporting Boundaries (§14).

## 9. Origin-IP Discovery

Purpose: when a site sits behind a CDN, find the origin server address. Only pursue this when (a) it is in scope and (b) you will verify — a raw origin IP is not a finding by itself.

1. **Favicon hashes**: fetch the site's favicon, hash it, and search the engines from §7.
   ```bash
   # mmh3 favicon hash for Shodan http.favicon.hash:
   python3 -c "import mmh3,requests,codecs;r=requests.get('https://target.com/favicon.ico',verify=False);print(mmh3.hash(codecs.encode(r.content,'base64')))"
   # then query: http.favicon.hash:<hash>  (Shodan)  or  icon_hash="<hash>"  (FOFA)
   ```
2. **SPF / DMARC records**: `dig TXT target.com +short` — `include:` and `ip4:` mechanisms enumerate mail-sending infrastructure that often lives on non-CDN, first-party IPs.
3. **Censys / passive DNS**: Censys search `services.tls.certificates.leaf_data.names: target.com` and historical/passive DNS (SecurityTrails, DNSDumpster, ViewDNS, VirusTotal) — look for A records that predate the CDN.
4. **Historical DNS**: old A records from passive DNS archives frequently point at the pre-CDN origin. Cross-check with the Wayback Machine for old IPs in page source (e.g., old asset URLs).
5. **Candidate verification** — for each candidate IP, confirm with **multiple** checks:
   - Send a request with the **target's Host header** directly to the IP (`curl -k -H "Host: target.com" https://<ip>/`) and compare the response to the CDN-fronted response (same app? different certificate?).
   - Compare the **TLS certificate** served by the IP to the CDN cert — an org-issued cert matching the domain is corroborating (still not proof of ownership; see §6).
   - Compare **JARM** (§8.2) between the CDN edge and the candidate IP.
   - Check if the IP responds on non-standard ports (SSH, 8080, 8443, RDP) or has a PTR consistent with the org.

Caveats: a verified origin IP still only matters if the CDN bypass yields an in-scope, exploitable difference (e.g., missing WAF, direct admin access). If the origin IP belongs to shared hosting or a third-party provider, stop — it is out of scope (§12). Every request to a candidate IP must be bounded and low-rate.

## 10. Infrastructure Fingerprinting and CDN/Origin Differentiation

Determine what sits in front of the target and what is behind it:

- **Identify the CDN** from: response headers (`server: cloudflare`, `x-cache: hit from cloudfront`, `via:`/`x-via` Akamai markers), certificate issuer (Cloudflare Inc, Amazon, Akamai, Fastly), IP ownership (CDN ASNs), and error-page branding.
- **Differentiate CDN from origin** using: `curl -sI https://target.com/` header set vs `curl -sI https://<origin-ip>/ -H "Host: target.com"`; response differences (cache headers, `x-powered-by`, error bodies, TLS cert identity); and JARM clustering (§8.2).
- **Map the tiers**: CDN edge → WAF/proxy (e.g., Akamai, CloudFront) → API gateway → application servers → data stores (from leaked headers/errors only; do not actively scan the interior).
- Note the CDN config quirks that matter for later testing (cache behavior, which paths bypass cache, presence of `X-Forwarded-*` handling) and hand off to the relevant testing skill — do **not** attempt CDN bypass on out-of-scope infrastructure.

## 11. Automation Pipelines

Recon is repetitive; pipeline it, but keep every stage bounded and logged.

Typical passive→active pipeline (one command per stage, outputs appended with `anew`):

```bash
# Stage 1 - passive collection (no direct target traffic)
subfinder -d target.com -silent | anew subs.txt
amass enum -passive -d target.com | anew subs.txt
echo "target.com" | gau --threads 3 | anew urls.txt

# Stage 2 - resolution + light probing (first active traffic)
cat subs.txt | dnsx -silent -a -resp | anew resolved.txt
cat resolved.txt | httpx -silent -title -status-code -tech-detect -rl 20 | anew live_hosts.txt

# Stage 3 - bounded, throttled checks (only in-scope hosts, per program RoE)
cat live_hosts.txt | nuclei -rl 10 -severity low,medium,high,critical -o nuclei_results.txt

# Stage 4 - periodic re-run (schedule hourly/daily via cron/scheduled task)
```

Rules for pipelines:

- **Rate-limit everything**: `httpx -rl`, `nuclei -rl`, `nmap -T3 --max-rate`, low `feroxbuster -t`. Never run default-aggressive scans unattended.
- **Dedupe with `anew`** so re-runs only add new data.
- **Keep audit trail**: each run writes a dated log; record tool versions (`tool -version`) in `notes.md`.
- **Scope-filter before scanning**: feed the pipeline only validated, in-scope hosts. An automation bug that scans a wildcard list can touch third-party assets — filter at every stage.
- **Stop conditions**: pipelines must not run intrusion-level scans (masscan at high rate, full `-p-` sweeps of entire /16s) without explicit authorization; prefer top-ports, low concurrency, and daytime windows per RoE.

## 12. Authorization and Safety Caveats

Strict rules that override any technique in this skill:

1. **Wildcard scope does not authorize everything.** `*.target.com` authorizes subdomains of that domain only. It does NOT authorize: unrelated IPs in the same ASN, co-tenants on shared hosting, domains sharing a registrant/cert, or the origin server behind a CDN when bypassing the CDN is not in scope.
2. **Shared hosting is a boundary.** If an IP hosts multiple unrelated tenants (reverse-IP lookups show many domains, the certificate lists foreign SANs, PTR is generic), you may not scan or exploit that IP beyond a single low-rate request for identification.
3. **Keep active probing bounded.** Prefer passive sources (§4, §7). When active: use top-ports and low rates, limit concurrency, throttle per host, and stop on any sign of third-party data. Full TCP sweeps, UDP scans, and high-rate masscan require explicit authorization and are typically unjustified in bug bounty.
4. **No third-party data.** Any request pattern that could return or modify another user's/tenant's data is an abort condition. Use owned test accounts only.
5. **CDN bypass is authorization-sensitive.** Finding an origin IP is fine; actively attacking the origin (or the CDN control plane) is only allowed if those assets are in scope.
6. **Do not weaponize recon results.** Do not use discovered credentials, internal hostnames, or exposed data beyond what is needed to demonstrate impact; never exfiltrate or dump data.
7. **When in doubt, verify scope with the program** or drop the asset. Missing a finding is better than touching an unauthorized system.
8. **Unsafe scan techniques are out of routine scope.** FIN/NULL/Xmas scans are unreliable on Windows and are not a default. Idle/zombie scans, source-port manipulation, source-IP spoofing, decoys, and fragmentation are authorization-sensitive, can affect third parties, and are documented as theory only (§13.12). Never spoof a third-party IP.
9. **No credential spraying, no exploitation, no high-rate scanning.** Part 2 maps and identifies services; it does not attack them. Authentication/authorization testing, exploitation, and credential brute-forcing belong to later skills with their own authorization gates.

## Part 2: Active Network, Service, and Host-Header Mapping (Windows-aware)

Part 2 extends Part 1 from "map the attack surface passively" to "understand what is actually listening and how hosts are reached." It is **active** by definition, so every step stays bounded: in-scope hosts only, low rates, top-port lists first, and full evidence preservation. Part 2 answers three questions: which ports are open, what services/versions answer, and which hostnames the servers actually route on (DNS vs VHOST). It does **not** perform exploitation, credential testing, or high-rate scanning (§12.9).

### 13.1 Nmap Output Preservation (evidence first)

Nmap results are evidence. Run **once** per target tier with all output formats so results are re-verifiable and machine-parseable:

```bash
# All formats at once (-oA); keep the timestamped raw copy
nmap -sV -sC -T3 --top-ports 100 -oA nmap/target-YYYYMMDD <target>

# Readable log + grepable + XML (for later tooling)
ls nmap/   # target-YYYYMMDD.nmap  (human-readable log)
           # target-YYYYMMDD.gnmap (grepable)
           # target-YYYYMMDD.xml   (machine/XML)

# Convert XML to HTML for the evidence folder if desired
xsltproc nmap/target-YYYYMMDD.xml -o nmap/target-YYYYMMDD.html
```

Rules: never summarize away scan output — save verbatim with the command line, date, and Nmap version used. `-oN/-oG/-oX` (or `-oA` for all three) on every run. Never re-scan "to remember" — re-read the saved file.

### 13.2 TCP/UDP Top-Port Scans

Start with **top ports**, not `-p-`. Top-100 TCP catches the large majority of bug-bounty-relevant services and keeps traffic defensible:

```bash
# TCP top-100, version detection, default scripts (bounded, T3)
nmap -sV -sC -T3 --top-ports 100 <host>

# TCP top-1000 only when the program explicitly allows deeper coverage
nmap -sV -sC -T3 --top-ports 1000 <host>

# UDP top-20: slow and intrusive — only with explicit authorization, low rate
nmap -sU -T3 --top-ports 20 --max-retries 1 <host>

# Explicitly ordered ports for known services
nmap -sV -sC -p 21,22,25,53,80,110,143,443,465,587,993,995,8080,8443 <host>
```

Notes:

- `-T3` is the default and correct for bug bounty; `-T4`/`-T5` raise dropouts and noise. Never run `-p-` sweeps of entire ranges without explicit authorization.
- UDP scanning is genuinely slow and noisy — treat as opt-in per RoE, and only on short, justified port lists.
- On Windows, Nmap runs fine, but raw-packet features behave differently (see §13.11, §13.12) — prefer TCP connect/service scans (`-sT` default when not root, `-sV`/`-sC` on open ports).

### 13.3 Service/Version/Script Triage

`-sV` (version detection) + `-sC` (default scripts) on open ports produce the service inventory. Triage the output:

- Record: service name, version, banner, and any script findings (e.g., `http-title`, `ssl-cert`, `ftp-anon`).
- **Do not auto-report banner/version observations** — a version is not a vulnerability. Note it as a candidate for the relevant testing skill.
- Distinguish *listening* from *reachable*: a port that answers a banner is only interesting if the service is in scope and actually testable.
- Feed the result into `httpx`/`whatweb`/`feroxbuster` only for in-scope web services.

### 13.4 FTP and Web-Content Pivot (hypothesis only)

An open FTP port (e.g., `ftp-anon` anonymous login) or an unexpected web service on a non-standard port is a **hypothesis generator**, not a finding:

```bash
# Check anonymous FTP (single connection, no brute force)
nmap -sV -p 21 --script ftp-anon <host>

# If a web service answers on a non-standard port, pivot content discovery there
# ONLY for in-scope hosts; treat the content as a separate application instance
feroxbuster -u http://<host>:8080/ -w wordlist.txt -t 10
```

Rules: an FTP service you can log into anonymously still belongs to the target's estate — if any other tenant can write there, treat its contents as **third-party data**: do not download, modify, or enumerate other tenants' files. A web-content pivot is a hypothesis ("this port serves an app worth mapping") that must be validated against scope and RoE before further testing.

### 13.5 Passive vs Active Subdomain Enumeration

Part 1 (§4) covers passive collection (CT logs, passive DNS, search engines). Part 2 adds *active* discovery on top; the two are **complementary, not interchangeable**:

| Dimension | Passive (Part 1) | Active (Part 2) |
| --- | --- | --- |
| Traffic to target | None (third-party sources) | Direct DNS queries, brute force, probing |
| Coverage | Only names that were *published/observed* | Names that *exist* but were never published |
| Finds | Known subdomains, historical names | Unknown-but-real names, permutations |
| Risk | Minimal | Rate limits, resolver load, WAF/IDS visibility |

Merge both into one list with `anew`; dedupe before resolution; resolve with `dnsx` (§13.9). Active enumeration is where rate limits and resolver hygiene matter most.

### 13.6 VHOST vs DNS Subdomain Distinction and Safe Host-Header Fuzzing

**DNS subdomain** = a name in the DNS namespace (`api.target.com` resolves). **VHOST** = a name the *HTTP server* routes on via the `Host` header, which may or may not resolve in DNS. A vhost can be a hidden app (staging, admin, internal) reachable only by sending the right `Host:` header to an IP or shared server.

- **VHOST discovery does NOT require DNS existence.** Fuzz `Host:` headers against a known-reachable in-scope host and diff responses by status, title, body length, `Set-Cookie`, and `Server` header.
- Safe, bounded fuzzing with `ffuf` — candidate names, per-host, throttled:

```bash
# VHOST fuzz against an in-scope host (rate-limited, per-host)
ffuf -w vhosts.txt -u http://<ip>/ -H "Host: FUZZ.target.com" \
     -fs <baseline-size> -mc all -t 10

# Confirm each candidate with a manual single request:
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -H "Host: staging.target.com" http://<ip>/
```

Rules for Host-header work:

- Only fuzz hosts you are authorized to reach; a `Host:` header change does **not** re-scope a shared server. If the IP serves other tenants, stop at identification (single request) — do not fuzz other tenants' vhosts.
- Diff against a baseline and record request/response pairs — this is evidence, and it is how you prove which vhost is which app.
- Do not use Host-header fuzzing as a pretext to scan co-tenant infrastructure (§12).

### 13.7 Reverse-IP and Certificate-Search Cross-Checks

Two cheap cross-checks confirm whether an IP is single-tenant (safe to treat as the target) or shared (a boundary):

- **Reverse-IP / PTR**: `dig -x <ip> +short`; also reverse-DNS/domain services (SecurityTrails, ViewDNS, HackerTarget) list other domains on the same IP. Many domains ⇒ shared hosting ⇒ boundary.
- **Certificate cross-check**: inspect the certificate(s) served by the IP; multiple unrelated SANs (or a cert issued to another brand) ⇒ shared/third-party ⇒ do not scan beyond identification.
- Corroborate against §6 ownership validation before any further probing. A shared IP is an abort condition for scanning (single low-rate identification request only).

### 13.8 CSP Header Subdomain Extraction

The `Content-Security-Policy` response header frequently lists the organization's own subdomains (`script-src`, `connect-src`, `img-src`, `frame-ancestors`). Extract them passively from responses you already hold:

```bash
# Grab the CSP from a live in-scope host (single request)
curl -sI https://target.com/ | grep -i content-security-policy

# Extract candidate subdomains from the policy
# e.g. script-src 'self' https://cdn.target.com https://static.target.com
# -> cdn.target.com, static.target.com become enumeration candidates (dedupe via anew)
```

These are **candidates**, not in-scope-by-assertion — still validate against the wildcard scope and §6. CSP extraction is passive and cheap; do it before spending brute-force budget.

### 13.9 Bounded Brute-Force and Permutation Discovery

Discovery tools generate candidate names from wordlists and permutations, then validate them via **resolver lists**:

- **AlterX** — generates permutations (prefix/suffix/wordlist mutations) of known names: `alterx -l subs.txt -o permutations.txt`.
- **MassDNS** — high-throughput resolution of candidate lists using a **resolver list** (NOT the target's own NS; use a public resolver list): `massdns -r resolvers.txt -t A -o S -w massdns.out permutations.txt`.
- **DNSx** — follow-up resolution and filtering of surviving names (cleans up noisy massdns output): `cat massdns.out | dnsx -silent -a -resp`.
- **Custom wordlists** — build target-specific candidate lists (brand/product/team names, common labels like `dev`, `staging`, `qa`, `uat`, `internal`, `admin`), merged with SecLists subdomain lists.

Windows/tool availability (current setup):

- **massdns** and **alterx** are NOT confirmed installed on this host — **check before use** (`massdns --version`, `alterx -h`); install only from official sources if missing, and record the version in `notes.md`.
- Go-based discovery tools (dnsx, subfinder, httpx, etc.) are expected in `recon-tools/go/bin` — add that directory to `PATH` when invoking them.
- A CSP extractor is a small script; if one is not already present, the `curl | grep` one-liner in §13.8 is sufficient — write results to a file as evidence.

Rate and hygiene rules:

- Resolve with an **external resolver list** and keep concurrency moderate; never hit the target's authoritative NS with brute force.
- Throttle (`-t`, `--rate`, `--max-rate`) every active step; stop and back off on any rate-limit/block response.
- Merge outputs with `anew`; keep raw massdns output as evidence; feed survivors to `dnsx` → `httpx`.

### 13.10 Part 2 Automation Pipelines and Deduplication

Pipeline the active phase the same way as Part 1 (§11), appending with `anew` so re-runs only add new data:

```bash
# Active discovery pipeline (per target, in-scope only, throttled)
alterx -l subs.txt -o permutations.txt                                # 1. generate candidates
cat subs.txt permutations.txt | anew all-candidates.txt               # 2. dedupe
massdns -r resolvers.txt -t A -o S -w massdns.out all-candidates.txt  # 3. bulk resolve
cat massdns.out | dnsx -silent -a -resp | anew resolved.txt           # 4. clean resolve
cat resolved.txt | httpx -silent -title -status-code -tech-detect -rl 20 | anew live_hosts.txt  # 5. probe
nmap -sV -sC -T3 --top-ports 100 -oA nmap/live-YYYYMMDD <in-scope-live-hosts>  # 6. map services
```

Every stage writes a dated artifact (`permutations.txt`, `massdns.out`, `resolved.txt`, `live_hosts.txt`, `nmap/*.nmap|gnmap|xml`). Dedupe with `anew`; diff new results per run; keep tool versions in `notes.md`.

### 13.11 Windows / Tool Availability Notes (current setup)

- Host: Windows (win32, PowerShell 5.1). Raw-packet Nmap features and exotic scan types behave differently or are unavailable (§13.12) — use TCP connect (`-sT`) and standard service scans.
- Go toolchain binaries for discovery (dnsx, subfinder, httpx, etc.) are expected in `recon-tools/go/bin` — verify presence and add to `PATH` before running.
- **massdns**, **alterx**, and a **CSP extractor** may need installation/check on this host — confirm availability first; install from official sources only; record the version in `notes.md`.
- Present/verified in `recon-tools`: masscan, feroxbuster, testssl.sh, sslscan, whatweb, wpscan, suricata, paramspider, SecLists wordlists (see the tool inventory report for exact versions). Zeek has no native Windows build — do not attempt WSL/Docker workarounds.
- Prefer PowerShell-safe invocation (`& "path\to\tool.exe" args`) for local tools; keep every artifact in the target's `evidence/` folder.

### 13.12 Unsafe and Authorization-Sensitive Scan Techniques (fence)

The following techniques are **documented as theory only** and are **NOT part of routine bug-bounty workflows**. Do not run them without explicit, written authorization, and never in a way that touches third parties:

- **FIN/NULL/Xmas scans** (`-sF`, `-sN`, `-sX`): unreliable on Windows (raw-socket/stateful-stack behavior) and **not a default**; they also trip IDS/IPS. Use standard TCP connect/service scans instead.
- **Idle/zombie scans** (`-sI`): abuse a third-party host as a decoy zombie — inherently affects a third party. **Do not use.** Theory only.
- **Source-port manipulation** (`-g`/`--source-port`): used to bypass firewall rules; authorization-sensitive and noisy — omit from routine work.
- **Source-IP spoofing / decoys** (`-D`, spoofed source): spoofed traffic can hit third parties and skew attribution. **Do not use** in authorized testing without explicit written permission; never spoof third-party IPs.
- **Fragmentation** (`-f`, `--mtu`): designed to evade packet filters; authorization-sensitive — omit from routine work.
- **Masscan at high rate / full `-p-` sweeps** of broad ranges: requires explicit authorization; restrict to authorized ranges and keep `--rate` low.

If a program or engagement explicitly authorizes any of these (rare, red-team scope), they must be: written into the RoE, limited to in-scope ranges, run without any third-party spoofing, and logged with full evidence. Otherwise treat them as out of scope.

## Command Reference (Preserved Phases)

### Phase 1: Passive Reconnaissance

#### Subdomain Enumeration (Passive)

```bash
# Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: $API_KEY"

# Subfinder (passive)
subfinder -d target.com -silent

# Amass (passive)
amass enum -passive -d target.com

# Combined approach
subfinder -d target.com -silent | anew subs.txt
amass enum -passive -d target.com | anew subs.txt
```

#### Historical Data

```bash
# Wayback Machine URLs
echo "target.com" | waybackurls | tee wayback.txt

# GAU (GetAllURLs)
echo "target.com" | gau --threads 5 | tee gau.txt

# Combined historical
cat wayback.txt gau.txt | sort -u | tee historical_urls.txt

# Find parameters
cat historical_urls.txt | grep "=" | qsreplace "FUZZ" | sort -u
```

#### Technology Detection

```bash
# Wappalyzer CLI
wappalyzer https://target.com

# WhatWeb
whatweb -a 3 https://target.com

# BuiltWith API
curl "https://api.builtwith.com/v19/api.json?KEY=$KEY&LOOKUP=target.com"
```

### Phase 2: Active Reconnaissance (bounded)

```bash
# DNS records (note: many resolvers ignore ANY; query record types individually)
dig target.com A +short
dig target.com MX +short
dig target.com TXT +short
dig target.com NS +short

# Zone transfer attempt (single, low-impact query)
dig axfr @ns1.target.com target.com

# DNSRecon
dnsrecon -d target.com -t std

# Subdomain brute force (rate-limit; use a small wordlist first)
puredns bruteforce wordlist.txt target.com -r resolvers.txt
```

#### Subdomain Resolution

```bash
# Resolve discovered subdomains
cat subs.txt | dnsx -silent -a -resp | tee resolved.txt

# Filter live hosts (single light request per host; keep -rl low)
cat resolved.txt | httpx -silent -title -status-code -tech-detect -rl 20 | tee live_hosts.txt

# Screenshot
cat live_hosts.txt | cut -d' ' -f1 | gowitness file -f - --threads 5
```

#### Port Scanning (bounded — see §12)

```bash
# Fast scan (top 100) - default aggressiveness, low rate
nmap -F -sV -T3 --max-rate 500 target.com

# Full TCP scan - only with explicit authorization; prefer --top-ports first
nmap -p- -T3 --max-rate 1000 target.com

# UDP scan (top 20) - intrusive; only with explicit authorization
nmap -sU --top-ports 20 target.com

# Service version detection on known-open ports
nmap -sV -sC -p 80,443,8080 target.com

# Masscan - high rates are intrusive; lower --rate and restrict to authorized ranges
masscan -p1-65535 --rate 1000 -oJ scan.json target.com
```

### Phase 3: Content Discovery

#### Directory Fuzzing

```bash
# Feroxbuster (low concurrency for bug bounty)
feroxbuster -u https://target.com -w /path/to/wordlist.txt -x php,asp,html -t 10

# FFUF
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -t 20

# Dirsearch
dirsearch -u https://target.com -e php,asp,html -t 20

# Gobuster
gobuster dir -u https://target.com -w wordlist.txt -x php,html -t 20
```

#### Parameter Discovery

```bash
# Arjun
arjun -u https://target.com/page

# ParamSpider
python3 paramspider.py -d target.com

# FFUF parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=value" -w params.txt -mc 200
```

#### JavaScript Analysis

```bash
# Extract JS files
cat live_hosts.txt | getJS --complete | tee js_files.txt

# Find endpoints in JS
cat js_files.txt | xargs -I{} sh -c 'curl -s {} | linkfinder -i -'

# Find secrets in JS
cat js_files.txt | xargs -I{} sh -c 'curl -s {} | secretfinder -i -'

# Nuclei JS analysis (only in-scope JS files)
nuclei -l js_files.txt -t exposures/ -rl 10
```

### Phase 4: Vulnerability Discovery (hand-off)

Automated scanning below is the **start** of vulnerability testing, not recon. Run it only against validated in-scope hosts with throttled rates, and hand off candidates to the matching skills (`bugbounty-workflow`, `idor-methodology`, `ssrf-testing`, etc.) rather than drilling down inside this skill.

```bash
# Nuclei (throttled)
nuclei -l live_hosts.txt -t nuclei-templates/ -rl 10 -o nuclei_results.txt

# Nikto
nikto -h https://target.com -Tuning 1,2,3 -output nikto.txt

# WPScan (WordPress - only if target runs WordPress)
wpscan --url https://target.com --enumerate u,p,t --api-token $WPScan_API
```

#### Manual Testing Points

```
1. Authentication
   - Login forms
   - Password reset
   - Registration
   - Session management

2. Authorization
   - IDOR on IDs
   - Horizontal privilege escalation
   - Vertical privilege escalation

3. Input Validation
   - All parameters (GET, POST)
   - Headers (Host, Referer, User-Agent)
   - Cookies
   - File uploads

4. Business Logic
   - Price manipulation
   - Quantity tampering
   - Skip steps
   - Race conditions
```

### Phase 5: Active Network, Service, and Host-Header Mapping (Part 2, §13)

```bash
# Nmap output-preserving scans (all formats, timestamped)
nmap -sV -sC -T3 --top-ports 100 -oA nmap/target-YYYYMMDD <host>

# UDP top-20 (explicit authorization only)
nmap -sU -T3 --top-ports 20 --max-retries 1 <host>

# FTP pivot hypothesis (single connection)
nmap -sV -p 21 --script ftp-anon <host>

# Safe VHOST fuzzing (per-host, throttled, diff vs baseline)
ffuf -w vhosts.txt -u http://<ip>/ -H "Host: FUZZ.target.com" -fs <baseline> -mc all -t 10

# CSP subdomain extraction (single request)
curl -sI https://target.com/ | grep -i content-security-policy

# Brute-force / permutation discovery (bounded, external resolvers)
alterx -l subs.txt -o permutations.txt
cat subs.txt permutations.txt | anew all-candidates.txt
massdns -r resolvers.txt -t A -o S -w massdns.out all-candidates.txt
cat massdns.out | dnsx -silent -a -resp | anew resolved.txt
```

## Reconnaissance Flow

```
Target Domain
     │
     ├── Scope, RoE, Target Understanding (§1)  ← read FIRST, re-check often
     │
     ├── Normal-User Browsing + Notes (§2)
     │
     ├── Portfolio Expansion via Public Sources (§3)  [scope-checked only]
     │
     ├── Passive Subdomain Enumeration (§4)
     │   ├── crt.sh, CertSpotter, SecurityTrails, passive DNS
     │   ├── Subfinder, Amass (passive)
     │   └── Historical data (wayback, gau)
     │
     ├── DNS Enumeration (bounded, Phase 2)
     │   ├── Record types (A, MX, TXT, NS, SPF)
     │   └── Zone transfer attempt (single query)
     │
     ├── ASN → CIDR → IP Expansion (§5)
     │   └── bgp.he.net, RIPEstat, Team Cymru, mapcidr
     │
     ├── Ownership Validation (§6)
     │   └── WHOIS + BGP origin ASN + PTR (+ cert as weak hint only)
     │
     ├── Search-Engine Queries (§7)
     │   └── Shodan / FOFA / ZoomEye on netblocks, certs, favicons
     │
     ├── TLS / JARM / JA3 Fingerprinting (§8)
     │   └── SAN enumeration, JARM/JA3 clustering, legacy TLS triage (no auto-report)
     │
     ├── Origin-IP Discovery (§9)  [authorized + verified only]
     │   └── favicon hash, SPF, Censys/passive DNS, historical DNS, verification
     │
     ├── Infrastructure Fingerprinting (§10)
     │   └── CDN/origin differentiation
     │
     ├── Resolution & Probing (bounded)
     │   ├── dnsx (resolve)
     │   └── httpx (probe, low rate)
     │
     ├── Port Scanning (bounded, §12)
     │   └── nmap top-ports / masscan only with authorization
     │
     ├── Part 2: Active Mapping (§13)
     │   ├── Nmap output-preserving scans + service/version triage
     │   ├── VHOST vs DNS subdomains, safe Host-header fuzzing
     │   ├── Reverse-IP/cert cross-checks, CSP extraction
     │   └── Bounded brute-force/permutation (AlterX→MassDNS→dnsx)
     │
     ├── Content Discovery
     │   ├── Directory fuzzing (low concurrency)
     │   ├── Parameter discovery
     │   └── JavaScript analysis
     │
     └── Vulnerability Scanning (hand-off)
         ├── Nuclei (throttled)
         └── Manual testing (other skills)
```

## Repeatable Workflow

Run in this order; each step feeds the next. Stop and re-validate scope whenever a new asset type appears.

1. **Read scope + RoE** (§1.1–1.2). Write the authorized asset list to `notes.md`.
2. **Browse as a normal user** with owned test accounts; take structured notes on auth model, architecture, integrations, and interesting IDs (§2).
3. **Expand the portfolio** from public sources; keep only in-scope additions (§3).
4. **Passive subdomain + live-host mapping** (§4, Phase 1). Save `subs.txt`, `resolved.txt`, `live_hosts.txt`.
5. **ASN → CIDR → IP expansion** for the org's ASNs (§5); do not scan yet.
6. **Ownership validation** of every network candidate via WHOIS/BGP/PTR corroboration (§6).
7. **Search-engine queries** (Shodan/FOFA/ZoomEye) over validated netblocks, certs, and favicon hashes (§7).
8. **TLS/SAN/JARM/JA3 fingerprinting**; cluster hosts; triage legacy TLS without auto-reporting (§8).
9. **Origin-IP discovery + verification** only if in scope and authorized (§9).
10. **Infrastructure fingerprinting**: CDN vs origin differentiation (§10).
11. **Bounded active probing**: resolution, light httpx, top-ports, throttled content discovery — in-scope hosts only (§11, Phase 2–3).
12. **Record evidence at every step** (below). Hand off candidates to the matching testing skill; do not drill into exploitation inside this skill.
13. **Re-run periodically** on a schedule; dedupe with `anew`; diff new results.
14. **Part 2 active mapping** (§13): Nmap output-preserving scans, service/version triage, vhost vs DNS subdomain checks with safe Host-header fuzzing, reverse-IP/cert cross-checks, CSP extraction, and bounded brute-force/permutation resolution (AlterX → MassDNS → dnsx).
15. **Windows/tooling check** (§13.11): verify massdns/alterx/CSP extractor availability, use `recon-tools/go/bin` tools, record versions in `notes.md`. Fenced techniques (§13.12) stay out of routine workflows.

## Evidence and Notes Guidance

- **Structure per target**: `targets/<name>/` with `notes.md` (architecture, auth model, scope), `findings.md` (confirmed/non-findings/open items), and an `evidence/` folder.
- **Save raw outputs** verbatim — never summarize away the data: `subs.txt`, `resolved.txt`, `live_hosts.txt`, `certs.json`, `shodan-results.json`, `nuclei_results.txt`, screenshots. Each file records the command, date, and tool version that produced it.
- **A finding's evidence must include**: request/response pairs (Burp), DNS records, TLS certs, and screenshots showing the impact. A claim without a reproducible request is not evidence.
- **Owned test accounts only**; store credentials in a gitignored `credentials.md`, never in notes that get committed.
- **Timestamps matter** for recon data (passive DNS, CT logs, scan results) — they show provenance and let you re-verify later.
- Update `notes.md` and `findings.md` as you go; results are versioned so a later session can tell what changed.

## Remediation and Reporting Boundaries

### What recon findings may be reportable (with proof)

- **Subdomain takeover** — only with a demonstration of control (e.g., provisioning the dangling cloud resource) and an in-scope impact.
- **Exposed sensitive data** discovered during recon: publicly readable config files, open admin panels, secrets in JS/`/.git` exposure — with request/response evidence and impact.
- **Origin-IP exposure that leads to an in-scope, exploitable bypass** (e.g., WAF bypass to a directly reachable admin function) — the exposure alone is not a finding.
- **Information disclosure with real impact** (internal hostnames/credentials in responses that enable a further attack) — per program policy.

### What is NOT reportable from recon alone

- **"Found the origin IP"** without an exploitable, in-scope consequence.
- **Legacy TLS / weak ciphers** by themselves — triage per program policy and concrete exploitability (§8.3).
- **Generic fingerprinting results** (CDN detected, framework version banners) with no exploitable impact.
- **Unvalidated asset lists** (ASN neighbors, shared-hosting co-tenants, certificate-org matches that fail §6 corroboration).
- Anything found on **out-of-scope or third-party infrastructure** — stop and document as a non-finding, do not escalate.

### Remediation guidance to include in reports

- **Ownership/inventory**: maintain an authoritative asset inventory (domains, IPs, ASNs, certs) so org and scope are unambiguous.
- **Certificates**: monitor CT logs for unauthorized or stale certificates; revoke unused certs; avoid putting brand names in certs for infrastructure that isn't org-owned.
- **TLS**: enforce modern protocol floors and cipher suites; use automated scanners to track drift; fix only when policy or exploitability demands.
- **CDN/origin**: keep origin IPs private (restrict origin firewalls to CDN IP ranges), rotate exposed origin addresses after a verified exposure, and treat origin as a trust boundary.
- **Data exposure**: remove secrets/config from publicly served files; restrict `/docs`, `.git`, backup files, and admin panels to authorized networks.

## CWE Tags

| CWE ID | Title | Typical recon relevance |
| --- | --- | --- |
| CWE-200 | Exposure of Sensitive Information | Leaked internal hostnames, configs, or data during enumeration |
| CWE-16 | Configuration | Insecure defaults, exposed admin/debug surfaces found in recon |
| CWE-319 | Cleartext Transmission of Sensitive Information | Services reachable without TLS |
| CWE-326 | Inadequate Encryption Strength | Legacy TLS/cipher observations (triaged, not auto-reported) |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Weak cipher/protocol support on discovered services |
| CWE-425 | Direct Request ('Forced Browsing') | Unlinked/undocumented endpoints found via content discovery |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | Secrets in JS, backups, `.git`, open directories |
| CWE-615 | Inclusion of Sensitive Information in Source Code Comments | Internal references left in served source/JS |
| CWE-345 | Insufficient Verification of Data Authenticity | Trusting client-supplied `Host`/headers to route to hidden vhosts during mapping |
| CWE-441 | Unintended Proxy or Intermediary | Shared-server/vhost confusion where a Host-header routes to another tenant's app |

## Wordlists

| Purpose     | Recommended Wordlist                                                         |
| ----------- | ---------------------------------------------------------------------------- |
| Subdomains  | SecLists/Discovery/DNS/subdomains-top1million-5000.txt                       |
| Directories | SecLists/Discovery/Web-Content/raft-medium-directories.txt                   |
| Files       | SecLists/Discovery/Web-Content/raft-medium-files.txt                         |
| Parameters  | SecLists/Discovery/Web-Content/burp-parameter-names.txt                      |
| Passwords   | SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt |

## Related Skills (avoid duplication)

- `bugbounty-workflow` — business-model mapping and vulnerability testing after recon completes.
- `idor-methodology`, `ssrf-testing`, `logic-bug-hunting`, `nextjs-testing` — endpoint/parameter candidates produced by recon are tested with these skills.
- `blind-sqli-origin-pivot` — worked example of origin-IP discovery and validation in an authorized engagement.
- Repo vault skills under `tools/skills/` — per-class testing procedures to apply once recon hands off candidates.