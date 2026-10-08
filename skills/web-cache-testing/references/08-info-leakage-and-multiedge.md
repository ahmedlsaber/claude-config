# 08 — Information Leakage & Multi-Edge Poisoning

## Timing (Age / max-age)
```
Age: 174
Cache-Control: public, max-age=1800   → window = 1800-174 = 1626s
```
Poison right after a refresh for max duration and a single precisely-timed request instead of a barrage.

## Vary analysis
`Vary: User-Agent` reveals the UA is keyed → targeted attacks, most-common-UA for reach, or concealment via a rare UA. Test empirically — caches may not honor every listed Vary header.

## Multi-edge / cross-cloud poisoning
CDNs run hundreds of regional edges; poisoning one doesn't poison all.
- **Cloudflare `CF-RAY: 6498c2c958e89cee-AMS`** → `AMS` = edge (IATA code). Different regions hit different caches.
- Enumerate CF edges (one-liner): fetch `cloudflare.com/ips-v4` → `zmap -p80` → `zgrab` → parse `colo=` → unique edges + sample IPs. Iterating IPs to poison many edges is trivially automated (Kettle) — **CVSS complexity should NOT be raised** for it.
- Other CDNs: Akamai `Akamai-Edge`/`Akamai-Request-BC`; Fastly `Fastly-Debug`; CloudFront `X-Amz-Cf-Pop`.

**Testing method:** note your poison's `CF-RAY`; test via VPN in US/EU/Asia and compare edge codes; if some edges are clean, demonstrate the enumeration one-liner and state in the report: "only demonstrated on [EDGE], but CF publishes all IPs and poisoning all edges is a one-line job."

**Triage risk:** a triager in another region may not reproduce your poison — pre-empt this in the writeup.
