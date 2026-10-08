#!/usr/bin/env python3
"""
Live cache-oracle recon (READ-ONLY).
Phase A of the methodology: confirm a cache exists + find hit/miss oracle.
Sends 2 harmless GET requests per target (with a unique cachebuster) and
records real cache headers, CDN fingerprint, framework hints, and whether a
cache HIT is observable. No payloads. No poisoning.
"""
import json, sys, time, uuid, argparse, concurrent.futures as cf
import urllib3
import requests

urllib3.disable_warnings()

CACHE_HDRS = [
    "x-cache", "cf-cache-status", "x-cache-status", "age", "cache-control",
    "server-timing", "x-amz-cf-pop", "x-served-by", "x-cache-hits",
    "akamai-cache-status", "akamai-grn", "via", "cf-ray", "x-varnish",
    "fastly-debug-digest", "x-drupal-cache", "x-litespeed-cache",
]
CDN_SIG = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly", "x-served-by"],
    "cloudfront": ["cloudfront", "x-amz-cf-pop"],
    "varnish": ["varnish", "x-varnish"],
    "azure": ["azureedge", "x-azure-ref"],
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"


def fingerprint_cdn(headers):
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for cdn, sigs in CDN_SIG.items():
        if any(s in blob for s in sigs):
            return cdn
    return "unknown"


def cache_headers(headers):
    return {k: v for k, v in headers.items() if k.lower() in CACHE_HDRS}


def hit_signal(headers):
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    if "hit" in h.get("cf-cache-status", ""): return True
    if "hit" in h.get("x-cache", ""): return True
    if "hit" in h.get("akamai-cache-status", ""): return True
    if "hit" in h.get("x-cache-status", ""): return True
    try:
        if int(h.get("age", "0")) > 0: return True
    except ValueError:
        pass
    return False


def probe(target):
    url = target["url"]
    cb = uuid.uuid4().hex[:10]
    out = {"url": url, "domain": target["domain"], "program": target.get("program"),
           "static_cdn": target.get("cdn_provider"), "live_cdn": None,
           "reachable": False, "status": None, "cache_headers": {},
           "cache_hit_observed": False, "is_oracle": False, "error": None}
    try:
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        r1 = s.get(f"{url}/?cb={cb}", timeout=12, verify=False, allow_redirects=False)
        time.sleep(0.4)
        r2 = s.get(f"{url}/?cb={cb}", timeout=12, verify=False, allow_redirects=False)
        out["reachable"] = True
        out["status"] = r1.status_code
        out["live_cdn"] = fingerprint_cdn(r2.headers)
        out["cache_headers"] = cache_headers(r2.headers)
        # oracle = we can see a cache hit on the repeat request
        out["cache_hit_observed"] = hit_signal(r2.headers)
        cc = str(r2.headers.get("cache-control", "")).lower()
        st = str(r2.headers.get("server-timing", "")).lower()
        # tighter: real hit, OR genuinely public/cacheable, OR an Akamai/CDN
        # cdn-cache oracle we can probe (desc present even if MISS/NO-STORE)
        publicly_cacheable = ("public" in cc or "s-maxage" in cc) and "no-store" not in cc
        cdn_cache_oracle = "cdn-cache" in st
        out["is_oracle"] = out["cache_hit_observed"] or publicly_cacheable or cdn_cache_oracle
        out["oracle_reason"] = (
            "live-hit" if out["cache_hit_observed"] else
            "public-cacheable" if publicly_cacheable else
            "cdn-cache-timing" if cdn_cache_oracle else None)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:120]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", required=True)
    ap.add_argument("--outfile", required=True)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--threads", type=int, default=15)
    args = ap.parse_args()

    data = json.load(open(args.recon))
    data = sorted(data, key=lambda x: x.get("priority_score", 0), reverse=True)[:args.limit]

    results = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i, res in enumerate(ex.map(probe, data), 1):
            results.append(res)
            flag = "ORACLE" if res["is_oracle"] else ("hit" if res["cache_hit_observed"] else ("up" if res["reachable"] else "DOWN"))
            print(f"[{i}/{len(data)}] {flag:7} {res['domain']:32} cdn={res['live_cdn']} status={res['status']}")

    json.dump(results, open(args.outfile, "w"), indent=2)
    oracles = [r for r in results if r["is_oracle"]]
    live_hits = [r for r in oracles if r.get("oracle_reason") == "live-hit"]
    print(f"\n== {len(oracles)}/{len(results)} oracles ({len(live_hits)} with live HIT) ==")
    from collections import Counter
    print("CDN breakdown:", dict(Counter(r["live_cdn"] for r in results if r["reachable"])))
    print("\n-- LIVE-HIT oracles (strongest) --")
    for o in live_hits:
        print(f"  {o['domain']:38} {o['live_cdn']:10} {o['cache_headers']}")


if __name__ == "__main__":
    main()
