#!/usr/bin/env python3
"""
Passive subdomain discovery for wildcard-scope programs.
Targets FORGOTTEN / neglected hosts (where cache misconfigs survive).
Sources (no API key, passive):
  - Shodan CTL (cert transparency):  https://ctl.shodan.io/api/v1/domain/<d>/hostnames
  - crt.sh (cert transparency):      https://crt.sh/?q=%25.<d>&output=json
  - Wayback CDX (archived URLs):     https://web.archive.org/cdx/search/cdx?url=*.<d>/*
Outputs a deduped hostlist; validate separately with httpx / live-oracle-recon.
"""
import json, sys, re, argparse, time
import urllib3, requests
urllib3.disable_warnings()
UA = "Mozilla/5.0 (cache-recon)"

def _get(url, timeout=25):
    return requests.get(url, headers={"User-Agent": UA}, timeout=timeout, verify=False)

def from_ctl(d):
    try:
        r = _get(f"https://ctl.shodan.io/api/v1/domain/{d}/hostnames")
        return set(h.lower() for h in r.json()) if r.ok else set()
    except Exception: return set()

def from_crtsh(d):
    try:
        r = _get(f"https://crt.sh/?q=%25.{d}&output=json")
        out = set()
        for row in r.json():
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(d): out.add(name)
        return out
    except Exception: return set()

def from_wayback(d):
    try:
        r = _get(f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&fl=original&collapse=urlkey&limit=8000")
        out = set()
        for line in r.text.splitlines():
            m = re.search(r"https?://([^/:\s]+)", line)
            if m and m.group(1).lower().endswith(d):
                out.add(m.group(1).lower())
        return out
    except Exception: return set()

def discover(d):
    hosts = set()
    for name, fn in [("ctl", from_ctl), ("crtsh", from_crtsh), ("wayback", from_wayback)]:
        s = fn(d)
        print(f"    {name:8} +{len(s)}", file=sys.stderr)
        hosts |= s
        time.sleep(0.5)
    # keep only in-scope of the root, drop obvious junk
    hosts = {h for h in hosts if h.endswith(d) and re.match(r"^[a-z0-9._-]+$", h)}
    return sorted(hosts)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", nargs="+", help="root domains")
    ap.add_argument("--domains-file")
    ap.add_argument("--outfile", required=True)
    args = ap.parse_args()
    roots = list(args.domains or [])
    if args.domains_file:
        roots += [l.strip() for l in open(args.domains_file) if l.strip()]
    allhosts = {}
    for d in roots:
        print(f"[*] {d}", file=sys.stderr)
        h = discover(d)
        allhosts[d] = h
        print(f"    => {len(h)} unique subdomains", file=sys.stderr)
    # flat list
    flat = sorted({h for hs in allhosts.values() for h in hs})
    json.dump({"by_root": allhosts, "all": flat}, open(args.outfile, "w"), indent=2)
    with open(args.outfile.replace(".json", ".txt"), "w") as f:
        f.write("\n".join(flat))
    print(f"\n[+] {len(flat)} total subdomains -> {args.outfile}", file=sys.stderr)

if __name__ == "__main__":
    main()
