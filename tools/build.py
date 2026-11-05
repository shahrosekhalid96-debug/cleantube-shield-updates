#!/usr/bin/env python3
"""Build + sign the CleanTube Shield update bundle.

Reads src/, downloads the block lists in src/sources.txt, merges them,
runs safety checks, writes dist/bundle.json.gz and dist/latest.json.
Signs the bundle with the ECDSA P-256 key in env SHIELD_PRIVATE_KEY (PEM).
"""
import base64, gzip, hashlib, json, os, re, sys, time, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC, DIST = os.path.join(ROOT, "src"), os.path.join(ROOT, "dist")
DOM = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
MIN_THREATS, MIN_ADS = 100_000, 20_000          # refuse to publish a gutted list
CSS_BAD = re.compile(r"url\s*\(|@import|expression|javascript:|[{}<>\\]", re.I)


def lines(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for l in f:
            l = l.strip()
            if l and not l.startswith(("#", "!")):
                yield l


def parse(text, fmt):
    out = set()
    for l in text.splitlines():
        l = l.strip().lower()
        if not l or l.startswith(("#", "!")):
            continue
        if fmt == "hosts":
            p = l.split()
            if len(p) < 2 or p[0] not in ("0.0.0.0", "127.0.0.1"):
                continue
            l = p[1]
        l = l.lstrip("*.").strip(".")
        if DOM.match(l):
            out.add(l)
    return out


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cleantube-shield-builder"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "ignore")


def collapse(s):
    keep = []
    for d in s:
        p = d.split(".")
        if not any(".".join(p[i:]) in s for i in range(1, len(p) - 1)):
            keep.append(d)
    return sorted(keep)


def main():
    allow = [d.lower() for d in lines(os.path.join(SRC, "allowlist.txt"))]
    is_allowed = lambda d: any(d == a or d.endswith("." + a) for a in allow)

    threats, ads = set(), set()
    for l in lines(os.path.join(SRC, "sources.txt")):
        kind, fmt, url = l.split()
        doms = parse(fetch(url), fmt)
        print(f"{kind:6} {len(doms):>8}  {url}")
        (threats if kind == "threat" else ads).update(doms)

    extra = {d.lower() for d in lines(os.path.join(SRC, "extra-block.txt"))}
    threats = {d for d in threats if not is_allowed(d)} | extra
    ads = {d for d in ads if not is_allowed(d)} - threats
    threats, ads = collapse(threats), collapse(ads)

    if len(threats) < MIN_THREATS or len(ads) < MIN_ADS:
        sys.exit(f"ABORT: lists too small (threats={len(threats)}, ads={len(ads)})")

    yt = json.load(open(os.path.join(SRC, "youtube-config.json")))
    yt.setdefault("hide", yt.get("css", []))
    yt.setdefault("fade", [])
    for sel in yt["hide"] + yt["fade"] + yt["skipSelectors"]:
        if not isinstance(sel, str) or CSS_BAD.search(sel) or len(sel) > 200:
            sys.exit(f"ABORT: unsafe selector {sel!r}")
    notice = json.load(open(os.path.join(SRC, "notice.json")))
    allow_all_path = os.path.join(SRC, "allow-all.txt")
    allow_all = sorted({d.lower() for d in lines(allow_all_path)}) if os.path.exists(allow_all_path) else []
    if any(not DOM.match(d) for d in allow_all):
        sys.exit("ABORT: bad domain in allow-all.txt")

    version = int(time.time())
    bundle = {
        "format": 1,
        "version": version,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(version)),
        "threats": threats,
        "adhosts": ads,
        "youtube": {"css": yt["hide"], "hide": yt["hide"], "fade": yt["fade"], "skipSelectors": yt["skipSelectors"]},
        "notice": notice,
        "allowAll": allow_all,
    }
    raw = json.dumps(bundle, separators=(",", ":")).encode()
    gz = gzip.compress(raw, 9, mtime=0)

    key = serialization.load_pem_private_key(os.environ["SHIELD_PRIVATE_KEY"].encode(), None)
    der = key.sign(gz, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()

    os.makedirs(DIST, exist_ok=True)
    open(os.path.join(DIST, "bundle.json.gz"), "wb").write(gz)
    latest = {
        "version": version,
        "created": bundle["created"],
        "size": len(gz),
        "sha256": hashlib.sha256(gz).hexdigest(),
        "sig": sig,
        "threats": len(threats),
        "adhosts": len(ads),
    }
    json.dump(latest, open(os.path.join(DIST, "latest.json"), "w"), indent=1)
    print(f"OK v{version}: {len(threats)} threats, {len(ads)} ad hosts, {len(gz)/1e6:.1f} MB")


if __name__ == "__main__":
    main()
