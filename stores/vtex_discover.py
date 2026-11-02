#!/usr/bin/env python3
"""Prueba las candidatas de vtex_candidates.txt: responde a GitHub? es VTEX (API de catálogo)? cuántos productos? CSP?
Escribe out/discover/summary.json y el archivo matrix.json con las que se pueden escanear."""
import gzip, json, os, re, sys, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
SKIP = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else set()   # ya escaneadas
def get(url, n=200_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json,*/*", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                try: b = gzip.decompress(b)
                except Exception: pass
            return r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()}, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception as e:
        return None, url, {}, f"ERROR {type(e).__name__}"
def probe(line):
    name, url = line.split()
    st, final, h, body = get(url)
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final if st == 200 else url))
    s2, _, h2, b2 = get(root + "/api/catalog_system/pub/products/search?_from=0&_to=0", 60_000)
    total = (h2.get("resources") or "").split("/")[-1]
    return {"name": name, "url": url, "root": root, "home": st, "vtex_api": s2, "is_vtex": b2.strip().startswith("["),
            "total": int(total) if total.isdigit() else None, "csp": bool(h.get("content-security-policy")),
            "csp_report_only": bool(h.get("content-security-policy-report-only")), "error": body[:40] if st is None else None}
lines = [l for l in open("stores/vtex_candidates.txt") if l.strip() and not l.startswith("#")]
with ThreadPoolExecutor(12) as ex:
    res = list(ex.map(probe, lines))
for r in res: print(r, flush=True)
ok = [r for r in res if r["is_vtex"] and r["name"] not in SKIP]
os.makedirs("out/discover", exist_ok=True)
json.dump(res, open("out/discover/summary.json", "w"), indent=1)
json.dump([{"name": r["name"], "url": r["root"]} for r in ok], open("matrix.json", "w"))
print("MATRIX", len(ok), [r["name"] for r in ok])
