#!/usr/bin/env python3
"""Detecta la plataforma de cada candidata (WooCommerce, Shopify, Magento, Tiendanube, ...) y si su catálogo
es accesible desde aquí. Escribe out/pdiscover/summary.json y matrix.json (las escaneables)."""
import gzip, json, os, re, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(url, n=400_000, accept="text/html,application/json,*/*"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept, "Accept-Encoding": "gzip", "Accept-Language": "es-AR,es;q=0.9"})
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
        return None, url, {}, ""
FP = [("shopify", r"cdn\.shopify\.com|Shopify\.theme|myshopify\.com"), ("tiendanube", r"d26lpennugtm8s\.cloudfront|tiendanube|nuvemshop|LS\.store"),
      ("woocommerce", r"wp-content/plugins/woocommerce|woocommerce-"), ("magento", r"Magento_|mage/cookies|\"Magento|static/version\d+/frontend"),
      ("prestashop", r"prestashop|/modules/ps_"), ("vtex", r"vtexassets|vteximg|vtex\.com"), ("wix", r"wixstatic|_wixCssImports"),
      ("empretienda", r"empretienda"), ("jumpseller", r"jumpseller"), ("sfcc", r"demandware"), ("wordpress", r"wp-content|wp-includes")]
def probe(line):
    name, url = line.split()
    st, final, h, body = get(url)
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final if st == 200 else url))
    fps = [k for k, rx in FP if re.search(rx, body, re.I)]
    r = {"name": name, "url": url, "root": root, "home": st, "fps": fps, "csp": bool(h.get("content-security-policy")), "platform": None, "size": None}
    s, _, h2, b = get(root + "/wp-json/wc/store/v1/products?per_page=1", 50_000, "application/json")
    if s == 200 and b.strip().startswith("["):
        r["platform"], r["size"] = "woocommerce", int(h2.get("x-wp-total") or 0) or None
    if not r["platform"]:
        s, _, _, b = get(root + "/products.json?limit=1", 50_000, "application/json")
        if s == 200 and '"products"' in b[:50]:
            r["platform"] = "shopify"
    if not r["platform"] and "magento" in fps:
        q = urllib.parse.quote('{products(filter:{price:{from:"0"}},pageSize:1){total_count}}')
        s, _, _, b = get(f"{root}/graphql?query={q}", 50_000, "application/json")
        m = re.search(r'"total_count"\s*:\s*(\d+)', b)
        r["platform"], r["size"] = ("magento", int(m.group(1))) if m else ("magento-nographql", None)
    if not r["platform"] and "tiendanube" in fps:
        r["platform"] = "tiendanube"
    if not r["platform"]:
        r["platform"] = (fps[0] if fps else "desconocida")
    return r
lines = [l for l in open("stores/platform_candidates.txt") if l.strip() and not l.startswith("#")]
with ThreadPoolExecutor(12) as ex:
    res = list(ex.map(probe, lines))
for r in res: print(r, flush=True)
SCAN = {"woocommerce", "shopify", "magento", "tiendanube", "magento-nographql", "prestashop", "wordpress"}
ok = [{"name": r["name"], "url": r["root"], "platform": r["platform"] if r["platform"] in ("woocommerce", "shopify", "magento", "tiendanube") else "other"}
      for r in res if r["home"] == 200 and r["platform"] in SCAN]
os.makedirs("out/pdiscover", exist_ok=True)
json.dump(res, open("out/pdiscover/summary.json", "w"), indent=1)
json.dump(ok, open("matrix.json", "w"))
print("MATRIX", len(ok))
