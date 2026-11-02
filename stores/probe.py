#!/usr/bin/env python3
"""¿Son VTEX (por HTML o Intelligent Search) las candidatas que no respondieron a la API de catálogo?"""
import gzip, json, os, re, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
NAMES = "tiendanewsan noblex tiendamacro tiendacomafi tiendaclaro tiendamovistar drean philco atma rodo casadelaudio converse vans kevingston cheeky prune cardon lamartina akiabara rapsodia solodeportes opensports reebok morph selma openfarma natura avon atomo lacoope musimundo philips stanley hush gaelle markova yagmour jazmin caro lupo babycottons owoko grisino".split()
def get(url, n=400_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json,*/*", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                try: b = gzip.decompress(b)
                except Exception: pass
            return r.status, r.geturl(), b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, ""
    except Exception as e:
        return None, url, ""
urls = dict(l.split() for l in open("stores/vtex_candidates.txt") if l.strip() and not l.startswith("#"))
FP = {"vtex": r"vtex", "shopify": r"cdn\.shopify|Shopify\.", "tiendanube": r"tiendanube|nuvemshop|d26lpennugtm8s", "magento": r"Magento|mage/cookies",
      "woocommerce": r"woocommerce|wp-content", "sfcc": r"demandware", "prestashop": r"prestashop", "vnda": r"vnda", "nextjs": r"__NEXT_DATA__"}
def p(name):
    st, final, body = get(urls[name])
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final))
    s2, _, b2 = get(root + "/api/io/_v/api/intelligent-search/product_search/?count=1&page=1", 100_000)
    tot = re.search(r'"recordsFiltered"\s*:\s*(\d+)', b2)
    return {"name": name, "root": root, "home": st, "fp": [k for k, rx in FP.items() if re.search(rx, body, re.I)],
            "is_status": s2, "is_total": int(tot.group(1)) if tot else None, "is_has_desc": '"description"' in b2}
with ThreadPoolExecutor(10) as ex: res = list(ex.map(p, NAMES))
os.makedirs("out/probe2", exist_ok=True)
json.dump(res, open("out/probe2/summary.json", "w"), indent=1)
