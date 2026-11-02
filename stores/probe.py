#!/usr/bin/env python3
"""Relevamiento de plataforma de e-commerce: qué hay detrás de cada tienda y por dónde se enumeran sus productos."""
import gzip, json, re, sys, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
TARGETS = sys.argv[1:] or ["https://www.compragamer.com", "https://www.falabella.com.ar", "https://www.falabella.com/falabella-cl",
    "https://www.adidas.com.ar", "https://www.nike.com.ar", "https://www.despegar.com.ar"]

def get(url, n=600_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json,*/*",
                                               "Accept-Language": "es-AR,es;q=0.9", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                try: b = gzip.decompress(b)
                except Exception: pass
            return r.status, r.geturl(), dict(r.headers), b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, dict(e.headers or {}), (e.read(20000) or b"").decode("utf-8", "replace")
    except Exception as e:
        return None, url, {}, f"ERROR {e}"

FP = {
    "vtex": r"vtex|vteximg|vtexassets", "sfcc/demandware": r"demandware|/on/demandware\.store|dwanalytics|dw/image",
    "shopify": r"cdn\.shopify|Shopify\.theme", "magento": r"Magento|mage/|static/version\d+", "tiendanube": r"tiendanube|nuvemshop",
    "woocommerce": r"woocommerce|wp-content", "nextjs": r"__NEXT_DATA__|/_next/static", "nuxt": r"__NUXT__|/_nuxt/",
    "angular": r"ng-version|ng-app", "akamai": r"akamai|_abck|bm_sz", "cloudflare": r"cloudflare|cf-ray|__cf_bm",
    "incapsula/imperva": r"incap_ses|visid_incap|_Incapsula", "perimeterx": r"_pxhd|perimeterx|px-captcha",
    "datadome": r"datadome", "gtm": r"googletagmanager", "commercetools": r"commercetools", "occ/oracle": r"oracle|atg|occ",
}
out = []
for base in TARGETS:
    r = {"target": base}
    st, final, hdr, body = get(base)
    hl = {k.lower(): v for k, v in hdr.items()}
    r.update(status=st, final_url=final, server=hl.get("server"), powered=hl.get("x-powered-by"),
             set_cookie=[c.split("=")[0] for c in (hl.get("set-cookie") or "").split(", ") if "=" in c][:15],
             title=(re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I) or [None, None])[1],
             body_len=len(body), body_head=body[:400] if (st or 0) >= 400 or len(body) < 3000 else None)
    blob = body + json.dumps(hdr)
    r["fingerprints"] = [k for k, rx in FP.items() if re.search(rx, blob, re.I)]
    srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", body, re.I)
    r["script_hosts"] = sorted({urllib.parse.urlsplit(urllib.parse.urljoin(final, s)).netloc for s in srcs})
    r["inline_scripts"] = len(re.findall(r"<script(?![^>]*src=)[^>]*>", body, re.I))
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final))
    st2, _, _, robots = get(root + "/robots.txt", 100_000)
    r["robots_status"] = st2
    r["sitemaps"] = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots or "")[:10]
    r["robots_disallow_sample"] = re.findall(r"(?im)^\s*disallow:\s*(\S+)", robots or "")[:15]
    sm = []
    for u in (r["sitemaps"] or [root + "/sitemap.xml"])[:3]:
        s3, _, _, x = get(u, 400_000)
        locs = re.findall(r"<loc>\s*([^<\s]+)", x or "")
        sm.append({"url": u, "status": s3, "n_locs": len(locs), "sample": locs[:12]})
    r["sitemap_probe"] = sm
    apis = {"vtex_catalog": "/api/catalog_system/pub/products/search?_from=0&_to=0",
            "vtex_is": "/api/io/_v/api/intelligent-search/product_search/?count=1",
            "shopify": "/products.json?limit=1", "next_data": None}
    r["api_probe"] = {}
    for k, path in apis.items():
        if not path: continue
        s4, _, h4, b4 = get(root + path, 50_000)
        r["api_probe"][k] = {"status": s4, "ctype": {kk.lower(): vv for kk, vv in h4.items()}.get("content-type"), "head": b4[:200]}
    out.append(r)
    print(json.dumps(r, ensure_ascii=False)[:3000], flush=True)
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
