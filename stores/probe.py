#!/usr/bin/env python3
"""Relevamiento de tiendas argentinas: ¿responden a GitHub Actions? ¿son VTEX? ¿cuántos productos?"""
import gzip, json, os, re, sys, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
SITES = {
 "fravega": "https://www.fravega.com", "garbarino": "https://www.garbarino.com", "musimundo": "https://www.musimundo.com",
 "megatone": "https://www.megatone.net", "oncity": "https://www.oncity.com", "cetrogar": "https://www.cetrogar.com.ar",
 "naldo": "https://www.naldo.com.ar", "changomas": "https://www.masonline.com.ar", "dia": "https://diaonline.supermercadosdia.com.ar",
 "coto": "https://www.cotodigital.com.ar", "farmacity": "https://www.farmacity.com", "easy": "https://www.easy.com.ar",
 "dexter": "https://www.dexter.com.ar", "moov": "https://www.moov.com.ar", "stockcenter": "https://www.stockcenter.com.ar",
 "grimoldi": "https://www.grimoldi.com", "laanonima": "https://supermercado.laanonimaonline.com", "libertad": "https://www.hiperlibertad.com.ar",
 "blaisten": "https://www.blaisten.com.ar", "tiendamia": "https://tiendamia.com/ar", "nike": "https://www.nike.com.ar",
 "newsport": "https://www.newsport.com.ar", "sportline": "https://www.sportline.com.ar", "carrefour": "https://www.carrefour.com.ar",
 "personal-flow": "https://tienda.personal.com.ar", "samsung": "https://www.samsung.com/ar", "hendel": "https://www.hendel.com",
 "pardo": "https://www.pardo.com.ar", "provincia-compras": "https://www.provinciacompras.com.ar", "tiendabna": "https://www.tiendabna.com.ar",
}
def get(url, n=300_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/json,*/*", "Accept-Language": "es-AR,es;q=0.9", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                try: b = gzip.decompress(b)
                except Exception: pass
            return r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()}, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception as e:
        return None, url, {}, f"ERROR {e}"
out = {}
for name, base in SITES.items():
    st, final, h, body = get(base)
    r = {"base": base, "status": st, "final": final, "server": h.get("server"), "vtex_html": bool(re.search(r"vtex", body, re.I)),
         "protect": [k for k, rx in {"akamai": r"akamai|_abck", "cloudflare": r"cloudflare|__cf_bm", "datadome": r"datadome", "imperva": r"incap_|imperva"}.items()
                     if re.search(rx, json.dumps(h) + body[:5000], re.I)]}
    root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final if st == 200 else base))
    s2, _, h2, b2 = get(root + "/api/catalog_system/pub/products/search?_from=0&_to=0", 50_000)
    r["vtex_api"] = s2; r["vtex_total"] = (h2.get("resources") or "").split("/")[-1] or None
    r["vtex_api_json"] = b2.strip().startswith("[")
    s3, _, _, b3 = get(root + "/api/catalog_system/pub/category/tree/1", 50_000)
    r["vtex_tree"] = s3 if b3.strip().startswith("[") else f"{s3}-nojson"
    r["root"] = root
    out[name] = r
    print(name, r, flush=True)
os.makedirs("out/probe", exist_ok=True)
json.dump(out, open("out/probe/probe.json", "w"), indent=1)
