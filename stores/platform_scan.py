#!/usr/bin/env python3
"""
Escaneo de tiendas en plataformas que no son VTEX: WooCommerce, Shopify, Magento y
Tiendanube (y, en modo solo-páginas, cualquier otra).

Dos partes, porque los skimmers viven en dos lugares distintos:

1. CATÁLOGO (donde estaba el de Cencosud): todas las descripciones de producto por
   la API pública de la plataforma, pasadas por los detectores de deep_scan.
     - WooCommerce: /wp-json/wc/store/v1/products   (Store API, pública)
     - Shopify:     /products.json                  (pública)
     - Magento:     /graphql                         (storefront GraphQL, pública)
     - Tiendanube:  no tiene API pública -> la descripción sale de cada página de producto.

2. PÁGINAS (donde suelen vivir los Magecart): home, carrito y una muestra de páginas de
   producto del sitemap. De cada página se extraen los scripts inline, los scripts
   externos, los atributos on*= y los iframes, y se comparan entre páginas:
     - código que aparece solo en algunas páginas es sospechoso (inyección por producto);
     - cualquier script con payload codificado o comportamiento de skimmer se reporta;
     - se baja cada script externo una vez y se analiza;
     - se arma el inventario de dominios de terceros.

Uso: platform_scan.py --site NOMBRE=URL --platform woocommerce|shopify|magento|tiendanube|other
Salida: out/NOMBRE/{findings.jsonl, pages.json, summary.json, progress.log}
"""
import argparse
import gzip
import hashlib
import html as htmlmod
import importlib.util
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("deep_scan", os.path.join(HERE, "..", "deep-scan", "deep_scan.py"))
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")

# Terceros comunes y legítimos: aparecen en el inventario pero no se marcan.
COMMON_HOSTS = (
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com", "doubleclick.net",
    "googleadservices.com", "googlesyndication.com", "youtube.com", "ytimg.com", "facebook.net", "facebook.com",
    "fbcdn.net", "instagram.com", "tiktok.com", "tiktokcdn.com", "hotjar.com", "clarity.ms", "bing.com",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "jquery.com",
    "shopify.com", "shopifycdn.com", "shopifysvc.com", "cdn.shopify.com", "myshopify.com", "wp.com", "wordpress.org",
    "gravatar.com", "woocommerce.com", "mercadopago.com", "mercadopago.com.ar", "mercadolibre.com", "mlstatic.com",
    "tiendanube.com", "nuvemshop.com.br", "d26lpennugtm8s.cloudfront.net", "d2r9epyceweg5n.cloudfront.net",
    "mailchimp.com", "list-manage.com", "klaviyo.com", "zendesk.com", "zdassets.com", "tawk.to", "whatsapp.com",
    "wa.me", "pinterest.com", "pinimg.com", "twitter.com", "x.com", "linkedin.com", "licdn.com", "vimeo.com",
    "vimeocdn.com", "recaptcha.net", "hcaptcha.com", "onesignal.com", "criteo.com", "criteo.net", "taboola.com",
    "adroll.com", "addthis.com", "sharethis.com", "fontawesome.com", "typekit.net", "adobe.com", "w3.org",
    "schema.org", "paypal.com", "paypalobjects.com", "stripe.com", "todopago.com.ar", "decidir.com", "payway.com.ar",
    "modo.com.ar", "getnet.com", "globalgetnet.com", "andreani.com", "oca.com.ar", "correoargentino.com.ar",
    "magento.com", "adobecommerce.com", "wpengine.com", "elementor.com", "jetpack.com", "trustpilot.com",
    "yotpo.com", "judge.me", "privy.com", "sumo.com", "intercom.io", "intercomcdn.com", "hubspot.com",
    "hs-scripts.com", "hs-analytics.net", "hsforms.net", "segment.com", "segment.io", "newrelic.com",
    "nr-data.net", "sentry.io", "sentry-cdn.com", "datadoghq.com", "cookiebot.com", "onetrust.com",
    "cookielaw.org", "polyfill.io", "bootstrapcdn.com", "jsdelivr.com", "smartlook.com", "metricool.com",
    "addi.com", "mobbex.com", "uala.com.ar", "naranjax.com", "fravega.com", "perfit.com.ar", "perfitcdn.com",
    "envialosimple.com", "doppler.com", "fromdoppler.com", "botmaker.com", "chatwoot.com", "jivosite.com",
)
# Hosts usados históricamente por skimmers que imitan servicios conocidos (ejemplos de patrón).
LOOKALIKE = re.compile(r"(g00gle|googie|gooqle|google-?analytics?-?(cdn|js|api)|googletagmanager-?(cdn|js)|"
                       r"jquery-?(cdn|min|js)\.(com|net|org|xyz|top)|cdnjs-|-cdn\.(xyz|top|ru)|analytic[s]?-?(cdn|js)\.(com|net)|"
                       r"mercadopag0|mercado-?pago-?(cdn|api|js)|payment-?(cdn|js|api)\.)", re.I)

LOGF = None


def log(m):
    line = f"{datetime.now():%H:%M:%S} {m}"
    print(line, flush=True)
    if LOGF:
        LOGF.write(line + "\n")
        LOGF.flush()


class Http:
    def __init__(self, rps):
        self.gap, self.next = 1.0 / rps, 0.0
        self.count = self.errors = 0

    def get(self, url, accept="text/html,application/json,*/*", n=15_000_000, headers=None):
        for attempt in range(4):
            now = time.monotonic()
            if self.next > now:
                time.sleep(self.next - now)
            self.next = max(now, self.next) + self.gap
            h = {"User-Agent": UA, "Accept": accept, "Accept-Language": "es-AR,es;q=0.9", "Accept-Encoding": "gzip"}
            h.update(headers or {})
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=40) as r:
                    b = r.read(n)
                    if r.headers.get("Content-Encoding") == "gzip":
                        b = gzip.decompress(b)
                    self.count += 1
                    return r.status, {k.lower(): v for k, v in r.headers.items()}, b.decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                self.count += 1
                if e.code in (429, 500, 502, 503, 504):
                    time.sleep(2 ** attempt + random.random())
                    continue
                return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
            except Exception:
                time.sleep(2 ** attempt)
        self.errors += 1
        return None, {}, ""


# ------------------------------------------------------------------ catálogo por API

def catalog_woocommerce(base, http, emit):
    page, n = 1, 0
    while True:
        st, h, t = http.get(f"{base}/wp-json/wc/store/v1/products?per_page=100&page={page}", "application/json")
        if st != 200:
            break
        try:
            items = json.loads(t)
        except Exception:
            break
        if not items:
            break
        for p in items:
            n += 1
            emit(p, p.get("id"), p.get("name"), p.get("permalink"))
        total_pages = int(h.get("x-wp-totalpages", "0") or 0)
        log(f"  woocommerce página {page}/{total_pages or '?'} — {n:,} productos")
        if total_pages and page >= total_pages:
            break
        page += 1
    return n


def catalog_shopify(base, http, emit):
    page, n, seen = 1, 0, set()
    while page <= 400:
        st, h, t = http.get(f"{base}/products.json?limit=250&page={page}", "application/json")
        if st != 200:
            break
        try:
            items = json.loads(t).get("products", [])
        except Exception:
            break
        new = [p for p in items if p.get("id") not in seen]
        if not new:
            break
        for p in new:
            seen.add(p.get("id"))
            n += 1
            emit(p, p.get("id"), p.get("title"), f"{base}/products/{p.get('handle')}")
        log(f"  shopify página {page} — {n:,} productos")
        page += 1
    return n


MAGENTO_Q = ("{products(filter:{price:{from:\"0\"}},pageSize:100,currentPage:%d)"
             "{total_count page_info{total_pages} items{sku name url_key "
             "description{html} short_description{html} meta_description meta_title}}}")


def catalog_magento(base, http, emit):
    page, n, total_pages = 1, 0, None
    while True:
        q = urllib.parse.quote(MAGENTO_Q % page)
        st, h, t = http.get(f"{base}/graphql?query={q}", "application/json", headers={"Store": "default"})
        try:
            data = json.loads(t)
        except Exception:
            log(f"  magento graphql: HTTP {st}, respuesta no JSON")
            break
        prods = (data.get("data") or {}).get("products")
        if not prods:
            log(f"  magento graphql sin datos: {str(data.get('errors'))[:200]}")
            break
        total_pages = (prods.get("page_info") or {}).get("total_pages") or 1
        for p in prods.get("items") or []:
            n += 1
            emit(p, p.get("sku"), p.get("name"), f"{base}/{p.get('url_key')}.html")
        log(f"  magento página {page}/{total_pages} — {n:,} productos")
        if page >= total_pages:
            break
        page += 1
    return n


# ------------------------------------------------------------------ páginas

SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
SRC_RE = re.compile(r"\bsrc\s*=\s*[\"']([^\"']+)", re.I)
HANDLER_RE = re.compile(r"<([a-z][a-z0-9]*)\b[^>]*?\s(on[a-z]{3,20})\s*=\s*([\"'])(.*?)\3", re.I | re.S)
IFRAME_RE = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)", re.I)
URLHOST = re.compile(r"(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=[/\"'`:?\s)]|$)", re.I)
VOLATILE = re.compile(r"\d{6,}|[0-9a-f]{16,}|\"(?:nonce|csrf|token|form_key|_wpnonce|sessionid)\"\s*:\s*\"[^\"]*\"", re.I)
SKIMMER_BEHAVIOR = re.compile(
    r"(window\.fetch\s*=(?!=)|XMLHttpRequest\.prototype\.(?:open|send)\s*=(?!=)|sendBeacon\s*\(|new\s+WebSocket\s*\("
    r"|cc_?number|card_?number|cardnumber|ccnum|cc-number|\bcvv\b|\bcvc\b|security_?code)", re.I)


def host_of(u, base):
    try:
        return urllib.parse.urlsplit(urllib.parse.urljoin(base, u)).netloc.lower().split(":")[0]
    except Exception:
        return ""


def is_common(h, own):
    h = h.lower()
    if not h or h == own or h.endswith("." + own) or own.endswith("." + h):
        return True
    root = ".".join(own.split(".")[-3:]) if own.endswith(".com.ar") else ".".join(own.split(".")[-2:])
    if h.endswith(root):
        return True
    return any(h == c or h.endswith("." + c) for c in COMMON_HOSTS)


def sitemap_products(base, http, platform, limit):
    urls = []
    st, _, t = http.get(base + "/robots.txt", "text/plain")
    maps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", t or "") or [base + "/sitemap.xml"]
    queue, seen = list(maps), set()
    while queue and len(seen) < 60 and len(urls) < limit * 4:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        st, _, x = http.get(htmlmod.unescape(u), "application/xml")
        locs = [htmlmod.unescape(l) for l in re.findall(r"<loc>\s*([^<\s]+)", x or "")]
        for l in locs:
            if l.endswith(".xml") or "sitemap" in l.split("/")[-1]:
                if re.search(r"product|producto|catalog", l, re.I) or len(seen) < 3:
                    queue.insert(0, l) if re.search(r"product", l, re.I) else queue.append(l)
            else:
                urls.append(l)
    prod_rx = {"woocommerce": r"/(producto|product|tienda)/", "shopify": r"/products/", "tiendanube": r"/productos/",
               "magento": r"\.html$"}.get(platform, r"/(producto|product|productos|products|p)/|\.html$")
    prods = [u for u in urls if re.search(prod_rx, u, re.I)] or urls
    random.Random(7).shuffle(prods)
    return prods[:limit]


def tiendanube_description(page_html):
    m = re.search(r'data-store="product-description[^"]*"[^>]*>(.*?)</div>\s*(?:</div>|<div[^>]*class="[^"]*(?:share|social|js-))',
                  page_html, re.S)
    if m:
        return m.group(1)
    m = re.search(r'class="[^"]*product-description[^"]*"[^>]*>(.*?)</div>', page_html, re.S)
    return m.group(1) if m else None


def scan_pages(base, http, platform, limit, emit_finding, emit_product):
    own = urllib.parse.urlsplit(base).netloc.lower().split(":")[0]
    pages = [base + "/"] + {"woocommerce": [base + "/carrito/", base + "/cart/"], "shopify": [base + "/cart"],
                             "magento": [base + "/checkout/cart/"], "tiendanube": [base + "/carrito/"]}.get(platform, [])
    prods = sitemap_products(base, http, platform, limit)
    log(f"  {len(prods)} páginas de producto del sitemap (muestra de hasta {limit})")
    pages += prods
    inline_on = defaultdict(set)     # hash -> páginas
    inline_body = {}
    ext_on = defaultdict(set)        # src -> páginas
    handlers = defaultdict(set)      # (tag,attr,value) -> páginas
    iframes = defaultdict(set)
    fetched = 0
    for i, u in enumerate(pages):
        st, h, t = http.get(u)
        if st != 200 or not t:
            continue
        fetched += 1
        if platform == "tiendanube" and u in prods:
            d = tiendanube_description(t)
            if d:
                emit_product({"description": d}, u.rstrip("/").split("/")[-1], None, u)
        for attrs, body in SCRIPT_RE.findall(t):
            src = SRC_RE.search(attrs)
            if src:
                ext_on[urllib.parse.urljoin(u, htmlmod.unescape(src.group(1)))].add(u)
            elif body.strip() and not re.search(r"type\s*=\s*[\"']?(application/(ld\+)?json|text/template|text/x-)", attrs, re.I):
                norm = VOLATILE.sub("#", body)
                k = hashlib.sha1(norm.encode()).hexdigest()[:16]
                inline_on[k].add(u)
                inline_body.setdefault(k, body)
        for tag, attr, _, val in HANDLER_RE.findall(t):
            handlers[(tag.lower(), attr.lower(), val[:400])].add(u)
        for s in IFRAME_RE.findall(t):
            iframes[host_of(s, u)].add(u)
        if (i + 1) % 25 == 0:
            log(f"  páginas {i + 1}/{len(pages)}")
    n = max(1, fetched)

    def share(s):
        return len(s) / n

    # 1) scripts inline: analizar todos; los que están en pocas páginas pesan más
    for k, where in inline_on.items():
        body = inline_body[k]
        hidden = [t for e, t in ds.reveal(body) if ds.JS_HINT.search(t)]
        behav = SKIMMER_BEHAVIOR.findall(body + "\n".join(hidden))
        hosts = [x for x in {hh.lower() for hh in URLHOST.findall(body + "\n".join(hidden))} if not is_common(x, own)]
        strong = re.search(r"\beval\s*\(|\batob\s*\(|fromCharCode|new\s+Function", body)
        rare = share(where) < 0.5 and fetched >= 8
        if hidden or (behav and hosts) or (rare and (strong or hosts)) or any(LOOKALIKE.search(x) for x in hosts):
            emit_finding({"kind": "inline-script", "pages": len(where), "of": fetched, "example_page": sorted(where)[0],
                          "hidden_js": [x[:1500] for x in hidden][:3], "behaviors": sorted(set(b.lower() for b in behav))[:10],
                          "unknown_hosts": hosts[:20], "rare": rare, "snippet": body[:1500]})
    # 2) handlers on*= en el HTML
    for (tag, attr, val), where in handlers.items():
        r = ds.analyze_string(f"<{tag} {attr}=\"{val}\">")
        rare = share(where) < 0.5 and fetched >= 8
        if r and (rare or "payload-js-codificado" in " ".join(r["rules"]) or re.search(r"eval|atob|fromCharCode", val)):
            emit_finding({"kind": "event-handler", "tag": tag, "attr": attr, "value": val, "pages": len(where), "of": fetched,
                          "example_page": sorted(where)[0], "rules": r["rules"], "hosts": r["hosts"], "rare": rare})
    # 3) scripts externos: inventario + análisis de cada uno
    ext_hosts = defaultdict(list)
    for src, where in ext_on.items():
        ext_hosts[host_of(src, base)].append(src)
    for src, where in sorted(ext_on.items(), key=lambda kv: -len(kv[1]))[:120]:
        hh = host_of(src, base)
        st, _, code = http.get(src, "*/*", n=6_000_000)
        if st != 200 or not code:
            continue
        hidden = [t for e, t in ds.reveal(code) if ds.JS_HINT.search(t)]
        h_hosts = [x for x in {y.lower() for y in URLHOST.findall("\n".join(hidden))} if not is_common(x, own)]
        behav = sorted(set(b.lower() for b in SKIMMER_BEHAVIOR.findall("\n".join(hidden))))
        uncommon = not is_common(hh, own)
        if (hidden and (h_hosts or behav)) or LOOKALIKE.search(hh) or (uncommon and share(where) < 0.5 and fetched >= 8):
            emit_finding({"kind": "external-script", "src": src, "host": hh, "pages": len(where), "of": fetched,
                          "hidden_js": [x[:1500] for x in hidden][:3], "hidden_hosts": h_hosts[:20], "behaviors": behav,
                          "uncommon_host": uncommon, "sha256": hashlib.sha256(code.encode()).hexdigest()[:16]})
    inv = {"pages_fetched": fetched, "inline_scripts": len(inline_on), "external_scripts": len(ext_on),
           "script_hosts": {h: len(v) for h, v in sorted(ext_hosts.items())},
           "uncommon_script_hosts": sorted(h for h in ext_hosts if not is_common(h, own)),
           "iframe_hosts": {h: len(v) for h, v in sorted(iframes.items())}}
    return inv


def main():
    global LOGF
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--pages", type=int, default=300, help="páginas de producto a revisar (tiendanube: es todo el catálogo revisado)")
    ap.add_argument("--rps", type=float, default=3)
    a = ap.parse_args()
    name, _, base = a.site.partition("=")
    base = base.rstrip("/")
    out = os.path.join("out", name)
    os.makedirs(out, exist_ok=True)
    LOGF = open(os.path.join(out, "progress.log"), "a", encoding="utf-8")
    fj = open(os.path.join(out, "findings.jsonl"), "w", encoding="utf-8")
    http = Http(a.rps)
    counts = {"catalog_products": 0, "catalog_findings": 0, "page_findings": 0}
    t0 = time.monotonic()
    log(f"[{name}] {a.platform} {base}")

    def emit_product(p, pid, pname, link):
        for f in ds.analyze_product(p):
            if f["severity"] == "BAJO":
                continue
            counts["catalog_findings"] += 1
            fj.write(json.dumps({"source": "catalog", "productId": pid, "name": pname, "link": link, "field": f["field"],
                                 "severity": f["severity"], "rules": f["rules"], "hosts": f["hosts"],
                                 "evidence": f["evidence"], "decoded": f.get("decoded", [])}, ensure_ascii=False) + "\n")
            fj.flush()

    def emit_finding(d):
        counts["page_findings"] += 1
        d["source"] = "pages"
        fj.write(json.dumps(d, ensure_ascii=False) + "\n")
        fj.flush()

    fn = {"woocommerce": catalog_woocommerce, "shopify": catalog_shopify, "magento": catalog_magento}.get(a.platform)
    if fn:
        log(f"[{name}] catálogo por API")
        counts["catalog_products"] = fn(base, http, emit_product)
    log(f"[{name}] páginas")
    limit = a.pages * (10 if a.platform == "tiendanube" else 1)
    inv = scan_pages(base, http, a.platform, limit, emit_finding, emit_product)
    if a.platform == "tiendanube":
        counts["catalog_products"] = inv["pages_fetched"]
    json.dump(inv, open(os.path.join(out, "pages.json"), "w"), indent=1, ensure_ascii=False)
    summary = dict(store=name, platform=a.platform, base=base, requests=http.count, errors=http.errors,
                   minutes=round((time.monotonic() - t0) / 60, 1), **counts,
                   pages_fetched=inv["pages_fetched"], uncommon_script_hosts=inv["uncommon_script_hosts"])
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
    log(f"[{name}] TERMINADO {json.dumps(summary, ensure_ascii=False)}")


if __name__ == "__main__":
    sys.exit(main())
