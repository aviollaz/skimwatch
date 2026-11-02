#!/usr/bin/env python3
"""
Escaneo de Compra Gamer (plataforma propia, Angular).

La tienda no tiene páginas de producto en el servidor: el navegador baja el
catálogo entero y los textos de la tienda desde archivos JSON estáticos
(static.compragamer.com) y arma todo con JavaScript. Así que "todo lo que el
sitio le muestra al usuario" = esos JSON + el JavaScript. Este script:

  1. Baja el JavaScript del sitio (bundle principal + todos los chunks) y los
     SDK de pago que la tienda declara (Getnet, MODO, Mercado Pago).
  2. Deduce del propio JavaScript la lista de archivos estáticos que usa y los
     baja todos.
  3. Pasa cada texto de los JSON por los mismos detectores del escaneo de
     Cencosud (deep_scan.analyze_string): handlers on*, <script>, eval/atob,
     base64 que decodifica a JavaScript, comportamiento de skimmer.
  4. En el JavaScript busca payloads codificados, ganchos sobre fetch/XHR,
     lectura de campos de tarjeta y TODOS los dominios a los que se habla,
     para revisarlos a mano.

Salida en ./out/compragamer/: findings.jsonl, js_inventory.json, static_inventory.json, summary.json
"""
import gzip
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("deep_scan", os.path.join(HERE, "..", "deep-scan", "deep_scan.py"))
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
BASE = "https://compragamer.com/"
OUT = os.path.join("out", "compragamer")


def get(url, n=200_000_000):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "application/json, text/plain, */*",
        "Origin": "https://compragamer.com", "Referer": BASE, "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                b = gzip.decompress(b)
            return r.status, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return None, f"ERROR {e}"


def log(m):
    print(m, flush=True)


# ---------------------------------------------------------------- JavaScript

JS_BEHAVIOR = {
    "hook-fetch": re.compile(r"window\.fetch\s*=(?!=)"),
    "hook-xhr": re.compile(r"XMLHttpRequest\.prototype\.(open|send)\s*=(?!=)"),
    "sendBeacon": re.compile(r"sendBeacon\s*\("),
    "websocket": re.compile(r"new\s+WebSocket\s*\("),
    "campos-tarjeta": re.compile(r"(cardNumber|card_number|ccnum|cc-number|numero_?tarjeta|nroTarjeta|cvv|cvc|securityCode|codigo_?seguridad)", re.I),
    "eval/Function": re.compile(r"\beval\s*\(|\bFunction\s*\(\s*['\"`]"),
    "document.write": re.compile(r"document\.write\s*\("),
}
URL_IN_JS = re.compile(r"(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=[/\"'`:?])", re.I)


def js_files():
    st, home = get(BASE)
    srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", home)
    inline = re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", home, re.S | re.I)
    queue = [urllib.parse.urljoin(BASE, s) for s in srcs]
    files, seen = {}, set()
    while queue:
        u = queue.pop(0)
        if u in seen or len(seen) > 400:
            continue
        seen.add(u)
        s, t = get(u)
        if s != 200:
            log(f"  JS {u}: HTTP {s}")
            continue
        files[u] = t
        for c in re.findall(r"(chunk-[A-Z0-9]+\.js)", t):
            queue.append(urllib.parse.urljoin(BASE, c))
    # service worker y su manifiesto (decide qué archivos sirve cacheados)
    for extra in ("ngsw-worker.js", "ngsw.json"):
        s, t = get(BASE + extra)
        if s == 200:
            files[BASE + extra] = t
    return home, inline, files


def analyze_js(url, code):
    rep = {"url": url, "bytes": len(code), "sha256": hashlib.sha256(code.encode()).hexdigest()[:16]}
    rep["hosts"] = sorted({h.lower() for h in URL_IN_JS.findall(code)})
    rep["behaviors"] = {k: len(rx.findall(code)) for k, rx in JS_BEHAVIOR.items() if rx.search(code)}
    hidden = ds.reveal(code)
    rep["hidden_js"] = [{"encoding": e, "preview": t[:600], "hosts": ds.external_hosts(t)}
                        for e, t in hidden if ds.JS_HINT.search(t)]
    # contexto de cada uso de eval/Function/hook, para revisarlo a mano
    ctx = []
    for k in ("hook-fetch", "hook-xhr", "eval/Function", "sendBeacon", "websocket", "document.write"):
        for m in JS_BEHAVIOR[k].finditer(code):
            ctx.append({"kind": k, "context": code[max(0, m.start() - 200): m.end() + 200]})
            if len(ctx) > 40:
                break
    rep["contexts"] = ctx
    return rep


# ---------------------------------------------------------------- JSON estáticos

def static_names(js_text, static_base):
    names = set()
    pats = [
        r"pathRequestStatic\s*\+\s*\"([^\"]+)\"",
        r"pathRequestStatic\}([a-zA-Z0-9_\-./]+)`",
        r"\$\{[A-Za-z_$.]*(?:apiStatic|staticUrl|_staticRoute|newHome|staticPrefix)\}([a-zA-Z0-9_\-./]+)",
        r"getStatic\(\s*[\"'`]([a-zA-Z0-9_\-./]+)",
        re.escape(static_base) + r"([a-zA-Z0-9_\-./]+)",
    ]
    for p in pats:
        names |= set(re.findall(p, js_text))
    return sorted(n for n in names if n and not n.endswith("/"))


def walk(obj, path=""):
    yield from ds.walk_strings(obj, path)


def main():
    os.makedirs(OUT, exist_ok=True)
    findings = open(os.path.join(OUT, "findings.jsonl"), "w", encoding="utf-8")
    nfind = 0

    log("== JavaScript del sitio")
    home, inline, files = js_files()
    env = dict(re.findall(r"(\w+):\"(https?://[^\"]+)\"", "\n".join(files.values())))
    static_base = env.get("apiStatic", "https://static.compragamer.com/")
    pay = re.search(r"paymentBundlesUrl:\{([^}]*)\}", "\n".join(files.values()))
    pay_urls = re.findall(r"\"(https?://[^\"]+)\"", pay.group(1)) if pay else []
    log(f"  {len(files)} archivos JS propios; SDK de pago declarados: {pay_urls}")
    for u in pay_urls:
        s, t = get(u)
        log(f"  SDK {u}: HTTP {s}, {len(t):,} bytes")
        if s == 200:
            files[u] = t
            # el loader de Getnet/MODO puede traer más scripts
            for extra in re.findall(r"[\"'](https://[a-z0-9.-]+/[^\"'\s]+\.js)[\"']", t)[:15]:
                s2, t2 = get(extra)
                if s2 == 200:
                    files[extra] = t2

    js_inv = [analyze_js(u, t) for u, t in files.items()]
    js_inv += [analyze_js(f"{BASE}#inline-{i}", t) for i, t in enumerate(inline)]
    all_hosts = {}
    for r in js_inv:
        for h in r["hosts"]:
            all_hosts.setdefault(h, []).append(r["url"])
    json.dump({"files": js_inv, "hosts": {h: sorted(set(v))[:10] for h, v in sorted(all_hosts.items())},
               "env": env, "payment_sdks": pay_urls}, open(os.path.join(OUT, "js_inventory.json"), "w"),
              indent=1, ensure_ascii=False)
    hidden_total = sum(len(r["hidden_js"]) for r in js_inv)
    log(f"  {len(all_hosts)} dominios referenciados en el JS; payloads JS codificados: {hidden_total}")

    log("== Archivos estáticos (catálogo y textos)")
    names = static_names("\n".join(files.values()), static_base)
    log(f"  {len(names)} archivos estáticos referenciados")
    static_inv, products = {}, 0
    for nm in names:
        url = static_base + nm
        s, t = get(url)
        info = {"status": s, "bytes": len(t)}
        if s != 200:
            static_inv[nm] = info
            continue
        try:
            data = json.loads(t)
        except Exception:
            # alcance_fijo.json se EVALÚA como JavaScript en el sitio: si no es JSON puro, es código
            info["not_json"] = True
            r = ds.analyze_string(t)
            info["analysis"] = r and {k: r[k] for k in ("severity", "rules", "hosts")}
            static_inv[nm] = info
            continue
        if isinstance(data, list):
            info["items"] = len(data)
        if nm == "productos" and isinstance(data, list):
            products = len(data)
        n_str = 0
        for path, sv in walk(data):
            n_str += 1
            r = ds.analyze_string(sv)
            if not r:
                continue
            m = re.match(r"\[(\d+)\]", path)
            item = data[int(m.group(1))] if (m and isinstance(data, list)) else None
            row = {"file": nm, "path": path, "severity": r["severity"], "rules": r["rules"], "hosts": r["hosts"],
                   "evidence": r["evidence"], "decoded": r.get("decoded", []),
                   "id_producto": item.get("id_producto") if isinstance(item, dict) else None,
                   "nombre": item.get("nombre") if isinstance(item, dict) else None}
            findings.write(json.dumps(row, ensure_ascii=False) + "\n")
            nfind += 1
        info["strings"] = n_str
        static_inv[nm] = info
        log(f"  {nm}: {info.get('items', '-')} items, {n_str:,} textos revisados")
    json.dump(static_inv, open(os.path.join(OUT, "static_inventory.json"), "w"), indent=1, ensure_ascii=False)
    findings.close()

    summary = {"js_files": len(files), "inline_scripts": len(inline), "js_hosts": len(all_hosts),
               "js_hidden_payloads": hidden_total, "static_files": len(names), "products": products,
               "findings": nfind}
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=1)
    log(f"== Resumen: {summary}")


if __name__ == "__main__":
    sys.exit(main())
