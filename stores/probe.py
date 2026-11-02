#!/usr/bin/env python3
"""Relevamiento 6: contexto de campos de tarjeta, jsdelivr/unpkg y alcance_fijo en el JS de Compra Gamer."""
import gzip, json, re, urllib.request, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(u):
    req = urllib.request.Request(u, headers={"User-Agent": UA, "Accept-Encoding": "gzip", "Referer": "https://compragamer.com/"})
    with urllib.request.urlopen(req, timeout=60) as r:
        b = r.read()
        if r.headers.get("Content-Encoding") == "gzip": b = gzip.decompress(b)
        return b.decode("utf-8", "replace")
out = {}
for c in ["chunk-427JYN7E.js", "chunk-6F457Z5R.js", "chunk-A4VEM5YH.js"]:
    t = get("https://compragamer.com/" + c)
    out[c] = {
      "card": [t[max(0,m.start()-250):m.end()+250] for m in re.finditer(r"cardNumber|card_number|ccnum|numero_?tarjeta|nroTarjeta|securityCode|codigo_?seguridad", t, re.I)][:12],
      "cdn": [t[max(0,m.start()-250):m.end()+250] for m in re.finditer(r"jsdelivr|unpkg|ipapi|metricool|chatwoot", t)][:10],
      "pago": [t[max(0,m.start()-250):m.end()+300] for m in re.finditer(r"serviciosAnx/pago|globalgetnet|\.endpoint", t)][:8]}
out["alcance_fijo_head"] = get("https://static.compragamer.com/alcance_fijo.json")[:600]
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
