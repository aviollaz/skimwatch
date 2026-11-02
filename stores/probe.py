#!/usr/bin/env python3
"""Detalle público de un producto VTEX: vendedor, fechas y si la descripción tiene <script>."""
import json, os, re, urllib.request
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
BASE, PID = "https://www.provinciacompras.com.ar", "328954"
def get(u):
    with urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": UA}), timeout=30) as r:
        return json.loads(r.read().decode())
p = get(f"{BASE}/api/catalog_system/pub/products/search?fq=productId:{PID}")
out = {"found": bool(p)}
if p:
    p = p[0]
    d = p.get("description") or ""
    out.update(productName=p.get("productName"), brand=p.get("brand"), releaseDate=p.get("releaseDate"), link=p.get("link"),
               description_has_script="<script" in d.lower(), description_head=d[:120],
               sellers=[{"sellerId": s.get("sellerId"), "sellerName": s.get("sellerName"),
                         "qty": (s.get("commertialOffer") or {}).get("AvailableQuantity"), "price": (s.get("commertialOffer") or {}).get("Price")}
                        for it in p.get("items", []) for s in it.get("sellers", [])])
    sid = out["sellers"][0]["sellerId"] if out["sellers"] else None
    if sid:  # otros productos del mismo vendedor con <script> en algún campo
        hits, n = [], 0
        for frm in range(0, 2500, 50):
            try: L = get(f"{BASE}/api/catalog_system/pub/products/search?fq=sellerId:{sid}&_from={frm}&_to={frm+49}")
            except Exception: break
            if not L: break
            for q in L:
                n += 1
                if re.search(r"<\s*script|i_p67x|onerror\s*=", json.dumps(q), re.I): hits.append([q.get("productId"), q.get("productName")])
        out["same_seller_scanned"], out["same_seller_hits"] = n, hits
os.makedirs("out/probe-pc", exist_ok=True)
json.dump(out, open("out/probe-pc/summary.json", "w"), indent=1, ensure_ascii=False)
