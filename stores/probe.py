#!/usr/bin/env python3
"""Relevamiento 5: de dónde salen la lista y el detalle de productos de Compra Gamer."""
import gzip, json, re, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(url, n=80_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, text/plain, */*", "Origin": "https://compragamer.com",
                                               "Referer": "https://compragamer.com/", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip": b = gzip.decompress(b)
            return r.status, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(3000) or b"").decode("utf-8", "replace")
    except Exception as e:
        return None, f"ERROR {e}"
st, home = get("https://compragamer.com/")
queue = [urllib.parse.urljoin("https://compragamer.com/", s) for s in re.findall(r"<script[^>]+src=[\"']([^\"']+)", home)]
seen, js = set(), []
while queue and len(seen) < 150:
    u = queue.pop(0)
    if u in seen: continue
    seen.add(u); s, t = get(u); js.append(t)
    queue += ["https://compragamer.com/" + c for c in re.findall(r"(chunk-[A-Z0-9]+\.js)", t)]
big = "\n".join(js)
def ctx(rx, n=25, w=260):
    return [big[max(0, m.start()-w): m.end()+w].replace("\n", " ") for m in re.finditer(rx, big)][:n]
out = {"pathRequest_ctx": ctx(r"pathRequest\s*=", 30), "apiGet_ctx": ctx(r"apiGet", 15), "descripcion_ctx": ctx(r"descripcion", 15, 200),
       "producto_ctx": ctx(r"[\"'`/]productos?[/\"'`?]", 30, 200)}
tries = {}
for p in ["https://static.compragamer.com/productos", "https://static.compragamer.com/productos.json", "https://static.compragamer.com/productos_lista",
          "https://api.compragamer.com/productos", "https://webbis.compragamer.com/serpir/productos"]:
    s, t = get(p)
    tries[p] = {"status": s, "len": len(t), "head": t[:300]}
out["tries"] = tries
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
