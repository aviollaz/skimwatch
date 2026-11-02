#!/usr/bin/env python3
"""Relevamiento 3: endpoints de api.compragamer.com usados por su frontend."""
import gzip, json, re, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(url, n=8_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, text/plain, */*", "Origin": "https://compragamer.com",
                                               "Referer": "https://compragamer.com/", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip": b = gzip.decompress(b)
            return r.status, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(3000) or b"").decode("utf-8", "replace")
    except Exception as e:
        return None, f"ERROR {e}"
st, home = get("https://compragamer.com/")
main = [urllib.parse.urljoin("https://compragamer.com/", s) for s in re.findall(r"<script[^>]+src=[\"']([^\"']+)", home)]
seen, queue, js_all = set(), list(main), {}
while queue and len(seen) < 120:
    u = queue.pop(0)
    if u in seen: continue
    seen.add(u); s, js = get(u); js_all[u] = js
    for c in re.findall(r"(chunk-[A-Z0-9]+\.js)", js):
        queue.append("https://compragamer.com/" + c)
big = "\n".join(js_all.values())
out = {"n_files": len(js_all)}
out["api_ctx"] = [big[max(0, m.start()-200): m.end()+300] for m in re.finditer(r"api\.compragamer\.com", big)][:15]
# strings que parecen rutas de API
cands = set(re.findall(r"[\"'`]((?:/|\$\{[^}]{1,40}\}/)[a-zA-Z_][a-zA-Z0-9_\-]{2,40}(?:/[a-zA-Z0-9_\-${}.]{1,40}){0,4})[\"'`]", big))
out["route_strings"] = sorted(c for c in cands if not c.startswith("/assets"))[:400]
# llamadas http
out["http_calls"] = [big[max(0, m.start()-80): m.end()+220] for m in re.finditer(r"this\.(?:http|_http|httpClient)\.(?:get|post)\(", big)][:120]
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
