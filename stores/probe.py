#!/usr/bin/env python3
"""Relevamiento 4: archivos estáticos (apiStatic) y caches de Compra Gamer."""
import gzip, json, re, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(url, n=60_000_000):
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
out = {}
out["env"] = sorted(set(re.findall(r"(api[A-Za-z]*|static[A-Za-z]*|base[A-Za-z_]*URL|cdn[A-Za-z]*):\"(https?://[^\"]+)\"", big)))
out["pathRequest"] = sorted(set(re.findall(r"pathRequest(?:Index)?:([^,}]{1,120})", big)))[:80]
names = set(re.findall(r"\$\{[A-Za-z_$.]*(?:apiStatic|staticUrl|_staticRoute|newHome|staticPrefix)\}([a-zA-Z0-9_\-./]+)", big))
names |= set(re.findall(r"getStatic\(\"([a-zA-Z0-9_\-./]+)\"", big))
out["static_names"] = sorted(names)
static = dict(out["env"]).get("apiStatic")
out["static_probe"] = {}
for nm in sorted(names)[:80]:
    if not static: break
    s, t = get(static + nm)
    info = {"status": s, "len": len(t)}
    try:
        j = json.loads(t)
        if isinstance(j, list):
            info["list_len"] = len(j); info["first_keys"] = list(j[0].keys())[:40] if j and isinstance(j[0], dict) else None
        elif isinstance(j, dict):
            info["keys"] = list(j.keys())[:40]
    except Exception:
        info["head"] = t[:150]
    out["static_probe"][nm] = info
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
