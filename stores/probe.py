#!/usr/bin/env python3
"""Relevamiento 2: API de Compra Gamer y estructura de Falabella."""
import gzip, json, re, urllib.request, urllib.error, urllib.parse
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
def get(url, n=8_000_000, accept="text/html,application/json,*/*"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept, "Accept-Language": "es-AR,es;q=0.9", "Accept-Encoding": "gzip"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            b = r.read(n)
            if r.headers.get("Content-Encoding") == "gzip":
                try: b = gzip.decompress(b)
                except Exception: pass
            return r.status, b.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        b = e.read(20000) or b""
        try: b = gzip.decompress(b)
        except Exception: pass
        return e.code, b.decode("utf-8", "replace")
    except Exception as e:
        return None, f"ERROR {e}"
out = {}
# --- Compra Gamer
st, home = get("https://compragamer.com/")
cg = {"home_status": st, "scripts": re.findall(r"<script[^>]+src=[\"']([^\"']+)", home), "home_tail": home[-1500:]}
urls, paths = set(), set()
for s in cg["scripts"]:
    u = urllib.parse.urljoin("https://compragamer.com/", s)
    s2, js = get(u)
    cg.setdefault("bundles", []).append([u, s2, len(js)])
    urls |= set(re.findall(r"https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./{}$]*)?", js))
    paths |= set(re.findall(r"[\"'`](/?(?:api|v\d|backend|ws|productos?|articulos?)[a-zA-Z0-9_\-/.]*)[\"'`]", js))
    for m in re.finditer(r"(apiUrl|baseUrl|API_URL|urlApi|api_url|backendUrl|environment)[^;]{0,300}", js):
        cg.setdefault("env_snippets", []).append(m.group(0)[:300])
cg["urls"] = sorted(u for u in urls if not re.search(r"w3\.org|angular\.io|github\.com|mozilla|googleapis\.com/css", u))[:300]
cg["paths"] = sorted(paths)[:300]
cg["env_snippets"] = cg.get("env_snippets", [])[:40]
s3, lazy = get("https://compragamer.com/")  # chunks referenced dynamically
cg["chunk_names"] = sorted(set(re.findall(r"chunk-[A-Z0-9]+\.js", " ".join(cg["urls"]) + home)))[:50]
out["compragamer"] = cg
# --- Falabella
fa = {}
st, idx = get("https://www.falabella.com/static/site/sitemaps/pdp/pdp_cl_FA_COM-index.xml")
kids = re.findall(r"<loc>\s*([^<\s]+)", idx)
fa["pdp_index_status"], fa["pdp_children"] = st, len(kids)
st, c0 = get(kids[0]) if kids else (None, "")
locs = re.findall(r"<loc>\s*([^<\s]+)", c0)
fa["child0"], fa["child0_locs"], fa["child0_sample"] = (kids[0] if kids else None), len(locs), locs[:5]
if locs:
    st, pdp = get(locs[0])
    fa["pdp_status"], fa["pdp_len"] = st, len(pdp)
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', pdp, re.S)
    if m:
        nd = json.loads(m.group(1)); pp = nd.get("props", {}).get("pageProps", {})
        fa["next_pageProps_keys"] = list(pp.keys())[:40]
        prod = pp.get("productData") or {}
        fa["productData_keys"] = list(prod.keys())[:60] if isinstance(prod, dict) else str(type(prod))
        s = json.dumps(pp)
        fa["desc_fields"] = sorted(set(re.findall(r'"([A-Za-z]*[Dd]escription[A-Za-z]*)"', s)))[:30]
        fa["buildId"] = nd.get("buildId")
    fa["pdp_script_hosts"] = sorted({urllib.parse.urlsplit(urllib.parse.urljoin(locs[0], x)).netloc for x in re.findall(r"<script[^>]+src=[\"']([^\"']+)", pdp)})
    fa["pdp_inline_scripts"] = len(re.findall(r"<script(?![^>]*src=)[^>]*>", pdp))
    fa["pdp_iframes"] = re.findall(r"<iframe[^>]+src=[\"']([^\"']+)", pdp)[:10]
st, ar = get("https://www.falabella.com.ar/")
fa["ar_status"] = st
out["falabella"] = fa
json.dump(out, open("probe.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps(out, ensure_ascii=False)[:5000])
