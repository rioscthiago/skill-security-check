#!/usr/bin/env python3
"""
nvd_check.py — Fase 0 da skill `security-check`.

Consulta a NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0) por cada
entrada da watchlist, desde a última verificação registrada em `nvd-state.json`,
e imprime um digest em Markdown. Com `--commit`, grava o novo estado.

Sem dependências externas (stdlib). Funciona com qualquer python3.

Uso típico:
  python3 scripts/nvd_check.py                       # desde o last_check do estado
  python3 scripts/nvd_check.py --project ~/projetos/meu-app
  python3 scripts/nvd_check.py --since 2026-01-01 --min-score 7
  python3 scripts/nvd_check.py --commit              # grava last_check / processed

Rate limit da NVD: 5 req / 30 s sem key, 50 req / 30 s com key.
Key opcional em $NVD_API_KEY ou ~/.nvd.key (https://nvd.nist.gov/developers/request-an-api-key).
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 119  # NVD limita pub/lastMod range a 120 dias
PAGE = 200

# ---------------------------------------------------------------- utils


def iso(d: dt.datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_iso(s: str) -> dt.datetime:
    s = s.strip().replace("Z", "")
    s = re.sub(r"[+-]\d\d:\d\d$", "", s)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s[:26], fmt)
        except ValueError:
            pass
    raise ValueError(f"data inválida: {s}")


def api_key():
    k = os.environ.get("NVD_API_KEY")
    if k:
        return k.strip()
    p = pathlib.Path.home() / ".nvd.key"
    if p.exists():
        return p.read_text().strip() or None
    return None


def semver_tuple(v: str):
    v = re.sub(r"^[\^~>=<v\s]+", "", v or "").split("+")[0]
    core, _, pre = v.partition("-")
    nums = []
    for part in core.split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    # pré-release conta como menor que a release
    return tuple(nums[:3]) + ((0, pre) if pre else (1, ""))


def version_in_range(v: str, m: dict) -> bool:
    t = semver_tuple(v)
    ok = True
    if m.get("versionStartIncluding"):
        ok &= t >= semver_tuple(m["versionStartIncluding"])
    if m.get("versionStartExcluding"):
        ok &= t > semver_tuple(m["versionStartExcluding"])
    if m.get("versionEndIncluding"):
        ok &= t <= semver_tuple(m["versionEndIncluding"])
    if m.get("versionEndExcluding"):
        ok &= t < semver_tuple(m["versionEndExcluding"])
    exact = m["criteria"].split(":")[5] if m["criteria"].count(":") >= 5 else "*"
    if exact not in ("*", "-") and not any(
        m.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    ):
        ok &= semver_tuple(exact) == t
    return ok


# ---------------------------------------------------------------- NVD client


class Client:
    def __init__(self, key):
        self.key = key
        self.delay = 0.7 if key else 6.5
        self.last = 0.0
        self.calls = 0

    def get(self, params: dict, flags=()):
        q = urllib.parse.urlencode(params)
        for f in flags:
            q += "&" + f
        url = f"{API}?{q}"
        headers = {"User-Agent": "security-check-skill/1.0"}
        if self.key:
            headers["apiKey"] = self.key
        for attempt in range(6):
            wait = self.delay - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=90) as r:
                    self.last = time.time()
                    self.calls += 1
                    return json.load(r)
            except urllib.error.HTTPError as e:
                self.last = time.time()
                if e.code in (403, 429, 503, 502, 504):
                    time.sleep(12 * (attempt + 1))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                self.last = time.time()
                time.sleep(8 * (attempt + 1))
        raise RuntimeError(f"NVD API falhou após retries: {url}")


def windows(start, end):
    cur = start
    while cur < end:
        nxt = min(cur + dt.timedelta(days=MAX_WINDOW_DAYS), end)
        yield cur, nxt
        cur = nxt


def fetch_entry(client, entry, start, end, log):
    out = []
    label = entry.get("cpe") or entry.get("term")
    for ws, we in windows(start, end):
        idx = 0
        while True:
            params = {
                "lastModStartDate": iso(ws),
                "lastModEndDate": iso(we),
                "resultsPerPage": PAGE,
                "startIndex": idx,
            }
            flags = []
            if entry.get("cpe"):
                params["virtualMatchString"] = entry["cpe"]
            else:
                params["keywordSearch"] = entry["term"]
                if entry.get("exact"):
                    flags.append("keywordExactMatch")
            d = client.get(params, flags)
            got = [v["cve"] for v in d.get("vulnerabilities", [])]
            out += got
            total = d.get("totalResults", 0)
            idx += d.get("resultsPerPage", 0) or PAGE
            log(f"  {label}: {min(idx,total)}/{total}")
            if idx >= total or not got:
                break
    return out


# ---------------------------------------------------------------- extraction


def best_metric(cve):
    m = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lst = m.get(key) or []
        if not lst:
            continue
        lst = sorted(lst, key=lambda x: 0 if x.get("type") == "Primary" else 1)
        c = lst[0].get("cvssData", {})
        return {
            "score": c.get("baseScore"),
            "severity": (c.get("baseSeverity") or lst[0].get("baseSeverity") or "").upper() or None,
            "vector": c.get("vectorString"),
            "version": key.replace("cvssMetric", ""),
            "source": lst[0].get("source"),
        }
    return {"score": None, "severity": None, "vector": None, "version": None, "source": None}


def description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    return (cve.get("descriptions") or [{}])[0].get("value", "").strip()


def cwes(cve):
    out = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                out.add(d["value"])
    return sorted(out)


def cpe_matches(cve):
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    yield m


def affected_rows(cve):
    rows = []
    for m in cpe_matches(cve):
        parts = m["criteria"].split(":")
        prod = f"{parts[3]}:{parts[4]}" if len(parts) > 5 else m["criteria"]
        ver = parts[5] if len(parts) > 5 else "*"
        rng = []
        if m.get("versionStartIncluding"):
            rng.append(f">={m['versionStartIncluding']}")
        if m.get("versionStartExcluding"):
            rng.append(f">{m['versionStartExcluding']}")
        if m.get("versionEndIncluding"):
            rng.append(f"<={m['versionEndIncluding']}")
        if m.get("versionEndExcluding"):
            rng.append(f"<{m['versionEndExcluding']}")
        rows.append(f"{prod} {' '.join(rng) if rng else ver}".strip())
    return sorted(set(rows))


def refs(cve, n=3):
    lst = cve.get("references", [])

    def rank(r):
        u = r.get("url", "")
        tags = " ".join(r.get("tags", []))
        s = 0
        if "github.com/advisories" in u or "/security/advisories/" in u:
            s -= 5
        if "Patch" in tags:
            s -= 3
        if "Vendor Advisory" in tags:
            s -= 2
        if "Exploit" in tags:
            s -= 2
        return s

    return [r["url"] for r in sorted(lst, key=rank)[:n]]


# ---------------------------------------------------------------- project match

ALIASES = {
    # nome do pacote -> tokens usados nas descrições/CPE da NVD.
    # Só entra aqui quem tem nome diferente na NVD ou é scoped; o resto casa pelo
    # próprio nome (>= 4 caracteres).
    "next": ["next.js", "vercel:next.js"],
    "react": ["react", "facebook:react"],
    "react-dom": ["react-dom", "react dom"],
    "react-server-dom-webpack": ["react server components", "react-server-dom"],
    "pg": ["node-postgres", "pg-promise"],
    "mysql2": ["mysql2"],
    "ai": ["ai sdk", "vercel ai sdk"],
    "next-auth": ["nextauth", "next-auth", "auth.js", "nextauth.js"],
    "@auth/core": ["auth.js", "@auth/core"],
    "better-auth": ["better auth", "better-auth"],
    "@prisma/client": ["prisma"],
    "prisma": ["prisma"],
    "drizzle-orm": ["drizzle"],
    "@supabase/supabase-js": ["supabase"],
    "@supabase/ssr": ["supabase"],
    "@modelcontextprotocol/sdk": ["model context protocol", "modelcontextprotocol"],
    "@nestjs/core": ["nestjs", "nest.js"],
    "@sveltejs/kit": ["sveltekit"],
    "@angular/core": ["angular"],
    "nuxt": ["nuxt", "nuxt.js"],
    "express": ["express", "openjs:express", "expressjs:express"],
    "vite": ["vite", "vitejs"],
    "pdfjs-dist": ["pdf.js", "pdfjs"],
    "jose": ["jose"],
    "zod": ["zod"],
    "bcryptjs": ["bcryptjs", "bcrypt"],
    "@node-rs/argon2": ["argon2"],
    "langchain": ["langchain"],
    "@langchain/core": ["langchain"],
}


def load_project(path: pathlib.Path):
    """Retorna {npm_name: version_string} priorizando lockfile."""
    deps = {}
    pj = path / "package.json"
    if pj.exists():
        d = json.loads(pj.read_text())
        for k in ("dependencies", "devDependencies"):
            for name, v in (d.get(k) or {}).items():
                deps[name] = re.sub(r"^[\^~>=<\s]+", "", str(v))
    lock = path / "package-lock.json"
    if lock.exists():
        try:
            L = json.loads(lock.read_text())
            for key, meta in (L.get("packages") or {}).items():
                if key.startswith("node_modules/") and key.count("node_modules/") == 1:
                    name = key[len("node_modules/"):]
                    if name in deps and meta.get("version"):
                        deps[name] = meta["version"]
        except Exception:
            pass
    for lf in ("pnpm-lock.yaml", "yarn.lock"):
        if (path / lf).exists():
            txt = (path / lf).read_text(errors="ignore")
            for name in list(deps):
                m = re.search(r"^\s*/?" + re.escape(name) + r"@([0-9][^:\s'\"(]*)", txt, re.M) or re.search(
                    r'^"?' + re.escape(name) + r'@[^\n]*\n\s+version:?\s+"?([0-9][^"\s]*)', txt, re.M
                )
                if m:
                    deps[name] = m.group(1)
    return deps


def token_in(text: str, token: str) -> bool:
    return re.search(r"(?<![\w@/.-])" + re.escape(token) + r"(?![\w-])", text, re.I) is not None


def match_project(cve, deps):
    """Retorna lista de strings 'pkg@ver — status'."""
    if not deps:
        return []
    desc = description(cve)
    cpes = list(cpe_matches(cve))
    cpe_products = {m["criteria"].split(":")[4].lower() for m in cpes if m["criteria"].count(":") >= 5}
    cpe_vp = {":".join(m["criteria"].split(":")[3:5]).lower() for m in cpes if m["criteria"].count(":") >= 5}
    hits = []
    for name, ver in deps.items():
        if name.startswith("@types/"):
            continue  # tipos não executam nada; geravam falso "AFETADO" (react, node)
        scoped = name.startswith("@")
        tokens = ALIASES.get(name) or ([] if scoped else ([name] if len(name) >= 4 else []))
        norm = name.split("/")[-1].lower()
        matched_cpe = [m for m in cpes if m["criteria"].count(":") >= 5 and (
            (not scoped and m["criteria"].split(":")[4].lower() in (norm, norm.replace("-", "_"), norm + ".js", norm.replace("-", ".")))
            or any(t.lower() == ":".join(m["criteria"].split(":")[3:5]).lower() for t in tokens)
        )]
        by_desc = any(token_in(desc, t) for t in tokens if ":" not in t)
        if not matched_cpe and not by_desc:
            continue
        if matched_cpe:
            vulnerable = any(version_in_range(ver, m) for m in matched_cpe)
            hits.append(f"{name}@{ver} — {'⚠️ AFETADO' if vulnerable else 'fora do range'} (CPE)")
        else:
            hits.append(f"{name}@{ver} — match por nome, sem range CPE (conferir versões na descrição)")
    return hits


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=str(SKILL_DIR / "nvd-state.json"))
    ap.add_argument("--watchlist", default=str(SKILL_DIR / "nvd-watchlist.json"))
    ap.add_argument("--since", help="ISO date; default = last_check do estado")
    ap.add_argument("--until", help="ISO date; default = agora (UTC)")
    ap.add_argument("--min-score", type=float, default=4.0, help="esconde CVEs com score abaixo (sem score sempre aparece)")
    ap.add_argument("--terms", help="lista separada por vírgula pra restringir a watchlist")
    ap.add_argument("--project", action="append", default=[], help="pasta com package.json (repetível)")
    ap.add_argument("--all", action="store_true", help="inclui CVEs já processados sem mudança")
    ap.add_argument("--json", help="salva findings brutos em JSON")
    ap.add_argument("--md", help="salva digest Markdown")
    ap.add_argument("--commit", action="store_true", help="grava last_check/processed no estado")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    log = (lambda *x: None) if a.quiet else (lambda *x: print(*x, file=sys.stderr, flush=True))

    state_p = pathlib.Path(a.state)
    state = json.loads(state_p.read_text()) if state_p.exists() else {}
    watch = json.loads(pathlib.Path(a.watchlist).read_text())
    entries = watch["watchlist"]
    if a.terms:
        want = {t.strip().lower() for t in a.terms.split(",")}
        entries = [e for e in entries if (e.get("term") or e.get("cpe") or "").lower() in want]

    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    until = parse_iso(a.until) if a.until else now
    if a.since:
        since = parse_iso(a.since)
    elif state.get("last_check"):
        since = parse_iso(state["last_check"]) - dt.timedelta(hours=1)  # overlap de segurança
    else:
        since = until - dt.timedelta(days=30)
    if since >= until:
        print("Janela vazia (since >= until). Nada a fazer.")
        return

    key = api_key()
    client = Client(key)
    log(f"NVD check: {iso(since)} → {iso(until)} | {len(entries)} termos | key={'sim' if key else 'não (5 req/30s)'}")

    projects = {}
    for p in a.project:
        pp = pathlib.Path(p).expanduser().resolve()
        projects[pp.name] = load_project(pp)

    seen = {}
    for e in entries:
        label = e.get("cpe") or e.get("term")
        for cve in fetch_entry(client, e, since, until, log):
            if cve.get("vulnStatus") == "Rejected":
                continue
            rec = seen.setdefault(cve["id"], {"cve": cve, "terms": []})
            if label not in rec["terms"]:
                rec["terms"].append(label)

    processed = state.get("processed", {})
    findings = []
    skipped = 0
    for cid, rec in seen.items():
        cve = rec["cve"]
        lm = cve.get("lastModified", "")
        if not a.all and processed.get(cid) == lm:
            skipped += 1
            continue
        met = best_metric(cve)
        f = {
            "id": cid,
            "status": cve.get("vulnStatus"),
            "published": cve.get("published", "")[:10],
            "lastModified": lm,
            "score": met["score"],
            "severity": met["severity"],
            "cvss": met["version"],
            "vector": met["vector"],
            "kev": cve.get("cisaExploitAdd"),
            "cwes": cwes(cve),
            "terms": rec["terms"],
            "affected": affected_rows(cve),
            "desc": description(cve),
            "refs": refs(cve),
            "new": cid not in processed,
            "projects": {pn: match_project(cve, deps) for pn, deps in projects.items()},
        }
        f["projects"] = {k: v for k, v in f["projects"].items() if v}
        findings.append(f)

    def sort_key(f):
        return (0 if f["kev"] else 1, -(f["score"] or -1), f["published"])

    findings.sort(key=sort_key)
    shown = [f for f in findings if f["score"] is None or f["score"] >= a.min_score or f["kev"] or f["projects"]]
    hidden = len(findings) - len(shown)

    # ---- markdown
    L = []
    L.append(f"# NVD digest — {since:%Y-%m-%d} → {until:%Y-%m-%d}")
    L.append(f"- termos: {len(entries)} · requisições: {client.calls} · CVEs únicos na janela: {len(seen)} · novos/alterados: {len(findings)} · já processados: {skipped} · ocultos por score < {a.min_score}: {hidden}")
    kev = [f["id"] for f in shown if f["kev"]]
    if kev:
        L.append(f"- **KEV (exploração ativa conhecida, CISA):** {', '.join(kev)}")
    hit = [(f["id"], pn, h) for f in shown for pn, hs in f["projects"].items() for h in hs if "AFETADO" in h]
    if hit:
        L.append("- **⚠️ Dependências afetadas nos projetos informados:**")
        for cid, pn, h in hit:
            L.append(f"  - {cid} · {pn}: {h}")

    def block(title, items):
        if not items:
            return
        L.append("")
        L.append(f"## {title} ({len(items)})")
        for f in items:
            sc = f"{f['score']} {f['severity']} ({f['cvss']})" if f["score"] is not None else "sem CVSS"
            flag = " · **KEV**" if f["kev"] else ""
            nw = "novo" if f["new"] else "alterado"
            L.append("")
            L.append(f"### {f['id']} · {sc}{flag} · pub {f['published']} · {f['status']} · {nw}")
            L.append(f"- termos: {', '.join(f['terms'])}" + (f" · CWE: {', '.join(f['cwes'])}" if f["cwes"] else ""))
            if f["affected"]:
                L.append(f"- afeta (CPE): {'; '.join(f['affected'][:6])}" + (" …" if len(f["affected"]) > 6 else ""))
            for pn, hs in f["projects"].items():
                for h in hs:
                    L.append(f"- projeto {pn}: {h}")
            L.append(f"- {f['desc'][:700]}" + (" …" if len(f["desc"]) > 700 else ""))
            for r in f["refs"]:
                L.append(f"  - {r}")

    block("🔴 CRITICAL / HIGH (≥ 7.0)", [f for f in shown if f["score"] is not None and f["score"] >= 7])
    block("🟠 MEDIUM (4.0–6.9)", [f for f in shown if f["score"] is not None and 4 <= f["score"] < 7])
    block("🟡 LOW (< 4.0, mostrados por KEV/projeto)", [f for f in shown if f["score"] is not None and f["score"] < 4])
    block("⚪ Sem CVSS (triagem manual — Received/Awaiting Analysis)", [f for f in shown if f["score"] is None])

    latest = max(findings, key=lambda f: (f["published"], f["id"]))["id"] if findings else state.get("last_cve_processed")
    L.append("")
    L.append(f"- CVE mais recente na janela: {latest}")
    md = "\n".join(L)
    print(md)

    if a.md:
        pathlib.Path(a.md).write_text(md)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(findings, indent=1, ensure_ascii=False))

    if a.commit:
        for cid, rec in seen.items():
            processed[cid] = rec["cve"].get("lastModified", "")
        state.update(
            {
                "last_check": iso(until),
                "last_cve_processed": latest,
                "last_run": {
                    "at": iso(now),
                    "since": iso(since),
                    "until": iso(until),
                    "terms": len(entries),
                    "unique": len(seen),
                    "new_or_changed": len(findings),
                },
                "processed": processed,
            }
        )
        state_p.write_text(json.dumps(state, indent=1, ensure_ascii=False))
        log(f"estado gravado em {state_p} (last_check={iso(until)}, last_cve_processed={latest})")


if __name__ == "__main__":
    main()
