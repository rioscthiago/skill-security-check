#!/usr/bin/env python3
"""
gh_advisories.py — Fase 0 (complemento) da skill `security-check`.

Consulta o GitHub Advisory Database por dependência DIRETA do projeto
(`/advisories?ecosystem=npm&affects=<pkg>`), compara o range vulnerável com a
versão instalada (lockfile) ou declarada (package.json / requirements.txt) e
imprime só o que afeta o projeto + a versão mínima segura por pacote.

Por que além da NVD: a NVD indexa por CPE (atrasa semanas) e a busca por
palavra é ruidosa; o GH Advisory é por nome de pacote, com range semver exato.
A NVD continua sendo a fonte pra componentes que não são pacote (runtime, banco
de dados, cache, serviços self-hosted) e pro flag KEV.

Requer `gh` autenticado (`gh auth status`); sem auth funciona com limite baixo.

Uso:
  python3 scripts/gh_advisories.py --project . [--since 2026-01-01] [--all] [--json out.json]
  python3 scripts/gh_advisories.py --project ~/projetos/app1 --project ~/projetos/app2
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3, None: 4}

# ------------------------------------------------------------------ semver


def parse_ver(v: str):
    v = (v or "").strip().lstrip("v=^~<>! ").split("+")[0]
    core, _, pre = v.partition("-")
    nums = []
    for part in core.split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    pre_parts = []
    if pre:
        for p in pre.split("."):
            pre_parts.append((0, int(p)) if p.isdigit() else (1, p))
    return (tuple(nums[:3]), pre_parts)


def cmp_ver(a, b):
    (na, pa), (nb, pb) = parse_ver(a), parse_ver(b)
    if na != nb:
        return -1 if na < nb else 1
    if not pa and not pb:
        return 0
    if not pa:
        return 1  # release > prerelease
    if not pb:
        return -1
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


def in_range(ver: str, rng: str) -> bool:
    """rng no formato do GH: '>= 1.0.0, < 1.16.0' | '<= 0.31.1' | '= 19.2.0'."""
    ok = True
    for clause in rng.split(","):
        clause = clause.strip()
        m = re.match(r"(>=|<=|>|<|=)\s*(.+)$", clause)
        if not m:
            continue
        op, v = m.group(1), m.group(2).strip()
        c = cmp_ver(ver, v)
        ok &= {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
    return ok


# ------------------------------------------------------------------ projeto


def npm_deps(path: pathlib.Path):
    """{name: (version, source)} source = lock | declared"""
    out = {}
    pj = path / "package.json"
    if not pj.exists():
        return out
    d = json.loads(pj.read_text())
    for k in ("dependencies", "devDependencies"):
        for name, v in (d.get(k) or {}).items():
            v = str(v)
            if v.startswith(("workspace:", "file:", "link:", "git", "http", "npm:")):
                continue
            out[name] = (re.sub(r"^[\^~>=<\s]+", "", v).split(" ")[0], "declared")
    lock = path / "package-lock.json"
    if lock.exists():
        try:
            L = json.loads(lock.read_text())
            for key, meta in (L.get("packages") or {}).items():
                if key.startswith("node_modules/") and key.count("node_modules/") == 1:
                    name = key[len("node_modules/"):]
                    if name in out and meta.get("version"):
                        out[name] = (meta["version"], "lock")
        except Exception:
            pass
    pl = path / "pnpm-lock.yaml"
    if pl.exists():
        txt = pl.read_text(errors="ignore")
        for name in list(out):
            m = re.search(r"^\s+/?" + re.escape(name) + r"@([0-9][^:\s'\"(]*)", txt, re.M)
            if m:
                out[name] = (m.group(1), "lock")
    yl = path / "yarn.lock"
    if yl.exists():
        txt = yl.read_text(errors="ignore")
        for name in list(out):
            m = re.search(r'^"?' + re.escape(name) + r'@[^\n]*:\n(?:\s+.*\n)*?\s+version:?\s+"?([0-9][^"\s]*)', txt, re.M)
            if m:
                out[name] = (m.group(1), "lock")
    return out


def pip_deps(path: pathlib.Path):
    out = {}
    for f in ("requirements.txt", "requirements/base.txt"):
        p = path / f
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.split("#")[0].strip()
                m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|>)?\s*([0-9][^,;\s]*)?", line)
                if m and m.group(1):
                    out[m.group(1).lower()] = (m.group(3) or "0", "pinned" if m.group(2) == "==" else "declared")
    pp = path / "pyproject.toml"
    if pp.exists():
        txt = pp.read_text()
        m = re.search(r"dependencies\s*=\s*\[(.*?)\]", txt, re.S)
        if m:
            for item in re.findall(r'"([^"]+)"', m.group(1)):
                mm = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|>)?\s*([0-9][^,;\s]*)?", item)
                if mm:
                    out[mm.group(1).lower()] = (mm.group(3) or "0", "pinned" if mm.group(2) == "==" else "declared")
    return out


# ------------------------------------------------------------------ GitHub


_cache = {}


def gh_advisories(eco: str, pkg: str, since: str):
    key = (eco, pkg, since)
    if key in _cache:
        return _cache[key]
    url = f"/advisories?ecosystem={eco}&affects={urllib.parse.quote(pkg, safe='')}&published=%3E%3D{since}&per_page=100"
    r = subprocess.run(["gh", "api", url], capture_output=True, text=True)
    if r.returncode != 0:
        _cache[key] = ("ERR", r.stderr.strip()[:160])
        return _cache[key]
    try:
        data = json.loads(r.stdout)
    except Exception as e:
        data = ("ERR", str(e))
    _cache[key] = data
    return data


# ------------------------------------------------------------------ main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", action="append", required=True, help="pasta do projeto (repetível)")
    ap.add_argument("--since", default=None, help="YYYY-MM-DD; default = 365 dias atrás")
    ap.add_argument("--all", action="store_true", help="mostra também advisories que NÃO afetam a versão instalada")
    ap.add_argument("--json", help="salva resultado")
    a = ap.parse_args()
    since = a.since or (dt.date.today() - dt.timedelta(days=365)).isoformat()

    chk = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if chk.returncode != 0:
        print("aviso: gh não autenticado — limite de 60 req/h", file=sys.stderr)

    report = {}
    for proj in a.project:
        p = pathlib.Path(proj).expanduser().resolve()
        deps = {("npm", n): v for n, v in npm_deps(p).items()}
        deps.update({("pip", n): v for n, v in pip_deps(p).items()})
        rows = []
        errors = []
        for (eco, name), (ver, src) in sorted(deps.items()):
            data = gh_advisories(eco, name, since)
            if isinstance(data, tuple):
                errors.append(f"{eco}:{name}: {data[1]}")
                continue
            for adv in data:
                if adv.get("withdrawn_at") or adv.get("summary", "").lower().startswith(("withdrawn", "duplicate advisory")):
                    continue
                vulns = [v for v in adv.get("vulnerabilities", []) if (v.get("package") or {}).get("name", "").lower() == name.lower()]
                if not vulns:
                    continue
                affected = any(in_range(ver, v.get("vulnerable_version_range") or "") for v in vulns)
                patched = [v.get("first_patched_version") for v in vulns if v.get("first_patched_version")]
                rows.append(
                    {
                        "eco": eco,
                        "package": name,
                        "installed": ver,
                        "source": src,
                        "affected": affected,
                        "ghsa": adv.get("ghsa_id"),
                        "cve": adv.get("cve_id"),
                        "severity": adv.get("severity"),
                        "score": (adv.get("cvss") or {}).get("score"),
                        "published": adv.get("published", "")[:10],
                        "summary": adv.get("summary", ""),
                        "ranges": "; ".join(f"{v.get('vulnerable_version_range')} → {v.get('first_patched_version') or '?'}" for v in vulns),
                        "patched": patched,
                        "url": adv.get("html_url"),
                    }
                )
        rows.sort(key=lambda r: (not r["affected"], SEV_ORDER.get(r["severity"], 4), r["published"]))
        report[str(p)] = {"deps": len(deps), "rows": rows, "errors": errors}

        hit = [r for r in rows if r["affected"]]
        print(f"\n## {p.name} — {len(deps)} deps diretas · advisories desde {since}: {len(rows)} · afetam a versão atual: {len(hit)}")
        if errors:
            print(f"- erros de consulta: {len(errors)} (ex.: {errors[0]})")
        # versão mínima segura por pacote afetado: menor patched > instalada, preferindo a mesma major
        mins = {}
        for r in hit:
            inst = r["installed"]
            cands = [pv for pv in r["patched"] if cmp_ver(pv, inst) > 0]
            same_major = [pv for pv in cands if parse_ver(pv)[0][0] == parse_ver(inst)[0][0]]
            pick = min(same_major or cands, key=lambda v: parse_ver(v)) if (same_major or cands) else None
            if pick is None:
                continue
            cur = mins.get(r["package"])
            if cur is None or cmp_ver(pick, cur) > 0:
                mins[r["package"]] = pick
        if mins:
            print("- **mínimo seguro sugerido:** " + ", ".join(f"{k} ≥ {v}" for k, v in sorted(mins.items())))
        majors = sorted({r["package"] for r in hit if all(parse_ver(pv)[0][0] != parse_ver(r["installed"])[0][0] for pv in r["patched"]) and r["patched"]})
        if majors:
            print(f"- **sem patch na major instalada (exige upgrade de major):** {', '.join(majors)}")
        shown = rows if a.all else hit
        for r in shown:
            flag = "⚠️" if r["affected"] else "ok"
            sc = f"{r['score']}" if r["score"] is not None else "-"
            print(f"  {flag} {r['eco']}:{r['package']}@{r['installed']} ({r['source']}) · {r['severity']} {sc} · {r['cve'] or r['ghsa']} · {r['published']}")
            print(f"     {r['summary'][:120]}")
            print(f"     range: {r['ranges'][:160]}")
        if not hit:
            print("  nenhuma dependência direta em range vulnerável (checar transitivas com npm audit / pip-audit)")

    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(report, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
