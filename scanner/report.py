"""Rendu du rapport de scan : un fichier HTML autonome (aucune ressource externe), façon dashboard."""
import html
from collections import Counter, defaultdict

E = html.escape
SEV = ("critical", "high", "medium", "low", "unknown")
SEV_FR = {"critical": "Critique", "high": "Haut", "medium": "Moyen", "low": "Bas", "unknown": "Inconnu"}
TOOL_FR = {"secrets": "Secrets", "deps": "Dépendances", "code": "Code", "skill": "Audit"}
STEP_FR = {"inventory": "Inventaire", "secrets": "Secrets · gitleaks", "deps": "Dépendances · OSV-Scanner",
           "code": "Code · Semgrep", "skill": "Skill d'audit · validateurs"}

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--fg:#14171c;--muted:#626a75;--line:#e3e6ea;--soft:#f0f2f5;
--ok:#18794e;--ok-bg:#e6f4ec;--part:#9a6100;--part-bg:#fdf1dc;--no:#b42318;--no-bg:#fde8e7;--na:#5b6370;--na-bg:#eceef1;
--critical:#b42318;--high:#d4580f;--medium:#b58100;--low:#3a6fd8;--unknown:#7a828d;--bar:#2f6fde;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1115;--panel:#171a20;--fg:#e7e9ee;--muted:#98a0ac;--line:#272b33;--soft:#1e222a;
--ok:#4cc38a;--ok-bg:#16301f;--part:#e5a73a;--part-bg:#33270f;--no:#f2706a;--no-bg:#3a1714;--na:#9aa2ad;--na-bg:#23272e;
--critical:#f2706a;--high:#f0884a;--medium:#e5b93a;--low:#6e9df2;--unknown:#98a0ac;--bar:#5b93f0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-end;justify-content:space-between;margin-bottom:20px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:13px}.meta code{font:12px var(--mono)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:32px 0 10px;font-weight:600}
.verdict{font-weight:700;font-size:13px;padding:6px 14px;border-radius:999px;letter-spacing:.04em}
.verdict.ok{background:var(--ok-bg);color:var(--ok)}.verdict.fail{background:var(--no-bg);color:var(--no)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:26px;line-height:1.15;font-variant-numeric:tabular-nums}
.kpi span{color:var(--muted);font-size:12px}
.kpi.sev-critical b{color:var(--critical)}.kpi.sev-high b{color:var(--high)}.kpi.sev-medium b{color:var(--medium)}.kpi.sev-low b{color:var(--low)}
.dims{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px}
.dim{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:6px}
.dim .top{display:flex;justify-content:space-between;gap:8px;align-items:center}
.dim strong{font-size:14px}.dim p{margin:0;color:var(--muted);font-size:12.5px}
.chip{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.c-ok{background:var(--ok-bg);color:var(--ok)}.c-part{background:var(--part-bg);color:var(--part)}
.c-no{background:var(--no-bg);color:var(--no)}.c-na{background:var(--na-bg);color:var(--na)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;background:var(--soft)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td code,.mono{font:12px var(--mono)}
.bar{display:flex;align-items:center;gap:8px;min-width:140px}
.bar i{flex:1;height:6px;border-radius:3px;background:var(--soft);position:relative;overflow:hidden}
.bar i em{position:absolute;inset:0 auto 0 0;background:var(--bar);border-radius:3px}
.bar small{font-variant-numeric:tabular-nums;color:var(--muted);min-width:38px;text-align:right}
.sevs{display:flex;gap:4px;flex-wrap:wrap}
.s{font:600 11px var(--mono);padding:1px 6px;border-radius:4px;color:#fff}
.s-critical{background:var(--critical)}.s-high{background:var(--high)}.s-medium{background:var(--medium)}.s-low{background:var(--low)}.s-unknown{background:var(--unknown)}
.muted{color:var(--muted)}
.det{white-space:nowrap}.det+.det{margin-top:6px}.det b{display:block;font-weight:600;font-size:12.5px}
.det small{display:block;color:var(--muted);font:11px var(--mono);white-space:normal;max-width:300px;word-break:break-all}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:10px}
ul.gaps{margin:0;padding:6px 0;list-style:none}
ul.gaps li{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:baseline}
ul.gaps li:last-child{border-bottom:0}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.filters button{font:12px system-ui,sans-serif;border:1px solid var(--line);background:var(--panel);color:var(--fg);border-radius:999px;padding:4px 12px;cursor:pointer}
.filters button[aria-pressed=true]{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.timeline{display:flex;flex-direction:column;gap:6px;padding:12px 14px}
.tl{display:grid;grid-template-columns:200px 1fr 56px;gap:10px;align-items:center;font-size:12.5px}
.tl i{height:8px;border-radius:4px;background:var(--soft);position:relative}
.tl i em{position:absolute;top:0;bottom:0;border-radius:4px;background:var(--bar)}
.tl.fail i em{background:var(--no)}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media (max-width:640px){.tl{grid-template-columns:110px 1fr 48px}}
"""

JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.filters button').forEach(x=>x.setAttribute('aria-pressed',x===b));
const f=b.dataset.f;document.querySelectorAll('#findings tbody tr').forEach(r=>{
r.hidden=!(f==='all'||r.dataset.sev===f||r.dataset.tool.split(' ').includes(f))})}));
"""


def chip(kind, label):
    return f'<span class="chip c-{kind}">{E(label)}</span>'


def sev_badges(counts):
    out = [f'<span class="s s-{s}" title="{SEV_FR[s]}">{counts[s]}</span>' for s in SEV if counts.get(s)]
    return f'<div class="sevs">{"".join(out)}</div>' if out else '<span class="muted">—</span>'


def bar(n, total):
    if not total:
        return '<span class="muted">—</span>'
    pct = round(100 * n / total)
    return f'<div class="bar"><i><em style="width:{pct}%"></em></i><small>{pct} %</small></div>'


def fmt_tokens(n):
    return f"{n / 1e6:.2f} M".replace(".", ",") if n >= 1e6 else f"{n / 1e3:.0f} k" if n >= 1e3 else str(n)


def mmss(sec):
    sec = int(sec or 0)
    return f"{sec // 60:02d}:{sec % 60:02d}"


def merge_by_location(items, order):
    """Un même fichier:ligne signalé par plusieurs outils devient un seul constat, avec tous ses détecteurs."""
    merged, out = {}, []
    for i in items:
        key = i["where"] if i["tool"] in ("secrets", "code") else None
        if key and key in merged:
            m = merged[key]
            m["tools"] += i.get("tools", [])
            m["steps"].add(i["tool"])
            m["rule"] = f'{m["rule"]} + {i["rule"]}' if i["rule"] not in m["rule"] else m["rule"]
            if order[i["sev"]] < order[m["sev"]]:
                m["sev"] = i["sev"]
            continue
        i = {**i, "tools": list(i.get("tools", [])), "steps": {i["tool"]}}
        if key:
            merged[key] = i
        out.append(i)
    return out


def detectors(i):
    return "".join(f'<div class="det"><b>{E(t["name"])}</b><small>{E(t["detail"])}</small></div>' for t in i["tools"])


def app_files(v):
    """Fichiers applicatifs : analysables, hors tests et hors exclusions déclarées par le dépôt."""
    return v["analysable"] - v["tests"] - v["excluded"]


def zone_state(v, code_ok):
    if not v["analysable"]:
        return chip("na", "Sans code")
    if not code_ok:
        return chip("no", "Non couverte")
    app = app_files(v)
    if app <= 0:
        return chip("part", "Exclue (dépôt)") if v["excluded"] >= v["tests"] else chip("part", "Tests seulement")
    if v["scanned"] == 0:
        return chip("no", "Non couverte")
    return chip("ok", "Couverte") if v["scanned"] >= app * 0.9 else chip("part", "Partielle")


def not_scanned(v):
    parts = [f"{v['unparsed']} erreur d'analyse" if v.get("unparsed") else "",
             f"{v['tests']} tests" if v["tests"] else "", f"{v['excluded']} exclus" if v["excluded"] else "",
             f"{v['other']} autres" if v["other"] else ""]
    return " · ".join(p for p in parts if p) or "—"


def dimensions(d):
    steps, inv = d["steps"], d["inventory"]
    dims = []

    def state_of(name):
        s = steps.get(name, {})
        if name not in d["only"]:
            return "na", "Non lancé"
        if "error" in s:
            return "no", "Erreur"
        return None, None

    k, lbl = state_of("secrets")
    s = steps.get("secrets", {})
    dims.append(("Secrets", (k, lbl) if k else ("ok", "Couvert"), s.get("error") or s.get("scope", "")))

    k, lbl = state_of("deps")
    s = steps.get("deps", {})
    if not k:
        locks, unc = s.get("lockfiles", []), s.get("uncovered_manifests", [])
        if not locks and not inv["manifests"]:
            k, lbl = "na", "Sans objet"
        elif not locks:
            k, lbl = "no", "Non couvert"
        elif unc:
            k, lbl = "part", "Partiel"
        else:
            k, lbl = "ok", "Couvert"
        detail = f"{len(locks)} lockfile(s) analysé(s)" + (f", {len(unc)} manifeste(s) sans lockfile" if unc else "")
    else:
        detail = s.get("error", "")
    dims.append(("Dépendances", (k, lbl), detail))

    k, lbl = state_of("code")
    s = steps.get("code", {})
    if not k:
        sc, app = inv["analysable_scanned"], app_files(inv)
        pct = round(100 * sc / app) if app else 0
        k, lbl = ("ok", "Couvert") if pct >= 90 else ("part", "Partiel") if pct > 0 else ("no", "Non couvert")
        detail = (f"{sc}/{app} fichiers applicatifs ({pct} %), {len(s.get('packs', []))} packs. "
                  f"Hors calcul : {inv['tests']} tests, {inv['excluded']} exclus par le dépôt"
                  + (f". {inv['unparsed']} en erreur d'analyse" if inv.get("unparsed") else ""))
    else:
        detail = s.get("error", "")
    dims.append(("Code statique", (k, lbl), detail))

    k, lbl = state_of("skill")
    s = steps.get("skill", {})
    if not k:
        v = s.get("validated", {})
        if all(x == "valide" for x in v.values()) and v:
            k, lbl, detail = "ok", "Validé", "findings.json et coverage-ledger.json conformes au schéma"
        elif any(x == "invalide" for x in v.values()):
            k, lbl, detail = "no", "Invalide", ", ".join(f"{a} {b}" for a, b in v.items())
        else:
            k, lbl, detail = "na", "Non monté", "Aucune sortie d'audit par agent fournie (option --audit)"
    else:
        detail = s.get("error", "")
    dims.append(("Audit par agent", (k, lbl), detail))

    sql = inv["langs"].get("SQL", 0)
    dims.append(("API en conditions réelles", ("no", "Non couvert"),
                 "Aucune exécution : authz, validation d'entrée, en-têtes, limites non testés en vrai"))
    dims.append(("Back-end sous charge", ("no", "Non couvert"), "Pas de test de charge ni d'épuisement de ressources"))
    dims.append(("Base de données", ("no", "Non couvert"),
                 (f"{sql} fichier(s) SQL détecté(s), " if sql else "") + "rôles, privilèges et RLS non testés en exécution"))
    return dims


def gaps(d):
    steps, inv = d["steps"], d["inventory"]
    out = [("no", "Dynamique", "API, back-end et BDD en conditions réelles : hors périmètre du scan statique (voir INTENT.md, phase 2)")]
    for name, s in steps.items():
        if name in TOOL_FR and "error" in s:
            out.append(("no", TOOL_FR[name], f"Étape en erreur : {s['error'][:200]}"))
        elif name in TOOL_FR and name not in d["only"]:
            out.append(("na", TOOL_FR[name], "Étape non lancée (--only)"))
    if "code" in d["only"] and "error" not in steps.get("code", {}):
        for z, v in sorted(inv["zones"].items()):
            if v["excluded"]:
                out.append(("part", "Code", f"Zone {z} : {v['excluded']} fichier(s) exclu(s) par la config du dépôt"))
            if v["other"]:
                out.append(("no", "Code", f"Zone {z} : {v['other']} fichier(s) ignoré(s) par Semgrep (taille, syntaxe ou langage)"))
        for u in steps.get("code", {}).get("unparsed_detail", []):
            out.append(("no", "Code", f"{u['path']} : erreur d'analyse Semgrep, règles non appliquées ({u['msg']})"))
        if inv["tests"]:
            out.append(("na", "Code", f"{inv['tests']} fichier(s) de test non analysés (dossiers test/ et tests/ ignorés par défaut par Semgrep)"))
    for lang in inv.get("langs_without_pack", []):
        out.append(("part", "Code", f"{lang} : pas de pack dédié, règles génériques (security-audit) seulement"))
    for m in steps.get("deps", {}).get("uncovered_manifests", []):
        out.append(("part", "Dépendances", f"{m} : aucun lockfile, versions non résolues donc non vérifiées"))
    ex = steps.get("code", {}).get("exclusions", 0)
    if ex:
        out.append(("na", "Code", f"{ex} exclusion(s) Semgrep déclarée(s) par le dépôt (tests/security/semgrep-exclusions.json)"))
    for f in steps.get("secrets", {}).get("skipped", []):
        out.append(("no", "Secrets", f"{f} : fichier non suivi de plus de 10 Mo, non analysé"))
    if d["git"].get("git"):
        out.append(("na", "Inventaire", "Fichiers ignorés par .gitignore exclus (dépendances installées, builds)"))
        if not d["git"].get("commits"):
            out.append(("part", "Secrets", "Dépôt git sans commit : pas d'historique, seul le répertoire de travail est analysé"))
    else:
        out.append(("part", "Secrets", "Pas d'historique git : secrets supprimés dans le passé non détectables"))
    return out


def render(d):
    steps, inv = d["steps"], d["inventory"]
    items = []
    for name in ("secrets", "deps", "code", "skill"):
        for it in steps.get(name, {}).get("items", []):
            items.append({**it, "tool": name})
    order = {s: i for i, s in enumerate(SEV)}
    items = merge_by_location(items, order)
    items.sort(key=lambda x: (order.get(x["sev"], 9), x["tool"], x["where"]))
    totals = Counter(i["sev"] for i in items)
    by_zone = defaultdict(Counter)
    for i in items:
        by_zone[i["zone"]][i["sev"]] += 1

    g = d["git"]
    ref = (f'<code>{E(g.get("branch", ""))}</code> @ <code>{E(g.get("commit", "")[:10])}</code>'
           + (" · worktree modifié" if g.get("dirty") else "")) if g.get("git") else "sans git"
    verdict = '<span class="verdict fail">ÉCHEC</span>' if d["fail"] else '<span class="verdict ok">OK</span>'
    tot, sc = app_files(inv), inv["analysable_scanned"]
    cov = f"{min(100, 100 * sc // tot)} %" if tot > 0 else "—"  # arrondi par défaut : 240/241 n'affiche pas 100 %

    h = [f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         f'<title>Scan · {E(d["repo"])}</title><style>{CSS}</style></head><body><div class="wrap">']
    h.append(f'<header><div><h1>Rapport de scan · {E(d["repo"])}</h1><div class="meta">{ref} · {E(d["started"])} UTC · '
             f'{inv["files"]} fichiers · mode {"strict" if d["strict"] else "standard"}</div></div>{verdict}</header>')

    h.append('<div class="kpis">')
    for s in ("critical", "high", "medium", "low"):
        h.append(f'<div class="kpi sev-{s}"><b>{totals.get(s, 0)}</b><span>{SEV_FR[s]}</span></div>')
    h.append(f'<div class="kpi"><b>{cov}</b><span>Code applicatif analysé ({sc}/{tot})</span></div>')
    h.append(f'<div class="kpi"><b>{len(inv["zones"])}</b><span>Zones · {len(inv["langs"])} langages</span></div>')
    h.append(f'<div class="kpi"><b>{mmss(d["duration"])}</b><span>Durée · budget {mmss(d["budget"])}</span></div>')
    tk = steps.get("skill", {}).get("tokens")
    h.append(f'<div class="kpi"><b>{fmt_tokens(tk["total"]) if tk else "—"}</b><span>Tokens audit agent'
             f'{"" if tk else " (non monté)"}</span></div>')
    h.append('</div>')

    h.append('<h2>Couverture par dimension</h2><div class="dims">')
    for title, (k, lbl), detail in dimensions(d):
        h.append(f'<div class="dim"><div class="top"><strong>{E(title)}</strong>{chip(k, lbl)}</div><p>{E(detail)}</p></div>')
    h.append('</div>')

    h.append('<h2>Zones</h2><div class="panel scroll"><table><thead><tr><th>Zone</th><th class="num">Fichiers</th>'
             '<th>Langages</th><th>Code analysé</th><th>Non analysé</th><th>Constats</th><th>État</th></tr></thead><tbody>')
    code_ok = "code" in d["only"] and "error" not in steps.get("code", {})

    def zkey(z):
        c = by_zone.get(z, Counter())
        return (-c["critical"], -c["high"], -c["medium"], -inv["zones"][z]["files"])
    for z in sorted(inv["zones"], key=zkey):
        v = inv["zones"][z]
        langs = ", ".join(f"{k} {n}" for k, n in Counter(v["langs"]).most_common(3)) or "—"
        h.append(f'<tr><td><code>{E(z)}</code></td><td class="num">{v["files"]}</td><td class="muted">{E(langs)}</td>'
                 f'<td>{bar(v["scanned"], v["analysable"])}</td><td class="muted">{not_scanned(v)}</td>'
                 f'<td>{sev_badges(by_zone.get(z, {}))}</td><td>{zone_state(v, code_ok)}</td></tr>')
    h.append('</tbody></table></div>')

    h.append('<div class="cols"><div><h2>Non couvert et limites</h2><div class="panel"><ul class="gaps">')
    for k, area, text in gaps(d):
        h.append(f'<li>{chip(k, area)}<span>{E(text)}</span></li>')
    h.append('</ul></div></div>')

    h.append('<div><h2>Déroulé</h2><div class="panel"><div class="timeline">')
    longest = max([steps.get(n, {}).get("seconds", 0) for n in STEP_FR] + [1])
    for n, label in STEP_FR.items():
        s = steps.get(n, {})
        sec = s.get("seconds", 0)
        w = max(1, round(100 * sec / longest)) if sec else 0
        cls = " fail" if "error" in s else ""
        h.append(f'<div class="tl{cls}"><span>{E(label)}</span><i><em style="left:0;width:{w}%"></em></i>'
                 f'<span class="mono muted">{mmss(sec)}</span></div>')
    h.append('</div></div>')
    if tk:
        h.append('<h2>Audit par agent · tokens</h2><div class="panel scroll"><table><thead><tr><th>Phase</th>'
                 '<th class="num">Agents</th><th class="num">Tokens</th><th>Part</th></tr></thead><tbody>')
        for p in tk["phases"]:
            h.append(f'<tr><td>{E(str(p["phase"]))}</td><td class="num">{p["agents"] or "—"}</td>'
                     f'<td class="num">{fmt_tokens(p["tokens"] or 0)}</td><td>{bar(p["tokens"] or 0, tk["total"])}</td></tr>')
        h.append(f'<tr><td><strong>Total</strong></td><td class="num">{sum(p["agents"] or 0 for p in tk["phases"])}</td>'
                 f'<td class="num"><strong>{fmt_tokens(tk["total"])}</strong></td><td></td></tr></tbody></table></div>')
        h.append(f'<p class="muted">Run <code>{E(tk["run_id"])}</code>. {E(tk["model"])}. {E(tk["note"])}</p>')
    h.append('<h2>Langages</h2><div class="panel scroll"><table><thead><tr><th>Langage</th><th class="num">Fichiers</th>'
             '<th>Règles</th></tr></thead><tbody>')
    nopack = set(inv.get("langs_without_pack", []))
    for lang, n in Counter(inv["langs"]).most_common():
        rules = "génériques seulement" if lang in nopack else ("—" if lang not in inv.get("langs_with_pack", []) else "pack dédié")
        h.append(f'<tr><td>{E(lang)}</td><td class="num">{n}</td><td class="muted">{rules}</td></tr>')
    h.append('</tbody></table></div></div></div>')

    h.append(f'<h2>Constats ({len(items)})</h2>')
    if items:
        h.append('<div class="filters"><button data-f="all" aria-pressed="true">Tous</button>')
        for s in SEV:
            if totals.get(s):
                h.append(f'<button data-f="{s}" aria-pressed="false">{SEV_FR[s]} {totals[s]}</button>')
        for t, lbl in TOOL_FR.items():
            if any(i["tool"] == t for i in items):
                h.append(f'<button data-f="{t}" aria-pressed="false">{lbl}</button>')
        h.append('</div><div class="panel scroll"><table id="findings"><thead><tr><th>Sévérité</th><th>Détecté par</th>'
                 '<th>Emplacement</th><th>Règle / ID</th><th>Description</th></tr></thead><tbody>')
        for i in items[:500]:
            h.append(f'<tr data-sev="{i["sev"]}" data-tool="{" ".join(sorted(i["steps"]))}"><td><span class="s s-{i["sev"]}">{SEV_FR[i["sev"]]}</span></td>'
                     f'<td>{detectors(i)}</td><td><code>{E(i["where"])}</code></td><td><code>{E(i["rule"])}</code></td>'
                     f'<td>{E(i["msg"])}</td></tr>')
        h.append('</tbody></table></div>')
        if len(items) > 500:
            h.append(f'<p class="muted">500 premiers constats affichés sur {len(items)}. Liste complète dans les JSON bruts.</p>')
    else:
        h.append('<div class="panel"><ul class="gaps"><li>Aucun constat.</li></ul></div>')

    code = steps.get("code", {})
    v = d.get("versions", {})
    h.append(f'<footer>Security Kit {E(v.get("kit", "?"))} · gitleaks {E(v.get("gitleaks", "?"))} · OSV-Scanner {E(v.get("osv", "?"))} · '
             f'Semgrep {E(v.get("semgrep", "?"))}, règles figées le {E(code.get("rules_date", "—"))}'
             f' ({E(", ".join(code.get("packs", [])))}) · skill cloudflare/security-audit-skill {E(v.get("skill", "?"))}'
             f' · image {E(v.get("arch", "?"))}. '
             f'JSON bruts : gitleaks.json, osv.json, semgrep.json, resume.json.</footer>')
    h.append(f'</div><script>{JS}</script></body></html>')
    return "".join(h)
