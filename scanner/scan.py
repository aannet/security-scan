#!/usr/bin/env python3
"""Scan de sécurité statique d'un dépôt quelconque. Étapes en parallèle, budget de temps global, progression en console.

Usage (dans le conteneur) :
  scan.py [--only=secrets,deps,code,skill] [--strict]

Entrées (montées par l'appelant, voir scan.sh) :
  /src     dépôt à scanner, en lecture seule
  /src/tests/security  config optionnelle du dépôt : gitleaks.toml, osv-scanner.toml, semgrep-exclusions.json
  /audit   optionnel : sortie d'un audit par agent (findings.json, coverage-ledger.json) à valider
  /out     rapports : report.html, resume.json, JSON bruts des outils

Codes de sortie : 1 si un constat critique (secret, CVSS >= 9, Semgrep CRITICAL), une erreur d'outil ou un dépassement
de budget ; avec --strict, 1 aussi pour un constat haut (CVSS >= 7, Semgrep ERROR/HIGH). Sinon 0.

Le suivi est uniquement affiché en console : aucun fichier de suivi n'est créé. Les fichiers temporaires vivent dans
/tmp (tmpfs du conteneur), détruit avec lui.
"""
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

SRC = Path(os.environ.get("SRC", "/src"))
OUT = Path(os.environ.get("OUT", "/out"))
CFG = Path(os.environ.get("CONFIG_DIR", str(SRC / "tests" / "security")))
RULES = Path(os.environ.get("RULES_DIR", "/opt/rules"))
# 9 min 30 : laisse la marge du démarrage du conteneur et du rendu pour tenir les 10 minutes.
BUDGET = int(os.environ.get("SCAN_BUDGET", "570"))
T0 = time.monotonic()
# Versions fixées par le Dockerfile (ENV) : source unique, reprises dans les constats et le rapport.
VERSIONS = {"kit": os.environ.get("KIT_VERSION", "dev"), "gitleaks": os.environ.get("GITLEAKS_VERSION", "?"), "osv": os.environ.get("OSV_VERSION", "?"),
            "semgrep": os.environ.get("SEMGREP_VERSION", "?"), "skill": os.environ.get("SKILL_REF", "?")[:7],
            "arch": os.uname().machine}
# Fichiers non suivis plus gros que ce seuil : non copiés pour gitleaks (tmpfs de 1 Go), signalés comme non couverts.
LOOSE_MAX = 10 * 1024 * 1024

LABELS = {"inventory": "Inventaire", "secrets": "Secrets", "deps": "Dépendances", "code": "Code", "skill": "Skill d'audit"}
TOOLS = {"inventory": "git ls-files", "secrets": "gitleaks", "deps": "OSV-Scanner", "code": "Semgrep", "skill": "validateurs Cloudflare"}
LEVELS = ("critical", "high", "medium", "low", "unknown")

# Répertoires jamais inventoriés hors git (dépendances, sorties de build).
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next", ".turbo",
             "target", ".tox", "coverage", ".cache"}
# Conteneurs de monorepo : la zone descend d'un niveau (apps/api plutôt que apps).
CONTAINERS = {"apps", "packages", "services", "libs", "modules", "cmd", "internal", "src", "projects"}
LANG = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".py": "Python", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".rs": "Rust", ".scala": "Scala", ".swift": "Swift", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".sql": "SQL", ".sh": "Shell", ".bash": "Shell", ".tf": "Terraform", ".yml": "YAML",
    ".yaml": "YAML", ".html": "HTML", ".vue": "Vue", ".svelte": "Svelte", ".json": "JSON",
}
# Langages pour lesquels Semgrep a un analyseur : base du calcul de couverture du code.
ANALYSABLE = {"TypeScript", "JavaScript", "Python", "Go", "Java", "Kotlin", "Ruby", "PHP", "C#", "Rust", "Scala",
              "Swift", "C", "C++", "Shell", "Terraform", "YAML", "HTML", "Vue", "Svelte", "Dockerfile", "SQL"}
PACKS = {"TypeScript": ["typescript", "javascript"], "JavaScript": ["javascript"], "Python": ["python"],
         "Go": ["golang"], "Java": ["java"], "Kotlin": ["kotlin"], "Ruby": ["ruby"], "PHP": ["php"], "C#": ["csharp"],
         "Rust": ["rust"], "Scala": ["scala"], "Dockerfile": ["dockerfile"], "Terraform": ["terraform"], "C": ["c"]}
MANIFESTS = {"package.json", "pyproject.toml", "Pipfile", "requirements.txt", "Cargo.toml", "Gemfile", "composer.json",
             "go.mod", "pom.xml", "build.gradle", "build.gradle.kts"}


def empty():
    return dict.fromkeys(LEVELS, 0)


def sev(score):
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "unknown"


def read_json(path, fallback):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback


def remaining():
    return BUDGET - (time.monotonic() - T0)


def run(args, **kw):
    """Lance un outil dans le temps restant du budget global ; un dépassement tue l'outil et fait échouer l'étape."""
    left = remaining()
    if left < 5:
        raise RuntimeError("budget de temps épuisé avant le lancement")
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=left, **kw)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"budget de temps dépassé ({BUDGET} s), outil interrompu")


def zone_of(path):
    parts = PurePosixPath(path).parts
    if len(parts) <= 1:
        return "(racine)"
    if parts[0] in CONTAINERS and len(parts) > 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def lang_of(path):
    name = PurePosixPath(path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    return LANG.get(PurePosixPath(path).suffix.lower())


# ---------------------------------------------------------------------------------------------- progression console

class Board:
    """Tableau des étapes. En TTY : redessiné sur place, étapes qui se ferment. Sinon : une ligne par transition."""
    SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    COLORS = {"ok": "32", "warn": "33", "fail": "31", "skip": "90", "run": "36", "wait": "90"}
    ICONS = {"wait": "·", "ok": "✓", "warn": "!", "fail": "✗", "skip": "–"}
    WORDS = {"wait": "attente", "run": "en cours", "ok": "terminé", "warn": "constats", "fail": "échec", "skip": "ignoré"}

    def __init__(self, names):
        self.names = names
        self.st = {n: {"state": "wait", "t0": None, "t1": None, "note": ""} for n in names}
        self.lock = threading.Lock()
        self.tty = sys.stdout.isatty()
        self.drawn = 0
        self.tick = 0
        self.stop = threading.Event()

    def set(self, name, state, note=""):
        with self.lock:
            s = self.st[name]
            if state == "run":
                s["t0"] = time.monotonic()
            elif state in ("ok", "warn", "fail", "skip"):
                s["t1"] = time.monotonic()
            s["state"], s["note"] = state, note
            if not self.tty:
                print(f"[{fmt_t(time.monotonic() - T0)}] {LABELS[name]:<14} {self.WORDS[state]:<10} {note}", flush=True)

    def elapsed(self, name):
        s = self.st[name]
        if not s["t0"]:
            return 0.0
        return (s["t1"] or time.monotonic()) - s["t0"]

    def _line(self, name):
        s = self.st[name]
        state = s["state"]
        icon = self.ICONS.get(state) or self.SPIN[self.tick % len(self.SPIN)]
        t = fmt_t(self.elapsed(name)) if s["t0"] else "     "
        c = self.COLORS[state]
        return f"  \x1b[{c}m{icon}\x1b[0m {LABELS[name]:<14} \x1b[90m{t}  {TOOLS[name]:<22}\x1b[0m {s['note']}"

    def draw(self):
        with self.lock:
            done = sum(1 for n in self.names if self.st[n]["state"] in ("ok", "warn", "fail", "skip"))
            total = len(self.names)
            width = 24
            fill = int(width * done / total)
            el = time.monotonic() - T0
            lines = [self._line(n) for n in self.names]
            lines.append(f"  [{'█' * fill}{'░' * (width - fill)}] {done}/{total} étapes · {fmt_t(el)} / budget {fmt_t(BUDGET)}")
            out = ""
            if self.drawn:
                out += f"\x1b[{self.drawn}F"
            out += "".join(f"\x1b[2K{line}\n" for line in lines)
            sys.stdout.write(out)
            sys.stdout.flush()
            self.drawn = len(lines)
            self.tick += 1

    def loop(self):
        last_beat = time.monotonic()
        while not self.stop.wait(0.15 if self.tty else 1.0):
            if self.tty:
                self.draw()
            elif time.monotonic() - last_beat >= 20:
                last_beat = time.monotonic()
                with self.lock:
                    running = [f"{LABELS[n]} {fmt_t(self.elapsed(n))}" for n in self.names if self.st[n]["state"] == "run"]
                if running:
                    print(f"[{fmt_t(time.monotonic() - T0)}] en cours : {', '.join(running)}", flush=True)

    def start(self):
        if self.tty:
            sys.stdout.write("\x1b[?25l")  # curseur masqué pendant le redessin
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join()
        if self.tty:
            self.draw()
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()


def fmt_t(sec):
    sec = int(sec)
    return f"{sec // 60:02d}:{sec % 60:02d}"


# ------------------------------------------------------------------------------------------------------------ étapes

def git_info():
    if not (SRC / ".git").exists():
        return {"git": False}
    def g(*a):
        r = subprocess.run(["git", "-C", str(SRC), *a], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else ""
    return {"git": True, "commit": g("rev-parse", "HEAD"), "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
            "commits": int(g("rev-list", "--all", "--count") or 0), "dirty": bool(g("status", "--porcelain"))}


def inventory():
    files, untracked = None, []
    if (SRC / ".git").exists():
        # -t préfixe chaque chemin de son état ("? " = non suivi) : fichiers et non suivis en un seul appel.
        r = subprocess.run(["git", "-C", str(SRC), "ls-files", "-z", "-t", "--cached", "--others", "--exclude-standard"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            tagged = [(p[2:], p[0] == "?") for p in r.stdout.split("\0") if p and (SRC / p[2:]).is_file()]
            files = [p for p, _ in tagged]
            untracked = [p for p, other in tagged if other]
    if files is None:
        files = []
        for root, dirs, names in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in names:
                files.append(str(Path(root, n).relative_to(SRC)))
    zones = {}
    langs = Counter()
    manifests = []
    for f in files:
        z = zones.setdefault(zone_of(f), {"files": 0, "analysable": 0, "langs": Counter()})
        z["files"] += 1
        lang = lang_of(f)
        if lang:
            langs[lang] += 1
            z["langs"][lang] += 1
            if lang in ANALYSABLE:
                z["analysable"] += 1
        if PurePosixPath(f).name in MANIFESTS:
            manifests.append(f)
    info = git_info()
    note = f"{len(files)} fichiers, {len(zones)} zones, {len(langs)} langages"
    return {"files": files, "untracked": untracked, "zones": zones, "langs": langs, "manifests": manifests,
            "git": info, "note": note}


LOOSE = Path("/tmp/gitleaks-files")  # copie des fichiers hors historique, pour gitleaks dir


def copy_loose(files):
    """Copie dans /tmp les fichiers que l'historique ne contient pas ; renvoie ceux écartés pour leur taille."""
    shutil.rmtree(LOOSE, ignore_errors=True)
    skipped = []
    for f in files:
        src = SRC / f
        if src.stat().st_size > LOOSE_MAX:
            skipped.append(f)
            continue
        dst = LOOSE / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    LOOSE.mkdir(exist_ok=True)
    return skipped


def secrets(inv):
    """Historique git, modifications indexées et non indexées, fichiers non suivis. Dépôt git sans commit : tous les
    fichiers du répertoire de travail. Sans git : le répertoire."""
    cfg = ["--config", str(CFG / "gitleaks.toml")] if (CFG / "gitleaks.toml").exists() else []
    base = ["--no-banner", "--report-format", "json", "--redact", "--exit-code", "0", *cfg]
    g = inv["git"]
    passes = []
    loose = []
    if g["git"] and g.get("commits"):
        passes.append(("history", ["gitleaks", "git", *base, str(SRC)]))
        passes.append(("unstaged", ["gitleaks", "git", "--pre-commit", *base, str(SRC)]))
        passes.append(("staged", ["gitleaks", "git", "--pre-commit", "--staged", *base, str(SRC)]))
        loose = inv["untracked"]
        scope = f"{g['commits']} commits, modifications indexées et non indexées, {len(loose)} fichier(s) non suivi(s)"
    elif g["git"]:
        loose = inv["files"]
        scope = f"aucun commit : {len(loose)} fichier(s) du répertoire de travail"
    else:
        passes.append(("dir", ["gitleaks", "dir", *base, str(SRC)]))
        scope = "répertoire (pas d'historique git)"
    skipped = copy_loose(loose) if loose else []
    if loose:
        passes.append(("files", ["gitleaks", "dir", *base, str(LOOSE)]))
    def one(p):
        name, args = p
        report = Path(f"/tmp/gitleaks-{name}.json")
        try:
            r = run([*args[:-1], "--report-path", str(report), args[-1]])
            if r.returncode != 0:
                raise RuntimeError(f"gitleaks {name} : {(r.stderr or r.stdout)[-400:]}")
            return name, args[-1] + "/", read_json(report, [])
        finally:
            report.unlink(missing_ok=True)

    try:  # passes indépendantes : en parallèle, fusionnées dans l'ordre de la liste
        with ThreadPoolExecutor(max_workers=max(1, len(passes))) as pool:
            results = list(pool.map(one, passes))
    finally:
        shutil.rmtree(LOOSE, ignore_errors=True)
    found = {}
    for name, root, findings in results:
        for f in findings:
            path = str(f.get("File") or "")
            f["File"] = path[len(root):] if path.startswith(root) else path  # chemins relatifs au dépôt
            key = (f["File"], f.get("StartLine"), f.get("RuleID"), f.get("Commit", ""))
            found.setdefault(key, {**f, "_pass": name})
    found = list(found.values())
    (OUT / "gitleaks.json").write_text(json.dumps(found, indent=2, ensure_ascii=False), encoding="utf-8")
    c = empty()
    c["critical"] = len(found)  # tout secret est critique tant qu'il n'est pas justifié dans gitleaks.toml
    passes_fr = {"history": "historique git", "unstaged": "modification non indexée", "staged": "modification indexée",
                 "files": "fichier non suivi" if g.get("commits") else "répertoire de travail (aucun commit)",
                 "dir": "répertoire"}
    items = [{"sev": "critical", "where": f"{f['File']}:{f.get('StartLine')}", "rule": f.get("RuleID", ""),
              "msg": f"commit {str(f['Commit'])[:8]}" if f.get("Commit") else passes_fr[f["_pass"]],
              "zone": zone_of(f["File"]),
              "tools": [{"name": f"gitleaks {VERSIONS['gitleaks']}",
                         "detail": f"règle {f.get('RuleID', '')} · {passes_fr[f['_pass']]}"}]}
             for f in found]
    return {"counts": c, "items": items, "scope": scope, "config": bool(cfg), "skipped": skipped,
            "note": (f"{len(found)} secret(s)" if found else "aucun secret")
                    + (f", {len(skipped)} fichier(s) trop gros ignoré(s)" if skipped else "")}


def deps(inv):
    report = OUT / "osv.json"
    report.unlink(missing_ok=True)
    cfg = ["--config", str(CFG / "osv-scanner.toml")] if (CFG / "osv-scanner.toml").exists() else []
    r = run(["osv-scanner", "scan", "source", "-r", *cfg, "--format", "json", "--output-file", str(report), str(SRC)])
    if r.returncode not in (0, 1, 128):  # 1 = vulnérabilités trouvées ; 128 = aucun paquet trouvé
        raise RuntimeError(f"osv-scanner : code {r.returncode} {(r.stderr or r.stdout)[-400:]}")
    data = read_json(report, {"results": []})
    c = empty()
    items = []
    lockfiles = []
    for res in data.get("results") or []:
        src = str((res.get("source") or {}).get("path", ""))
        rel = os.path.relpath(src, SRC) if src.startswith(str(SRC)) else src
        lockfiles.append(rel)
        for p in res.get("packages") or []:
            by_id = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            for g in p.get("groups") or []:
                try:
                    level = sev(float(g.get("max_severity")))
                except (TypeError, ValueError):
                    level = "unknown"
                c[level] += 1
                ids = g.get("ids") or []
                gid = ids[0] if ids else None
                pkg = p["package"]
                items.append({"sev": level, "where": f"{pkg['name']}@{pkg['version']} · {rel}", "rule": gid or "",
                              "msg": (by_id.get(gid) or {}).get("summary", ""), "zone": zone_of(rel),
                              "tools": [{"name": f"OSV-Scanner {VERSIONS['osv']}",
                                         "detail": f"base OSV.dev · {', '.join(ids[:3])} · {pkg.get('ecosystem', '')}"}]})
    # Un manifeste est couvert si un lockfile scanné se trouve dans son répertoire ou un parent (workspaces).
    lockfiles = sorted(set(lockfiles))
    lock_dirs = {str(PurePosixPath(l).parent) for l in lockfiles}
    uncovered = [m for m in inv["manifests"]
                 if not any(str(d) in lock_dirs for d in PurePosixPath(m).parents)]
    return {"counts": c, "items": items, "lockfiles": lockfiles, "uncovered_manifests": uncovered,
            "config": bool(cfg), "note": f"{len(lockfiles)} lockfile(s), {sum(c.values())} vulnérabilité(s)"}


TEST_DIRS = {"test", "tests"}  # ignorés par défaut par Semgrep (.semgrepignore implicite)


def uncovered_reason(path, scanned, patterns, unparsed=()):
    """scanned, unparsed (erreur d'analyse), excluded (exclusion du dépôt), tests (ignorés par défaut par Semgrep), other."""
    if path in scanned:
        return "scanned"
    if path in unparsed:
        return "unparsed"
    parts = PurePosixPath(path).parts
    if any(fnmatch(path, p) or any(fnmatch(part, p) for part in parts) for p in patterns):
        return "excluded"
    if TEST_DIRS & set(parts[:-1]):
        return "tests"
    return "other"


def rule_id(check_id):
    """Semgrep préfixe l'id d'une règle locale par le chemin de son fichier (opt.rules.<id>)."""
    prefix = ".".join(RULES.parts[1:]) + "."
    return check_id[len(prefix):] if check_id.startswith(prefix) else check_id


def pack_index(packs):
    """id de règle -> packs utilisés qui la contiennent (une règle peut être dans plusieurs packs)."""
    index = {}
    for p in packs:
        for r in read_json(RULES / f"{p}.json", {}).get("rules", []):
            index.setdefault(r["id"], []).append(p)
    return index


def semgrep_packs(inv):
    packs = ["security-audit"]
    for lang in inv["langs"]:
        packs += PACKS.get(lang, [])
    if any(PurePosixPath(m).name == "package.json" for m in inv["manifests"]):
        packs.append("nodejs")
    if any(f.startswith(".github/workflows/") for f in inv["files"]):
        packs.append("github-actions")
    return list(dict.fromkeys(packs))


def code(inv):
    ex = read_json(CFG / "semgrep-exclusions.json", {"rules": [], "paths": []})
    report = OUT / "semgrep.json"
    report.unlink(missing_ok=True)
    packs = semgrep_packs(inv)
    jobs = str(max(1, min(4, os.cpu_count() or 2)))
    args = ["semgrep", "scan", "--metrics=off", "--quiet", "--json", "--output", str(report), "--jobs", jobs,
            "--timeout", "20", "--max-target-bytes", "1000000", "--disable-version-check"]
    for p in packs:
        args += ["--config", str(RULES / f"{p}.json")]
    for p in ex.get("paths", []):
        args += ["--exclude", p["pattern"]]
    for rule in ex.get("rules", []):
        args += ["--exclude-rule", rule["id"]]
    args.append(".")
    r = run(args, cwd=SRC)
    if not report.exists():
        raise RuntimeError(f"semgrep : code {r.returncode} {(r.stderr or r.stdout)[-400:]}")
    data = read_json(report, {"results": [], "errors": []})
    rule_packs = pack_index(packs)
    c = empty()
    items = []
    for f in data.get("results", []):
        extra = f.get("extra", {})
        s = str(extra.get("severity", "")).upper()
        impact = str((extra.get("metadata") or {}).get("impact", "")).upper()
        level = ("critical" if impact == "CRITICAL" or s == "CRITICAL" else "high" if s in ("ERROR", "HIGH")
                 else "medium" if s in ("WARNING", "MEDIUM") else "low")
        c[level] += 1
        rid = rule_id(f["check_id"])
        origin = ", ".join(rule_packs.get(rid, [])) or "registre"
        items.append({"sev": level, "where": f"{f['path']}:{f['start']['line']}", "rule": rid,
                      "msg": str(extra.get("message", "")).split("\n")[0][:240], "zone": zone_of(f["path"]),
                      "tools": [{"name": f"Semgrep {VERSIONS['semgrep']}", "detail": f"pack {origin}"}]})
    # Un fichier en erreur d'analyse figure quand même dans paths.scanned : il ne doit pas compter comme couvert.
    unparsed = sorted({str(e["path"]) for e in data.get("errors", []) if e.get("path")})
    scanned = [str(p) for p in (data.get("paths") or {}).get("scanned", []) if str(p) not in unparsed]
    fetched = (RULES / "FETCHED").read_text().strip() if (RULES / "FETCHED").exists() else "?"
    unparsed_detail = [{"path": str(e["path"]), "msg": str(e.get("message", "")).split("\n")[0][:160]}
                       for e in data.get("errors", []) if e.get("path")]
    return {"counts": c, "items": items, "packs": packs, "scanned": scanned, "errors": len(data.get("errors", [])),
            "unparsed": unparsed, "unparsed_detail": unparsed_detail,
            "rules_date": fetched, "exclusions": len(ex.get("paths", [])) + len(ex.get("rules", [])),
            "exclude_patterns": [p["pattern"] for p in ex.get("paths", [])],
            "note": f"{len(scanned)} fichiers analysés, {len(packs)} packs, {sum(c.values())} constat(s)"
                    + (f", {len(unparsed)} en erreur d'analyse" if unparsed else "")}


def skill(inv):
    """Skill d'audit Cloudflare : validation d'une sortie d'audit montée sur /audit. L'intégrité du skill (ses tests)
    est vérifiée au build de l'image, figée ensuite. L'audit lui-même n'est pas produit ici : il demande un agent à
    outils et un modèle."""
    sd = Path(os.environ.get("SKILL_DIR", "/opt/security-audit-skill/skills/security-audit"))
    if not (sd / "validate-findings.cjs").exists():
        raise RuntimeError(f"skill absent de l'image : {sd}")
    checks = {"findings.json": "validate-findings.cjs", "coverage-ledger.json": "validate-coverage-ledger.cjs"}
    audit = Path(os.environ.get("AUDIT_DIR", "/audit"))
    counts = empty()
    validated = {}
    items = []
    for name, validator in checks.items():
        target = audit / name
        if not target.exists():
            validated[name] = "absent"
            continue
        r = run(["node", str(sd / validator), str(target)])
        if r.returncode != 0:
            counts["critical"] += 1  # un fichier d'audit invalide fait échouer le run
            validated[name] = "invalide"
            items.append({"sev": "critical", "where": name, "rule": validator,
                          "msg": (r.stdout + r.stderr)[-300:].strip(), "zone": "(audit)",
                          "tools": [{"name": "Validateurs Cloudflare", "detail": f"{validator} · skill {VERSIONS['skill']}"}]})
        else:
            validated[name] = "valide"
    # Consommation de l'audit par agent, affichée seulement (pas de plafond) : run-metadata.json du run monté.
    meta = read_json(audit / "run-metadata.json", {})
    usage = meta.get("token_usage_subagents") or {}
    tokens = None
    if usage:
        phases = [{"phase": k, "agents": v.get("agents"), "tokens": v.get("tokens")}
                  for k, v in usage.items() if isinstance(v, dict) and "tokens" in v]
        tokens = {"total": usage.get("total") or sum(p["tokens"] or 0 for p in phases), "phases": phases,
                  "note": usage.get("note", ""), "run_id": meta.get("run_id", ""),
                  "model": (meta.get("models") or {}).get("all_subagents", "")}
    present = [k for k, v in validated.items() if v != "absent"]
    note = "intégrité OK (build), " + (", ".join(f"{k} {v}" for k, v in validated.items()) if present else "pas d'audit monté")
    if tokens:
        note += f", audit {tokens['total'] / 1e6:.2f} M tokens"
    return {"counts": counts, "items": items, "validated": validated, "tokens": tokens, "note": note}


STEPS = {"secrets": secrets, "deps": deps, "code": code, "skill": skill}


def main(argv):
    strict = "--strict" in argv
    only = next((a[len("--only="):] for a in argv if a.startswith("--only=")), ",".join(STEPS)).split(",")
    unknown = [s for s in only if s not in STEPS]
    if unknown:
        print(f"Étape inconnue : {', '.join(unknown)}. Choix : {', '.join(STEPS)}", file=sys.stderr)
        return 2
    if not SRC.is_dir() or not any(SRC.iterdir()):
        print(f"Dépôt introuvable ou vide sur {SRC}. Monter le dépôt : -v <dépôt>:/src:ro", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)

    names = ["inventory", *STEPS]
    board = Board(names)
    print(f"\nSecurity Kit {VERSIONS['kit']} · {os.environ.get('REPO_NAME', SRC)} · budget {fmt_t(BUDGET)}\n", flush=True)
    board.start()

    board.set("inventory", "run")
    try:
        inv = inventory()
        board.set("inventory", "ok", inv["note"])
    except Exception as err:
        board.set("inventory", "fail", str(err)[:120])
        board.finish()
        print(f"Inventaire impossible : {err}", file=sys.stderr)
        return 1

    summary = {}

    def step(name):
        if name not in only:
            board.set(name, "skip", "non demandé")
            return
        board.set(name, "run")
        try:
            res = STEPS[name](inv)
            summary[name] = res
            c = res["counts"]
            board.set(name, "warn" if (c["critical"] or c["high"]) else "ok", res["note"])
        except Exception as err:  # une erreur d'outil compte comme un échec
            summary[name] = {"error": str(err)}
            board.set(name, "fail", str(err).splitlines()[0][:120] if str(err) else "erreur")

    with ThreadPoolExecutor(max_workers=len(STEPS)) as pool:
        list(pool.map(step, STEPS))
    board.finish()

    critical = high = 0
    for s in summary.values():
        if "error" in s:
            critical += 1
            continue
        critical += s["counts"]["critical"]
        high += s["counts"]["high"]
    fail = critical > 0 or (strict and high > 0)
    duration = time.monotonic() - T0
    for name in names:
        summary.setdefault(name, {})["seconds"] = round(board.elapsed(name), 1)

    data = {"repo": os.environ.get("REPO_NAME", SRC.name), "started": started.strftime("%Y-%m-%d %H:%M"),
            "duration": round(duration, 1), "budget": BUDGET, "strict": strict, "fail": fail,
            "critical": critical, "high": high, "git": inv["git"], "steps": summary, "only": only, "versions": VERSIONS,
            "inventory": {"files": len(inv["files"]), "langs": dict(inv["langs"]), "manifests": inv["manifests"],
                          "zones": {k: {"files": v["files"], "analysable": v["analysable"], "langs": dict(v["langs"])}
                                    for k, v in inv["zones"].items()}}}
    code_langs = [lang for lang in inv["langs"] if lang in ANALYSABLE and lang not in ("YAML", "HTML", "SQL")]
    data["inventory"]["langs_with_pack"] = [lang for lang in code_langs if lang in PACKS]
    data["inventory"]["langs_without_pack"] = [lang for lang in code_langs if lang not in PACKS]
    # Couverture du code par zone : fichiers analysables vus par Semgrep, et cause de chaque fichier non vu.
    scanned = set(summary.get("code", {}).get("scanned") or [])
    patterns = summary.get("code", {}).get("exclude_patterns") or []
    unparsed = set(summary.get("code", {}).get("unparsed") or [])
    analysable_files = [f for f in inv["files"] if lang_of(f) in ANALYSABLE]
    cov = {z: Counter() for z in inv["zones"]}
    for f in analysable_files:
        cov[zone_of(f)][uncovered_reason(f, scanned, patterns, unparsed)] += 1
    keys = ("scanned", "unparsed", "excluded", "tests", "other")
    for z, v in data["inventory"]["zones"].items():
        v.update({k: cov[z][k] for k in keys})
    total = sum(cov.values(), Counter())
    data["inventory"].update({"analysable": len(analysable_files), "analysable_scanned": total["scanned"],
                              **{k: total[k] for k in keys if k != "scanned"}})

    resume = dict(data)
    resume["steps"] = {k: {kk: vv for kk, vv in v.items() if kk != "scanned"} for k, v in summary.items()}
    (OUT / "resume.json").write_text(json.dumps(resume, indent=2, ensure_ascii=False), encoding="utf-8")

    sys.path.insert(0, str(Path(__file__).parent))
    import report
    (OUT / "report.html").write_text(report.render(data), encoding="utf-8")

    print(f"\nCritique {critical} · haut {high} · durée {fmt_t(duration)}")
    print(f"Rapport : {os.environ.get('HOST_OUT', OUT)}/report.html")
    print(f"ECHEC : constat critique{' ou haut' if strict else ''} ou erreur d'outil" if fail else "OK : aucun constat critique")
    return 1 if fail else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stdout.write("\x1b[?25h\nInterrompu.\n")
        sys.exit(130)
