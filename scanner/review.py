#!/usr/bin/env python3
"""Relecture d'un rapport : liste les constats, puis produit un rapport relu sans les faux positifs retenus.

Usage (dans le conteneur, lancé par scan.sh --review) :
  review.py

Entrées, dans /out (le dossier d'un rapport) :
  resume.json   synthèse du scan
  ecarts.json   optionnel : {"items": [{"id": "<identifiant listé>", "reason": "<pourquoi c'est un faux positif>"}]}

Sans ecarts.json : liste les constats et leur identifiant, rien n'est écrit. Avec : report-revu.html et
corrections-revu.md. Un constat écarté sort des comptes et du verdict, et reste listé avec son motif. report.html,
resume.json et les JSON bruts ne sont jamais modifiés.

Codes de sortie : 0 fait ; 2 relecture refusée (rapport absent ou d'une autre version, ecarts.json non conforme).
"""
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # python -I n'ajoute pas le dossier du script
import report

OUT = Path(os.environ.get("OUT", "/out"))
# Les constats d'un audit par agent ont leur propre verdict (findings.json) : ils ne s'écartent pas ici.
STEPS = ("secrets", "deps", "code", "zap")
# Mesure du kit, pas une alerte : si la route est volontairement publique, c'est le contrat qu'on corrige.
MEASURED = ("KIT-ANON-01",)
SHORT = 240


class Refused(Exception):
    pass


def finding_id(step, item):
    key = "\0".join([step, *(str(item.get(k, "")) for k in ("rule", "where", "msg"))])
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:10]


def findings(data):
    """(identifiant, étape, constat), du plus grave au moins grave."""
    found = [(finding_id(step, i), step, i) for step in STEPS for i in data["steps"].get(step, {}).get("items", [])]
    return sorted(found, key=lambda f: (report.SEV.index(f[2]["sev"]), f[1], f[2]["where"]))


def one_line(text):
    """Le contenu d'un constat vient du dépôt ou de l'application : une ligne, sans caractère de contrôle."""
    clean = " ".join("".join(c if c.isprintable() else " " for c in str(text or "")).split())
    return clean if len(clean) <= SHORT else clean[:SHORT] + "…"


def listing(data):
    found = findings(data)
    lines = [f"{len(found)} constat(s) à relire · {data['repo']}"]
    for ident, step, i in found:
        fixed = " · mesuré, non écartable" if i["rule"] in MEASURED else ""
        lines.append(f"\n[{ident}] {report.SEV_FR[i['sev']]} · {report.TOOL_FR[step]} · {one_line(i['rule'])}{fixed}")
        lines.append(f"  où     : {one_line(i['where'])}")
        lines.append(f"  résumé : {one_line(i.get('msg'))}")
        if i.get("evidence"):
            lines.append(f"  preuve : {one_line(i['evidence'])}")
    return "\n".join(lines)


def dismissals(data, raw):
    """{identifiant: motif}, contrôlé : chaque écart vise un constat présent et dit pourquoi."""
    items = raw.get("items") if isinstance(raw, dict) else None
    if not isinstance(items, list) or not items:
        raise Refused("ecarts.json : objet attendu avec une liste items non vide")
    known = {ident: i for ident, _, i in findings(data)}
    out, errors = {}, []
    for n, e in enumerate(items, 1):
        ident = e.get("id") if isinstance(e, dict) else None
        reason = e.get("reason") if isinstance(e, dict) else None
        if not isinstance(ident, str) or ident not in known:
            errors.append(f"item {n} : identifiant inconnu")
        elif ident in out:
            errors.append(f"item {n} : identifiant en double")
        elif known[ident]["rule"] in MEASURED:
            errors.append(f"item {n} : {known[ident]['rule']} est mesuré, corriger le contrat et relancer le scan")
        elif not isinstance(reason, str) or not reason.strip():
            errors.append(f"item {n} : motif (reason) obligatoire")
        else:
            out[ident] = reason.strip()
    if errors:
        raise Refused("ecarts.json : " + " ; ".join(errors))
    return out


def apply(data, reasons):
    """Données du rapport relu : constats écartés retirés des étapes, comptes et verdict recalculés. Les étapes en
    erreur restent comptées. Le résultat d'origine est conservé dans data["review"]."""
    data = json.loads(json.dumps(data))
    original = {k: data[k] for k in ("fail", "critical", "high")}
    gone = Counter()
    dismissed = []
    for step in STEPS:
        s = data["steps"].get(step, {})
        if "items" not in s:
            continue
        kept = []
        for i in s["items"]:
            ident = finding_id(step, i)
            if ident in reasons:
                dismissed.append({"id": ident, "tool": step, "reason": reasons[ident],
                                  **{k: i.get(k, "") for k in ("sev", "rule", "where", "msg")}})
                s["counts"][i["sev"]] -= 1
                gone[i["sev"]] += 1
            else:
                kept.append(i)
        s["items"] = kept
    data["critical"] -= gone["critical"]
    data["high"] -= gone["high"]
    data["fail"] = data["critical"] > 0 or (data["strict"] and data["high"] > 0)
    dismissed.sort(key=lambda d: (report.SEV.index(d["sev"]), d["tool"], d["where"]))
    data["review"] = {"original": original, "dismissed": dismissed}
    return data


def main():
    try:
        try:
            data = json.loads((OUT / "resume.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise Refused("resume.json absent ou illisible : donner le dossier d'un rapport")
        kit, made = os.environ.get("KIT_VERSION", "dev"), data.get("versions", {}).get("kit")
        if made != kit:
            raise Refused(f"rapport produit par la version {made}, kit en version {kit} : relancer le scan")
        path = OUT / "ecarts.json"
        if not path.exists():
            print(listing(data))
            return 0
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise Refused("ecarts.json illisible : JSON attendu")
        reviewed = apply(data, dismissals(data, raw))
    except Refused as err:
        print(f"Relecture refusée : {err}", file=sys.stderr)
        return 2
    (OUT / "report-revu.html").write_text(report.render(reviewed), encoding="utf-8")
    (OUT / "corrections-revu.md").write_text(report.corrections(reviewed), encoding="utf-8")
    before = reviewed["review"]["original"]
    print(f"Écartés : {len(reviewed['review']['dismissed'])} constat(s)")
    print(f"Critique {before['critical']} → {reviewed['critical']} · haut {before['high']} → {reviewed['high']}")
    print(f"Rapport relu : {os.environ.get('HOST_OUT', OUT)}/report-revu.html")
    print("ECHEC après relecture" if reviewed["fail"] else "OK après relecture : aucun constat bloquant",
          f"(scan d'origine : {'en échec' if before['fail'] else 'réussi'}, code de sortie inchangé)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
