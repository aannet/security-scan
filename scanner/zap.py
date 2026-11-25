"""Dynamique avec OWASP ZAP. ZAP tourne dans son image officielle, lancée par scan.sh ; ce module prépare son plan et
lit ses résultats, depuis l'image du kit. Avec un contrat OpenAPI, la préparation sonde aussi le refus de l'accès
anonyme : un GET sans identité par lecture déclarée.

Usage (dans le conteneur, avant le lancement de ZAP) :
  zap.py --url=<url> [--active] [--ajax] [--openapi=<url> | --openapi-file] [--allow-remote=<hôte>] [--network=<nom>]

Entrées : /zap-spec (contrat OpenAPI local), variables SCAN_BUDGET et ZAP_SUBNETS (sous-réseaux du réseau désigné).
Sortie dans /zap-work : plan.json (Automation Framework), meta.json (avec la sonde), openapi.json.

Codes de sortie : 0 plan prêt ; 2 cible refusée ou injoignable.
"""
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

WORK = Path(os.environ.get("ZAP_WORK", "/zap-work"))
SPEC = Path(os.environ.get("ZAP_SPEC", "/zap-spec"))
HOST_ALIAS = "host.docker.internal"
PORTS = {"http": 80, "https": 443}
SPEC_MAX = 10 * 1024 * 1024
PHASES = {"openapi": "Import OpenAPI", "spider": "Spider", "spiderAjax": "AJAX spider",
          "passiveScan-wait": "Analyse passive", "activeScan": "Scan actif"}
RISK = {"3": "high", "2": "medium", "1": "low"}
WRITES = ("post", "put", "patch", "delete")
METHODS = ("get", "head", "options", "trace", *WRITES)
# Sonde anonyme : bornée pour tenir dans la marge entre le budget du scan et les 10 minutes.
PROBE_SECONDS = 20
PROBE_TIMEOUT = 3
PROBE_MAX = 500
PROBE_FAILURES = 5
PROBE_VALUE = "security-kit-probe"
PROBE_UUID = "00000000-0000-0000-0000-000000000000"
REFUSAL = (401, 403)


class Refused(Exception):
    pass


# ------------------------------------------------------------------------------------------------------- préparation

def parse_url(url):
    """(schéma, hôte, port, chemin avec requête). Refuse ce qui n'est pas une URL HTTP(S) simple."""
    u = urlsplit(url)
    try:
        port = u.port
    except ValueError:
        raise Refused(f"port invalide : {url}")
    if u.scheme not in PORTS or not u.hostname:
        raise Refused(f"URL attendue en http:// ou https:// : {url}")
    if u.username or u.password:
        raise Refused("identifiants dans l'URL refusés : le scan est non authentifié")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", u.hostname):
        raise Refused(f"nom d'hôte invalide : {u.hostname}")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return u.scheme, u.hostname, port or PORTS[u.scheme], path


def netloc(scheme, host, port):
    h = f"[{host}]" if ":" in host else host
    return h if port == PORTS[scheme] else f"{h}:{port}"


def origin(scheme, host, port):
    return f"{scheme}://{netloc(scheme, host, port)}"


def is_loopback(host):
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def resolve(host):
    try:
        return sorted({a[4][0].split("%")[0] for a in socket.getaddrinfo(host, None)})
    except (OSError, UnicodeError):
        return []


def locate(host, subnets, resolver=resolve):
    """(hôte à joindre depuis le conteneur, locale ?). Locale : le poste, ou un hôte dont toutes les adresses sont
    dans un sous-réseau du réseau Docker désigné. Une adresse privée hors de ce réseau n'est pas locale."""
    if is_loopback(host) or host == HOST_ALIAS:
        return HOST_ALIAS, True
    nets = [ipaddress.ip_network(s, strict=False) for s in subnets]
    ips = resolver(host) if nets else []
    inside = bool(ips) and all(any(ipaddress.ip_address(i) in n for n in nets) for i in ips)
    return host, inside


def authorize(host, subnets, allow_remote, resolver=resolve):
    internal, local = locate(host, subnets, resolver)
    if not local and host != allow_remote:
        raise Refused(f"cible non locale : {host}. Pour la scanner en assumant d'y être autorisé : "
                      f"--zap-allow-remote={host}")
    return internal, local


def fetch(scheme, host, port, path, host_header, local, limit=65536, timeout=10, deadline=None):
    """GET sans suivre les redirections, sans cookie ni jeton. Certificat vérifié, sauf cible locale (certificats de
    développement). Avec une échéance, le corps est lu par morceaux et abandonné à son terme (flux sans fin)."""
    if scheme == "https":
        context = ssl.create_default_context()
        if local:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": host_header, "User-Agent": "security-kit"})
        r = conn.getresponse()
        if deadline is None:
            body = r.read(limit + 1)
        else:
            body = b""
            try:
                while len(body) <= limit and time.monotonic() < deadline:
                    chunk = r.read1(limit + 1 - len(body))
                    if not chunk:
                        break
                    body += chunk
            except (OSError, http.client.HTTPException):
                pass  # le code de réponse est acquis : un corps interrompu ne le remet pas en cause
        return r.status, r.getheader("Location") or "", body
    finally:
        conn.close()


def confine_spec(text, target, active):
    """Contrat réécrit pour ne désigner que l'origine visée : sans quoi ZAP appellerait les serveurs qu'il déclare.
    En passif, les opérations d'écriture sont retirées : l'import appelle chaque opération déclarée.
    Renvoie (contrat OpenAPI 3 ou Swagger 2, nombre d'opérations retirées, opérations déclarées avant retrait)."""
    try:
        spec = json.loads(text)
    except ValueError:
        from ruamel.yaml import YAML  # présent dans l'image (dépendance de Semgrep)
        try:
            spec = YAML(typ="safe", pure=True).load(text)
        except Exception as err:
            raise Refused(f"contrat OpenAPI illisible : {str(err).splitlines()[0]}")
    if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec) or "paths" not in spec:
        raise Refused("contrat OpenAPI attendu (clés openapi ou swagger, et paths)")

    def clean(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                raise Refused(f"contrat OpenAPI : référence externe refusée ({ref[:80]}), fournir un contrat autonome")
            return {k: clean(v) for k, v in node.items()}
        return [clean(v) for v in node] if isinstance(node, list) else node

    spec = clean(spec)
    scheme, rest = target.split("://", 1)
    if "swagger" in spec:
        spec["host"], spec["schemes"] = rest, [scheme]
    else:
        servers = spec.get("servers") or [{}]
        first = str((servers[0] or {}).get("url", ""))
        base = urlsplit(first).path if "{" not in first else ""  # préfixe conservé (/api/v1), variables abandonnées
        spec["servers"] = [{"url": target + ("/" + base.strip("/") if base.strip("/") else "")}]
    declared = operations(spec)
    removed = 0
    for item in (spec.get("paths") or {}).values():  # serveurs propres à un chemin ou à une opération
        if isinstance(item, dict):
            if "$ref" in item and not active:  # chemin défini par référence : ses méthodes ne sont pas filtrables ici
                raise Refused("contrat OpenAPI : chemin défini par $ref non pris en charge en passif")
            item.pop("servers", None)
            for method in [m for m in item if not active and str(m).lower() in WRITES]:
                del item[method]
                removed += 1
            for op in item.values():
                if isinstance(op, dict):
                    op.pop("servers", None)
    return spec, removed, declared


def pointer(spec, node):
    """Suit les références internes (#/...) d'un nœud ; {} si elles ne mènent nulle part."""
    for _ in range(10):
        if not (isinstance(node, dict) and isinstance(node.get("$ref"), str)):
            return node if isinstance(node, dict) else {}
        found = spec
        for part in node["$ref"][2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            found = found.get(part) if isinstance(found, dict) else None
        node = found
    return {}


def dummy(spec, parameter):
    """Valeur factice d'un paramètre de chemin. Ni exemple ni valeur par défaut : ils peuvent désigner un objet réel."""
    schema = pointer(spec, parameter.get("schema") or parameter)
    if schema.get("format") == "uuid":
        return PROBE_UUID
    return "0" if schema.get("type") in ("integer", "number") else PROBE_VALUE


def base_path(spec):
    raw = spec.get("basePath") if "swagger" in spec else urlsplit(str(spec["servers"][0]["url"])).path
    return "/" + str(raw or "").strip("/") if str(raw or "").strip("/") else ""


def operations(spec):
    """Opérations du contrat : chemin déclaré, chemin à appeler (préfixe et valeurs factices) et accès. Protégée : son
    security effectif (le sien, sinon le global) n'est pas vide et n'admet pas l'anonyme ({})."""
    prefix, found = base_path(spec), []
    for path, node in (spec.get("paths") or {}).items():
        item = pointer(spec, node)
        for method, op in item.items():
            if str(method).lower() not in METHODS or not isinstance(op, dict):
                continue
            security = op["security"] if "security" in op else spec.get("security")
            params = {}
            for raw in [*(item.get("parameters") or []), *(op.get("parameters") or [])]:
                p = pointer(spec, raw)
                if p.get("in") == "path":
                    params[p.get("name")] = p
            full = prefix + "/" + str(path).lstrip("/")
            call = re.sub(r"\{([^{}]*)\}", lambda m: dummy(spec, params.get(m[1], {})), full)
            found.append({"method": str(method).upper(), "path": full,
                          "call": quote(call, safe="/:@!$&'()*+,;=-._~%"),
                          "access": "protected" if security and {} not in security else "public"})
    return found


# ------------------------------------------------------------------------------------------------------ sonde anonyme

def probe(ops, get, prefix="", seconds=PROBE_SECONDS, clock=time.monotonic):
    """Un GET sans identité par lecture déclarée : une opération protégée doit répondre 401 ou 403.
    get(chemin, délai, échéance) renvoie (code, redirection, corps). Les écritures ne sont jamais appelées.
    Ne conserve que méthode, chemin, accès, code et verdict."""
    deadline, failures, calls = clock() + seconds, 0, 0

    def call(path):
        nonlocal failures, calls
        left = deadline - clock()
        if left <= 0 or failures >= PROBE_FAILURES:
            return None
        calls += 1
        try:
            status, _, body = get(path, min(PROBE_TIMEOUT, left), deadline)
        except (OSError, ValueError, http.client.HTTPException):
            failures += 1
            return 0, b""
        failures = 0
        return status, body

    control = call(prefix + "/" + PROBE_VALUE + "-inexistant")
    # Publiques d'abord : elles servent de témoins, même si le temps manque ensuite.
    answers, reads = {}, [i for i, o in enumerate(ops) if o["method"] == "GET"]
    for i in sorted(reads, key=lambda i: ops[i]["access"] != "public")[:PROBE_MAX]:
        answer = call(ops[i]["call"])
        if answer is None:
            break
        answers[i] = answer
    witnesses = ([s for i, (s, _) in answers.items() if s and ops[i]["access"] == "public"]
                 or [s for s, _ in answers.values() if s])
    refused_control = bool(control) and control[0] in REFUSAL
    # Tout est refusé, route inexistante comprise : un filtre (hôte, WAF) donnerait le même résultat.
    filtered = refused_control and all(s in REFUSAL for s in witnesses)
    generic = control[1] if control and 200 <= control[0] < 300 else None
    out = []
    for i, o in enumerate(ops):
        status, body = answers.get(i, (None, b""))
        if o["method"] != "GET":
            verdict = "untested"
        elif status is None:
            verdict = "unprobed"
        elif not status:
            verdict = "inconclusive"
        elif o["access"] == "public":
            verdict = "observed"
        elif status in REFUSAL:
            verdict = "inconclusive" if filtered else "refused"
        elif 200 <= status < 300 and body != generic:
            verdict = "open"
        else:
            verdict = "inconclusive"
        out.append({"method": o["method"], "path": o["path"], "call": o["call"], "access": o["access"],
                    "status": status or None, "verdict": verdict})
    return {"operations": out, "control": (control[0] or None) if control else None, "filtered": filtered,
            "requests": calls}


def access_counts(access):
    protected = [o for o in access["operations"] if o["access"] == "protected"]
    return sum(o["verdict"] == "refused" for o in protected), sum(o["method"] == "GET" for o in protected)


def open_item(op, url, version_label):
    """Constat : lecture déclarée protégée qui répond à un appel sans identité. Champs attendus par les fiches."""
    return {"sev": "high", "where": f"GET {url}"[:240], "rule": "KIT-ANON-01", "zone": "(dynamique)",
            "msg": f"Route déclarée protégée accessible sans identité : {op['path']}"[:240],
            "details": "Le contrat OpenAPI exige une authentification pour cette lecture. Un GET envoyé sans cookie ni jeton "
                       f"a reçu {op['status']}. Soit le contrôle d'accès manque, soit le contrat est faux.",
            "fix": "Exiger l'authentification sur cette route (401 ou 403 sans identité), ou corriger le security du contrat "
                   "si la route est volontairement publique.",
            "refs": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            "evidence": f"GET {url} · code {op['status']} · aucun cookie ni jeton envoyé"[:600],
            "tools": [{"name": version_label, "detail": f"GET sans identité · réponse {op['status']}"}]}


def limits(budget, active, ajax):
    """Durées maximales des phases, en minutes, pour tenir dans le budget (marge : démarrage de ZAP et rapport)."""
    minutes = (budget - 90) // 60
    lim = {"spider": 1, "passiveScan-wait": 1}
    if ajax:
        lim["spiderAjax"] = 2 if minutes >= 5 else 1
    if active:
        lim["activeScan"] = max(1, minutes - sum(lim.values()))
    needed = sum(lim.values())
    if minutes < needed:
        raise Refused(f"SCAN_BUDGET trop petit pour ces phases ZAP : {needed * 60 + 90} s au minimum")
    return lim


def build_plan(meta, work="/zap-work"):
    target, lim = meta["internal_origin"], meta["limits"]
    scope = re.escape(target) + r"(?:[/?#].*)?"
    jobs = []
    if meta["host_header"]:  # l'application voit le nom d'hôte demandé, pas host.docker.internal
        jobs.append({"type": "replacer", "parameters": {"deleteAllRules": True}, "rules": [
            {"description": "Host d'origine", "url": scope, "matchType": "req_header", "matchString": "Host",
             "matchRegex": False, "replacementString": meta["host_header"]}]})
    jobs.append({"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}})
    if meta["openapi"]:
        jobs.append({"type": "openapi", "parameters": {"apiFile": f"{work}/openapi.json", "targetUrl": target,
                                                       "context": "cible"}})
    jobs.append({"type": "spider", "parameters": {"context": "cible", "maxDuration": lim["spider"],
                                                  "postForm": meta["active"]}})
    if meta["ajax"]:
        jobs.append({"type": "spiderAjax", "parameters": {"context": "cible", "maxDuration": lim["spiderAjax"],
                                                          "inScopeOnly": True, "browserId": "firefox-headless",
                                                          "numberOfBrowsers": 2}})
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": lim["passiveScan-wait"]}})
    if meta["active"]:
        jobs.append({"type": "activeScan", "parameters": {"context": "cible", "maxRuleDurationInMins": 1,
                                                          "maxScanDurationInMins": lim["activeScan"]}})
        jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": 1}})
    jobs.append({"type": "export", "parameters": {"type": "url", "source": "all", "fileName": f"{work}/urls.txt"}})
    jobs.append({"type": "report", "parameters": {"template": "traditional-json", "reportDir": work,
                                                  "reportFile": "zap.json"}})
    return {"env": {"contexts": [{"name": "cible", "urls": [target + meta["path"]], "includePaths": [scope]}],
                    "parameters": {"failOnError": True, "progressToStdout": True}}, "jobs": jobs}


def prepare(opts, subnets, budget):
    scheme, host, port, path = parse_url(opts["url"])
    allow = opts.get("allow-remote", "").strip("[]").lower()
    if allow and allow != host:
        raise Refused(f"--zap-allow-remote={allow} ne correspond pas à l'hôte de l'URL ({host})")
    internal, local = authorize(host, subnets, allow)
    shown, target = origin(scheme, host, port), origin(scheme, internal, port)
    header = netloc(scheme, host, port)
    try:
        status, location, _ = fetch(scheme, internal, port, path, header, local)
    except (OSError, http.client.HTTPException) as err:
        hint = (" Sous Linux sans Docker Desktop, l'application doit écouter sur 0.0.0.0, pas seulement 127.0.0.1."
                if internal == HOST_ALIAS else "")
        raise Refused(f"cible injoignable : {opts['url']} ({err}).{hint}")
    if 300 <= status < 400 and re.match(r"https?://", location):
        dest = origin(*parse_url(location)[:3])
        if dest not in (shown, target):
            raise Refused(f"la cible redirige vers une autre origine ({dest}) : passer l'URL finale à --zap")
    openapi = opts.get("openapi") or ("fichier local" if "openapi-file" in opts else "")
    active, ajax = "active" in opts, "ajax" in opts
    skipped, access = 0, None
    if openapi:
        if "openapi" in opts:
            s, h, p, spec_path = parse_url(opts["openapi"])
            # Même hôte que la cible : déjà autorisé. Sinon la même règle de localité s'applique.
            spec_host, spec_local = (internal, local) if h == host else authorize(h, subnets, allow)
            try:
                code, _, raw = fetch(s, spec_host, p, spec_path, netloc(s, h, p), spec_local, SPEC_MAX)
            except (OSError, http.client.HTTPException) as err:
                raise Refused(f"contrat OpenAPI injoignable : {opts['openapi']} ({err})")
            if code != 200:
                raise Refused(f"contrat OpenAPI : réponse HTTP {code} sur {opts['openapi']}")
        else:
            raw = SPEC.read_bytes()
        if len(raw) > SPEC_MAX:
            raise Refused("contrat OpenAPI de plus de 10 Mo")
        spec, skipped, declared = confine_spec(raw.decode("utf-8", "replace"), target, active)
        (WORK / "openapi.json").write_text(json.dumps(spec, default=str), encoding="utf-8")
    plan_limits = limits(budget, active, ajax)  # budget refusé avant d'envoyer la moindre requête de sonde
    if openapi:
        access = probe(declared, lambda p, timeout, deadline: fetch(scheme, internal, port, p, header, local,
                                                                     timeout=timeout, deadline=deadline),
                       base_path(spec))
    meta = {"access": access, "url": shown + path, "origin": shown, "internal_origin": target, "path": path,
            "host_header": header if internal != host else "", "active": active, "ajax": ajax, "openapi": openapi,
            "skipped_operations": skipped, "remote": not local, "network": opts.get("network", ""), "limits": plan_limits}
    (WORK / "plan.json").write_text(json.dumps(build_plan(meta, str(WORK)), indent=2), encoding="utf-8")
    (WORK / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


# --------------------------------------------------------------------------------------------------------- résultats

def read_log(work):
    try:
        return (work / "zap.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def current_phase(work):
    started = re.findall(r"^Job (\S+) started", read_log(work), re.M)
    if not started:
        return "démarrage de ZAP"
    return PHASES.get(started[-1], "rapport").lower() if started[-1] != "passiveScan-config" else ""


def parse_phases(log, lim):
    """Durée de chaque phase et nombre d'URL trouvées. Une phase qui atteint sa limite est partielle."""
    phases, found, passive = [], {}, 0
    for job, h, m, s in re.findall(r"^Job (\S+) finished, time taken: (\d+):(\d+):(\d+)", log, re.M):
        if job not in PHASES:
            continue
        seconds = int(h) * 3600 + int(m) * 60 + int(s)
        passive += job == "passiveScan-wait"
        limit = 1 if job == "passiveScan-wait" and passive > 1 else lim.get(job)
        label = PHASES[job] + (" (après attaques)" if job == "passiveScan-wait" and passive > 1 else "")
        phases.append({"job": job, "label": label, "seconds": seconds, "limit": limit,
                       "partial": bool(limit) and seconds >= limit * 60 - 1})
    for job, n in re.findall(r"^Job (spider|spiderAjax|openapi) (?:found|added) (\d+) URLs", log, re.M):
        found[job] = int(n)
    return phases, found


def plain(text):
    """Les descriptions ZAP sont en HTML : texte simple, un paragraphe par ligne."""
    text = re.sub(r"</p>|<br\s*/?>", "\n", str(text or ""))
    return re.sub(r"\n{2,}", "\n", html.unescape(re.sub(r"<[^>]+>", "", text))).strip()


def evidence(instances):
    lines = []
    for i in instances[:10]:
        extra = " · ".join(f"{label} : {str(i[k])[:200]}" for k, label in
                           (("param", "paramètre"), ("attack", "attaque"), ("evidence", "preuve")) if i.get(k))
        lines.append(f"{i.get('method', '')} {i.get('uri', '')}".strip()[:300] + (f" · {extra}" if extra else ""))
    return "\n".join(lines)


def results(work, out, version):
    meta = json.loads((work / "meta.json").read_text(encoding="utf-8"))
    log = read_log(work)
    code = (work / "exit").read_text().strip()
    # Automation Framework : 0 succès, 2 succès avec avertissements.
    if code not in ("0", "2") or not (work / "zap.json").exists():
        failures = log.split("Automation plan failures:", 1)
        tail = failures[1] if len(failures) > 1 else log
        raise RuntimeError(f"ZAP : code {code} {' '.join(tail.split())[-400:]}")
    shown, internal = meta["origin"], meta["internal_origin"]

    def display(text):
        return text.replace(internal, shown) if internal != shown else text

    raw = json.loads(display((work / "zap.json").read_text(encoding="utf-8")))
    # Seule l'origine visée compte : les autres sites vus par ZAP n'ont pas été testés.
    sites = [s for s in raw.get("site") or [] if s.get("@name", "").rstrip("/") == shown]
    raw["site"] = sites
    (out / "zap.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    counts = dict.fromkeys(("critical", "high", "medium", "low", "unknown"), 0)
    items, informational = [], 0
    for alert in (a for s in sites for a in s.get("alerts") or []):
        if str(alert.get("confidence")) == "0":  # faux positif déclaré par la règle
            continue
        level = RISK.get(str(alert.get("riskcode")))
        if not level:
            informational += 1
            continue
        counts[level] += 1
        inst = alert.get("instances") or [{}]
        total = int(alert.get("count") or len(inst))
        first = inst[0]
        where = f"{first.get('method', '')} {first.get('uri', shown)}".strip()
        param = first.get("param")
        items.append({"details": plain(alert.get("desc")), "fix": plain(alert.get("solution")),
                      "refs": plain(alert.get("reference")).split()[:5], "evidence": evidence(inst),
                      "sev": level, "where": where[:240] + (f" (+{total - 1})" if total > 1 else ""),
                      "rule": f"ZAP {alert.get('pluginid', '?')}",
                      "msg": alert.get("name", "") + (f" · paramètre {param}" if param else ""), "zone": "(dynamique)",
                      "tools": [{"name": f"OWASP ZAP {version}",
                                 "detail": ("scan actif" if meta["active"] else "analyse passive")
                                           + f" · {total} occurrence(s)"}]})
    access = meta.get("access")
    if access:
        for op in access["operations"]:
            if op["verdict"] == "open":
                counts["high"] += 1
                items.append(open_item(op, shown + op["call"], "Security Kit · sonde anonyme"))
    try:
        seen = display((work / "urls.txt").read_text(encoding="utf-8", errors="replace")).split()
    except OSError:
        seen = []
    urls = set()
    for u in seen:
        p = urlsplit(u)
        base = f"{p.scheme}://{p.netloc}"
        if base == shown:
            urls.add(base + (p.path or "/"))  # sans la requête : les variantes d'attaque ne sont pas des URL de plus
    phases, found = parse_phases(log, meta["limits"])
    partial = sum(p["partial"] for p in phases)
    note = (f"{'actif' if meta['active'] else 'passif'}, {len(urls)} URL, {sum(counts.values())} alerte(s)"
            + (f", {partial} phase(s) partielle(s)" if partial else "")
            + (", AJAX spider sans résultat" if meta["ajax"] and not found.get("spiderAjax") else "")
            + (", refus anonyme {}/{}".format(*access_counts(access)) if access else ""))
    return {"access": access, "counts": counts, "items": items, "informational": informational, "urls": sorted(urls),
 "phases": phases, "found": found,
            **{k: meta[k] for k in ("url", "active", "ajax", "openapi", "skipped_operations", "remote", "network")}, "note": note}


def main(argv):
    opts = {}
    for a in argv:
        k, _, v = a.removeprefix("--").partition("=")
        opts[k] = v
    try:
        meta = prepare(opts, os.environ.get("ZAP_SUBNETS", "").split(), int(os.environ.get("SCAN_BUDGET", "570")))
    except Refused as err:
        print(f"Dynamique refusé : {err}", file=sys.stderr)
        return 2
    print(f"Cible ZAP : {meta['url']} · {'ACTIF (attaques)' if meta['active'] else 'passif'}"
          f"{' · HÔTE DISTANT' if meta['remote'] else ''}")
    if meta["access"]:
        refused, total = access_counts(meta["access"])
        print(f"Sonde anonyme : {meta['access']['requests']} requête(s) GET, {refused}/{total} lecture(s) protégée(s) "
              "refusent l'appel sans identité")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
