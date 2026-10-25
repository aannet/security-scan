# Security Kit : image de scan statique pour n'importe quel dépôt. Seule dépendance hôte : Docker.
# Outils épinglés : gitleaks, OSV-Scanner, Semgrep (+ règles Semgrep figées au build), skill d'audit Cloudflare.
# Multi-architecture : amd64 (x86_64) et arm64 (Apple Silicon, Graviton, Raspberry Pi 64 bits). L'architecture est
# celle de l'image de base, donc celle de l'hôte par défaut ; forcer avec docker build --platform linux/arm64.
# Changer une version = changer la version ET les deux sommes SHA-256 (amd64, arm64). scan.py lit les versions de l'ENV.
# Le code à scanner n'est jamais copié dans l'image : il est monté en lecture seule à /src (voir scan.sh).
FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG OSV_VERSION=2.7.0
ARG OSV_SHA256_AMD64=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG OSV_SHA256_ARM64=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7
ARG SEMGREP_VERSION=1.181.0
# Packs Semgrep téléchargés au build : règles figées dans l'image, aucun accès au registre pendant le scan.
# scan.py choisit ceux qui correspondent aux langages détectés.
ARG SEMGREP_PACKS="security-audit javascript typescript nodejs python golang java kotlin ruby php csharp rust scala dockerfile terraform c github-actions kubernetes"
# Skill d'audit Cloudflare (MIT), épinglé à une révision précise. Les validateurs qu'il contient sont en Node sans dépendance.
ARG SKILL_REPO=https://github.com/cloudflare/security-audit-skill.git
ARG SKILL_REF=c1c8a8c1471069fb0e188eeaff69b8e8db6564a8

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git nodejs \
 && rm -rf /var/lib/apt/lists/*

# Skill : clone à la révision épinglée, vérification de la révision, tests d'intégrité (une fois pour toutes : l'image
# est figée), puis suppression de l'historique git.
RUN git clone "${SKILL_REPO}" /opt/security-audit-skill \
 && git -C /opt/security-audit-skill checkout --quiet "${SKILL_REF}" \
 && test "$(git -C /opt/security-audit-skill rev-parse HEAD)" = "${SKILL_REF}" \
 && cd /opt/security-audit-skill/skills/security-audit \
 && node --test validate-findings.test.cjs validate-coverage-ledger.test.cjs \
 && rm -rf /opt/security-audit-skill/.git \
 && chmod -R a+rX /opt/security-audit-skill

# gitleaks (archive .tar.gz) et OSV-Scanner (binaire brut). Architecture lue dans l'image (dpkg), indépendante du
# builder (BuildKit ou non).
RUN arch="$(dpkg --print-architecture)" \
 && case "$arch" in \
      amd64) asset=x64;   gsum="${GITLEAKS_SHA256_AMD64}"; osum="${OSV_SHA256_AMD64}" ;; \
      arm64) asset=arm64; gsum="${GITLEAKS_SHA256_ARM64}"; osum="${OSV_SHA256_ARM64}" ;; \
      *) echo "Architecture non supportée : $arch (amd64, arm64)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${asset}.tar.gz" -o /tmp/gitleaks.tgz \
 && echo "${gsum}  /tmp/gitleaks.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm /tmp/gitleaks.tgz \
 && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${arch}" -o /usr/local/bin/osv-scanner \
 && echo "${osum}  /usr/local/bin/osv-scanner" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/osv-scanner

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Règles Semgrep : une copie par pack, convertie en JSON (Semgrep charge le JSON ~10 s plus vite que le même YAML ;
# constats identiques), date de récupération notée pour le rapport.
# Validation : un scan sur un dossier vide charge toutes les règles (schéma et syntaxe des motifs, hors réseau) ;
# une règle que cette version de Semgrep refuse fait échouer le build plutôt que le premier scan.
# semgrep --validate ne suffit pas : il laisse passer un motif invalide.
RUN mkdir -p /opt/rules /tmp/vide \
 && for p in ${SEMGREP_PACKS}; do curl -fsSL "https://semgrep.dev/c/p/${p}" -o "/tmp/${p}.yml" || exit 1; done \
 && python3 -c 'import json, sys; from ruamel.yaml import YAML; y = YAML(typ="safe"); [json.dump(y.load(open(f"/tmp/{p}.yml")), open(f"/opt/rules/{p}.json", "w")) for p in sys.argv[1:]]' ${SEMGREP_PACKS} \
 && rm /tmp/*.yml \
 && semgrep scan --metrics=off --disable-version-check --quiet $(for p in ${SEMGREP_PACKS}; do printf -- '--config /opt/rules/%s.json ' "$p"; done) /tmp/vide >/dev/null \
 && rm -rf /tmp/vide /root/.semgrep \
 && date -u +%Y-%m-%d > /opt/rules/FETCHED \
 && chmod -R a+rX /opt/rules

COPY scan.py report.py /opt/scan/

# Non-root. Le dépôt est monté en lecture seule ; seul /out est inscriptible (et /tmp en tmpfs).
RUN useradd --uid 10001 --create-home scanner \
 && mkdir -p /out && chown scanner /out
USER scanner
# HOME en tmpfs : Semgrep écrit sa configuration dans ~/.semgrep, et le système de fichiers est en lecture seule.
# safe.directory : le dépôt monté appartient à l'utilisateur hôte, git refuserait sinon de le lire.
# Versions : source unique, reprise par scan.py pour le rapport.
ENV HOME=/tmp SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONIOENCODING=utf-8 \
    SKILL_DIR=/opt/security-audit-skill/skills/security-audit RULES_DIR=/opt/rules \
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=* \
    GITLEAKS_VERSION=${GITLEAKS_VERSION} OSV_VERSION=${OSV_VERSION} SEMGREP_VERSION=${SEMGREP_VERSION} \
    SKILL_REF=${SKILL_REF}

ENTRYPOINT ["python3", "-I", "/opt/scan/scan.py"]
