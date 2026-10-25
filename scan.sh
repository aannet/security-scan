#!/bin/sh
# Security Kit : scan statique d'un dépôt quelconque. Seule dépendance : Docker.
#
#   ./scan.sh <chemin-du-dépôt> [--strict] [--only=secrets,deps,code,skill] [--audit=<dossier>] [--rebuild]
#   ./scan.sh --version
#
# Le dépôt est monté en lecture seule. Rapport : reports/<horodatage>-<dépôt>/report.html
# Aucun fichier de suivi n'est créé : la progression s'affiche en console, le conteneur et son /tmp sont détruits à la fin.
set -eu

KIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Version du kit : source unique dans VERSION. Elle tague l'image, donc un changement de version force le build.
VERSION=$(cat "$KIT/VERSION")
IMAGE=${SCAN_IMAGE:-security-kit:$VERSION}
BUDGET=${SCAN_BUDGET:-570}

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 1 ] || usage
case "$1" in -h|--help) usage ;; --version) echo "Security Kit $VERSION"; exit 0 ;; esac
[ -d "$1" ] || { echo "Dépôt introuvable : $1" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$1" && pwd)
shift

ARGS=""
AUDIT=""
REBUILD=0
for a in "$@"; do
  case "$a" in
    --audit=*) AUDIT=$(CDPATH= cd -- "${a#--audit=}" && pwd) ;;
    --rebuild) REBUILD=1 ;;
    --strict|--only=*) ARGS="$ARGS $a" ;;
    *) echo "Option inconnue : $a" >&2; usage ;;
  esac
done

if [ "$REBUILD" = 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Construction de l'image $IMAGE (une seule fois)..."
  docker build -q --build-arg KIT_VERSION="$VERSION" -t "$IMAGE" "$KIT/scanner" >/dev/null
fi

NAME=$(basename "$REPO")
OUT="$KIT/reports/$(date +%Y%m%d-%H%M%S)-$NAME"
mkdir -p "$OUT"

TTY=""
[ -t 1 ] && TTY="-t"
AUDIT_MOUNT=""
[ -n "$AUDIT" ] && AUDIT_MOUNT="-v $AUDIT:/audit:ro"

# Durcissement : utilisateur hôte non root, FS en lecture seule, aucune capacité, pas d'élévation,
# mémoire et processus plafonnés. Seuls /out (rapports) et /tmp (tmpfs, détruit avec le conteneur) sont inscriptibles.
# Réseau : nécessaire pour la base de vulnérabilités OSV. Les règles Semgrep sont dans l'image.
set +e
# shellcheck disable=SC2086
docker run --rm --init $TTY \
  --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:size=1g \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 4g --pids-limit 512 \
  -e SCAN_BUDGET="$BUDGET" -e REPO_NAME="$NAME" -e HOST_OUT="$OUT" \
  -v "$REPO":/src:ro -v "$OUT":/out $AUDIT_MOUNT \
  "$IMAGE" $ARGS
CODE=$?
set -e

if [ -f "$OUT/report.html" ]; then
  case "$(uname -r)" in
    *[Mm]icrosoft*) command -v wslpath >/dev/null 2>&1 && printf 'Windows : %s\n' "$(wslpath -w "$OUT/report.html")" ;;
  esac
else
  rmdir "$OUT" 2>/dev/null || true  # pas de rapport : on ne laisse pas de dossier vide
fi
exit $CODE
