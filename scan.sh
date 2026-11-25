#!/bin/sh
# SECK : scan d'un dépôt quelconque (statique, et dynamique ZAP en option). Seule dépendance : Docker.
#
#   ./scan.sh <chemin-du-dépôt> [--strict] [--only=secrets,deps,code,skill] [--audit=<dossier>] [--rebuild]
#   ./scan.sh <chemin-du-dépôt> --zap=<url> [--zap-active] [--zap-ajax] [--zap-openapi=<fichier|url>]
#                               [--zap-network=<réseau Docker>] [--zap-allow-remote=<hôte>]
#   ./scan.sh --review=<dossier d'un rapport>
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

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 1 ] || usage
case "$1" in -h|--help) usage ;; --version) echo "SECK $VERSION"; exit 0 ;; esac
# Relecture d'un rapport existant : ni dépôt ni réseau, seul le dossier du rapport est monté (voir scanner/review.py).
case "$1" in
  --review=?*)
    [ $# -eq 1 ] || { echo "--review s'emploie seul." >&2; exit 2; }
    DIR=${1#--review=}
    [ -f "$DIR/resume.json" ] || { echo "Rapport introuvable (pas de resume.json) : $DIR" >&2; exit 2; }
    OUT=$(CDPATH= cd -- "$DIR" && pwd)
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      echo "Construction de l'image $IMAGE (une seule fois)..."
      docker build -q --build-arg KIT_VERSION="$VERSION" -t "$IMAGE" "$KIT/scanner" >/dev/null
    fi
    exec docker run --rm --init --network none \
      --user "$(id -u):$(id -g)" \
      --read-only --tmpfs /tmp:size=64m \
      --cap-drop ALL --security-opt no-new-privileges \
      --memory 1g --pids-limit 128 \
      -e HOST_OUT="$OUT" -v "$OUT":/out \
      --entrypoint python3 "$IMAGE" -I /opt/scan/review.py ;;
esac
[ -d "$1" ] || { echo "Dépôt introuvable : $1" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$1" && pwd)
shift

ARGS=""
AUDIT=""
REBUILD=0
ZAP_URL=""
ZAP_ACTIVE=""
ZAP_AJAX=""
ZAP_OPENAPI=""
ZAP_NETWORK=""
ZAP_REMOTE=""
for a in "$@"; do
  case "$a" in
    --audit=*) AUDIT=$(CDPATH= cd -- "${a#--audit=}" && pwd) ;;
    --rebuild) REBUILD=1 ;;
    --strict|--only=*) ARGS="$ARGS $a" ;;
    --zap=?*) ZAP_URL=${a#--zap=} ;;
    --zap-active) ZAP_ACTIVE=1 ;;
    --zap-ajax) ZAP_AJAX=1 ;;
    --zap-openapi=?*) ZAP_OPENAPI=${a#--zap-openapi=} ;;
    --zap-network=?*) ZAP_NETWORK=${a#--zap-network=} ;;
    --zap-allow-remote=?*) ZAP_REMOTE=${a#--zap-allow-remote=} ;;
    *) echo "Option inconnue : $a" >&2; usage ;;
  esac
done

if [ -z "$ZAP_URL" ] && [ -n "$ZAP_ACTIVE$ZAP_AJAX$ZAP_OPENAPI$ZAP_NETWORK$ZAP_REMOTE" ]; then
  echo "Les options --zap-* exigent --zap=<url>." >&2
  exit 2
fi
case "$ZAP_OPENAPI" in
  ""|http://*|https://*) ;;
  *) [ -f "$ZAP_OPENAPI" ] || { echo "Contrat OpenAPI introuvable : $ZAP_OPENAPI" >&2; exit 2; }
     ZAP_OPENAPI=$(CDPATH= cd -- "$(dirname -- "$ZAP_OPENAPI")" && pwd)/$(basename -- "$ZAP_OPENAPI") ;;
esac
ZAP_SUBNETS=""
case "$ZAP_NETWORK" in
  "") ;;
  host|none|container:*) echo "--zap-network attend un réseau Docker nommé, pas '$ZAP_NETWORK'." >&2; exit 2 ;;
  *) ZAP_SUBNETS=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$ZAP_NETWORK" 2>/dev/null) \
       || { echo "Réseau Docker introuvable : $ZAP_NETWORK" >&2; exit 2; } ;;
esac

# --rebuild repart de zéro : sans --pull ni --no-cache, Docker réutiliserait l'image de base et les règles Semgrep.
if [ "$REBUILD" = 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Construction de l'image $IMAGE (une seule fois)..."
  FRESH=""
  [ "$REBUILD" = 1 ] && FRESH="--pull --no-cache"
  # shellcheck disable=SC2086
  docker build -q $FRESH --build-arg KIT_VERSION="$VERSION" -t "$IMAGE" "$KIT/scanner" >/dev/null
fi

NAME=$(basename "$REPO")
OUT="$KIT/reports/$(date +%Y%m%d-%H%M%S)-$NAME"
mkdir -p "$OUT"

# Dynamique : le dossier de travail (plan et sorties de ZAP) et le conteneur ZAP ne survivent pas au scan.
WORK="$OUT/.zap"
ZAP_NAME="security-kit-zap-$$"
ZAP_PID=""
cleanup() {
  if [ -n "$ZAP_PID" ]; then
    docker rm -f "$ZAP_NAME" >/dev/null 2>&1 || true
    wait "$ZAP_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
  [ -f "$OUT/report.html" ] || rmdir "$OUT" 2>/dev/null || true  # pas de rapport : pas de dossier vide
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [ -n "$ZAP_URL" ]; then
  mkdir -p "$WORK"
  # Préparation dans l'image du kit, sur le même réseau que ZAP : contrôle de la cible, contrat, plan.
  (
    set -- --url="$ZAP_URL"
    [ -n "$ZAP_ACTIVE" ] && set -- "$@" --active
    [ -n "$ZAP_AJAX" ] && set -- "$@" --ajax
    [ -n "$ZAP_REMOTE" ] && set -- "$@" --allow-remote="$ZAP_REMOTE"
    [ -n "$ZAP_NETWORK" ] && set -- "$@" --network="$ZAP_NETWORK"
    case "$ZAP_OPENAPI" in
      "") set -- "$IMAGE" -I /opt/scan/zap.py "$@" ;;
      http://*|https://*) set -- "$IMAGE" -I /opt/scan/zap.py "$@" --openapi="$ZAP_OPENAPI" ;;
      *) set -- -v "$ZAP_OPENAPI":/zap-spec:ro "$IMAGE" -I /opt/scan/zap.py "$@" --openapi-file ;;
    esac
    [ -n "$ZAP_NETWORK" ] && set -- --network "$ZAP_NETWORK" "$@"
    exec docker run --rm --init \
      --user "$(id -u):$(id -g)" \
      --read-only --tmpfs /tmp:size=64m \
      --cap-drop ALL --security-opt no-new-privileges \
      --memory 512m --pids-limit 128 \
      --add-host host.docker.internal:host-gateway \
      -e SCAN_BUDGET="$BUDGET" -e ZAP_SUBNETS="$ZAP_SUBNETS" \
      -v "$WORK":/zap-work --entrypoint python3 "$@"
  ) || exit 2
  # Image et digest : source unique dans le Dockerfile. Téléchargée au premier scan dynamique, hors budget.
  ZAP_IMAGE=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" | sed -n 's/^ZAP_IMAGE=//p')
  if ! docker image inspect "$ZAP_IMAGE" >/dev/null 2>&1; then
    echo "Téléchargement de l'image ZAP (une seule fois, plus d'1 Go)..."
    docker pull -q "$ZAP_IMAGE" >/dev/null
  fi
fi

TTY=""
[ -t 1 ] && TTY="-t"
AUDIT_MOUNT=""
[ -n "$AUDIT" ] && AUDIT_MOUNT="-v $AUDIT:/audit:ro"

# ZAP en parallèle du scan statique, aussi durci que lui. /home/zap en tmpfs : ZAP et Firefox y écrivent leurs profils ;
# exec est requis, ZAP y extrait le pilote de Firefox (sans lui, l'AJAX spider ne visite rien, sans erreur).
# -silent : aucune requête de ZAP vers ses propres services (mises à jour, télémétrie).
if [ -n "$ZAP_URL" ]; then
  (
    set -- "$ZAP_IMAGE" zap.sh -Xmx1536m -cmd -silent -dir /home/zap/.ZAP -autorun /zap-work/plan.json
    [ -n "$ZAP_NETWORK" ] && set -- --network "$ZAP_NETWORK" "$@"
    code=0
    docker run --rm --init --name "$ZAP_NAME" \
      --user "$(id -u):$(id -g)" \
      --read-only --tmpfs /tmp:size=512m --tmpfs /home/zap:size=1g,mode=1777,exec --shm-size 512m \
      --cap-drop ALL --security-opt no-new-privileges \
      --memory 3g --pids-limit 2048 \
      --add-host host.docker.internal:host-gateway \
      -e HOME=/home/zap -e JAVA_TOOL_OPTIONS=-Duser.home=/home/zap \
      -v "$WORK":/zap-work "$@" >"$WORK/zap.log" 2>&1 || code=$?
    echo "$code" >"$WORK/exit.tmp" && mv "$WORK/exit.tmp" "$WORK/exit"
  ) &
  ZAP_PID=$!
fi

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
fi
exit $CODE
