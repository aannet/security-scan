# Scanner

Scan statique de n'importe quel dépôt, et dynamique ZAP en option. Seule dépendance hôte : Docker. Exigences dans [../INTENT.md](../INTENT.md).

## Lancer

```bash
./scan.sh <chemin-du-dépôt>                    # depuis la racine du kit
./scan.sh <dépôt> --strict                     # échoue aussi sur un constat haut
./scan.sh <dépôt> --only=secrets,code          # sous-ensemble d'étapes
./scan.sh <dépôt> --audit=audits/<repo>/run-1  # valide en plus une sortie d'audit par agent
./scan.sh <dépôt> --rebuild                    # reconstruit l'image de zéro (après modif de scan.py, report.py, zap.py, review.py, Dockerfile)
./scan.sh --version                            # affiche la version du kit
./scan.sh --review=reports/<dossier>           # relecture des faux positifs (review.py, voir ../README.md)
SCAN_BUDGET=300 ./scan.sh <dépôt>              # budget de temps en secondes (défaut 570)
./scan.sh <dépôt> --zap=http://localhost:3000  # ajoute le dynamique (options --zap-* : voir ../README.md)
```

L'image `security-kit:<version>` (version lue dans `VERSION`) est construite au premier lancement (environ 1 minute). Rapport :
`reports/<horodatage>-<dépôt>/report.html` (à la racine du kit, hors du contexte de build), avec les JSON bruts (`gitleaks.json`, `osv.json`, `semgrep.json`, `resume.json`).

## Étapes (en parallèle après l'inventaire)

| Étape | Outil | Portée | Critique si |
|-------|-------|--------|-------------|
| Inventaire | `git ls-files` (sinon parcours) | fichiers, zones, langages, manifestes | — |
| `secrets` | gitleaks 8.30.1 | historique git complet, modifications indexées et non indexées, fichiers non suivis (≤ 10 Mo) ; dépôt sans commit : répertoire de travail ; sans git : répertoire | tout secret non justifié |
| `deps` | OSV-Scanner 2.7.1 | tous les lockfiles, récursivement | CVSS ≥ 9 |
| `code` | Semgrep 1.187.0 | packs choisis selon les langages détectés, règles figées dans l'image | impact CRITICAL |
| `skill` | validateurs Cloudflare | validation d'un audit monté sur `/audit` (intégrité du skill testée au build de l'image) | fichier invalide |
| `zap` | OWASP ZAP 2.17.0 | avec `--zap` seulement, quel que soit `--only` : application déjà lancée | — (High = haut) |

Une erreur d'outil ou un dépassement du budget fait échouer le scan (code 1).

## Progression

En console uniquement. En terminal : tableau redessiné sur place, étapes qui se ferment, barre et temps contre budget.
Sans terminal (CI, redirection) : une ligne par transition et un battement toutes les 20 s. Aucun fichier de suivi :
le conteneur (`--rm`) et son `/tmp` (tmpfs) disparaissent à la fin.

## Rapport

Un fichier dont Semgrep ne comprend qu'une partie de la syntaxe (`PartialParsing`) est compté en **analyse
partielle** : ni couvert, ni en échec, avec les lignes en cause dans les limites. Toute autre erreur sur un fichier le
compte en erreur d'analyse.

Dashboard HTML autonome : KPIs, couverture par dimension (secrets, dépendances, code, audit ; API non couverte sans
`--zap`, partielle avec ; charge et base de données non couvertes), zones avec part de code analysé et cause du non-analysé (tests, exclusions du dépôt, autres), liste
des limites, déroulé, constats filtrables avec l'outil qui les a détectés.

Avec `--audit=<run>`, le rapport affiche aussi les tokens consommés par l'audit par agent (lus dans `run-metadata.json`,
champ `token_usage_subagents`), par phase. Affichage seulement : le scan lui-même ne consomme aucun token, son seul
garde-fou est le budget de temps.

Il ajoute une section **Audit par agent · analyse** : verdicts du skill (confirmés, à valider, rejetés), état du
ledger, puis une ligne par piste. Les constats confirmés comptent dans les KPIs et le verdict avec leur sévérité.
Le skill ne note pas les pistes à valider : un `triage.json` optionnel, écrit par l'agent en fin d'audit dans le
dossier du run, y ajoute une estimation, affichée comme telle :

```json
{
  "context": "Exposition de la cible, en une phrase (optionnel).",
  "items": [{
    "fingerprint": "<empreinte présente dans findings.json>",
    "severity_if_confirmed": "critical | high | medium | low",
    "attacker": "Qui peut l'exploiter",
    "confidence": "high | medium | low",
    "fix_effort": "1 ligne de config",
    "action": "now | before_release | later",
    "rationale": "Pourquoi, et le correctif"
  }]
}
```

L'ordre des items donne l'ordre d'affichage. Un `triage.json` non conforme (empreinte inconnue, valeur hors liste)
fait échouer le scan, comme un `findings.json` invalide.

## Déroulé du dynamique

1. `scan.sh` lance `zap.py` (image du kit, sur le réseau de la cible) : contrôle de l'URL et de sa localité, test de
   joignabilité, réécriture du contrat OpenAPI, plan Automation Framework dans `<rapport>/.zap/`. Un refus arrête tout
   avant le scan (code 2).
2. L'image ZAP est téléchargée si absente (hors budget), puis lancée en arrière-plan avec ce plan.
3. L'étape `zap` de `scan.py` suit `.zap/zap.log`, attend `.zap/exit`, filtre les résultats sur l'origine visée.
4. `.zap/` et le conteneur ZAP sont supprimés en fin de scan, y compris sur interruption.

Détails qui comptent :

- le tmpfs `/home/zap` doit être `exec` : ZAP y extrait le pilote de Firefox. En `noexec`, l'AJAX spider termine sans
  erreur et sans rien visiter (le rapport signale un AJAX spider sans résultat) ;
- une URL du poste est jointe par `host.docker.internal`, avec l'en-tête `Host` d'origine restitué ; le rapport affiche
  l'URL demandée ;
- changer de version ZAP : `ZAP_VERSION` et `ZAP_DIGEST` (index multi-architecture) dans le `Dockerfile`. Les add-ons et
  les règles sont figés avec l'image (`-silent` : pas de mise à jour au lancement).

## Config du dépôt (optionnelle)

Lue dans `tests/security/` du dépôt scanné : `gitleaks.toml`, `osv-scanner.toml`, `semgrep-exclusions.json`
(`{"paths":[{"pattern":"..."}],"rules":[{"id":"..."}]}`). Absente : valeurs par défaut des outils.

## Points à savoir

- **Réseau :** requis par OSV-Scanner (base de vulnérabilités) et par ZAP pour joindre la cible. Les règles Semgrep sont dans l'image, converties en JSON au build (Semgrep les charge ~10 s plus vite qu'en YAML) puis validées par un scan à vide, qui fait échouer le build si la version de Semgrep refuse une règle : `--rebuild` les rafraîchit, ainsi que l'image de base (`--pull --no-cache`).
- **Tests :** Semgrep ignore par défaut les dossiers `test/` et `tests/`. Le rapport les compte à part.
- **Isolation :** dépôt en lecture seule, conteneur `--read-only`, non root, `--cap-drop ALL`, `no-new-privileges`, 4 Go, 512 processus.
- **Architectures :** amd64 et arm64 (Apple Silicon, Graviton). L'image prend l'architecture de l'hôte ; pour en
  forcer une : `docker build --platform linux/arm64 -t security-kit:$(cat VERSION) scanner`.
- **Versions :** changer un outil = changer la version et les deux sommes SHA-256 (amd64, arm64) dans le `Dockerfile`.
  `scan.py` et le rapport lisent les versions dans l'environnement de l'image.
- **Durée mesurée :** dépôt applicatif de 776 fichiers et 521 commits 26 s ; un second dépôt 13 s ; le kit lui-même 5 s.
