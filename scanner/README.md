# Scanner

Scan statique de n'importe quel dépôt. Seule dépendance hôte : Docker. Exigences dans [../INTENT.md](../INTENT.md).

## Lancer

```bash
./scan.sh <chemin-du-dépôt>                    # depuis la racine du kit
./scan.sh <dépôt> --strict                     # échoue aussi sur un constat haut
./scan.sh <dépôt> --only=secrets,code          # sous-ensemble d'étapes
./scan.sh <dépôt> --audit=audits/<repo>/run-1  # valide en plus une sortie d'audit par agent
./scan.sh <dépôt> --rebuild                    # reconstruit l'image (après modif de scan.py, report.py, Dockerfile)
SCAN_BUDGET=300 ./scan.sh <dépôt>              # budget de temps en secondes (défaut 570)
```

L'image `security-kit:1` est construite au premier lancement (environ 1 minute). Rapport :
`reports/<horodatage>-<dépôt>/report.html` (à la racine du kit, hors du contexte de build), avec les JSON bruts (`gitleaks.json`, `osv.json`, `semgrep.json`, `resume.json`).

## Étapes (en parallèle après l'inventaire)

| Étape | Outil | Portée | Critique si |
|-------|-------|--------|-------------|
| Inventaire | `git ls-files` (sinon parcours) | fichiers, zones, langages, manifestes | — |
| `secrets` | gitleaks 8.30.1 | historique git complet, modifications indexées et non indexées, fichiers non suivis (≤ 10 Mo) ; dépôt sans commit : répertoire de travail ; sans git : répertoire | tout secret non justifié |
| `deps` | OSV-Scanner 2.7.0 | tous les lockfiles, récursivement | CVSS ≥ 9 |
| `code` | Semgrep 1.181.0 | packs choisis selon les langages détectés, règles figées dans l'image | impact CRITICAL |
| `skill` | validateurs Cloudflare | intégrité du skill, validation d'un audit monté sur `/audit` | test en échec, fichier invalide |

Une erreur d'outil ou un dépassement du budget fait échouer le scan (code 1).

## Progression

En console uniquement. En terminal : tableau redessiné sur place, étapes qui se ferment, barre et temps contre budget.
Sans terminal (CI, redirection) : une ligne par transition et un battement toutes les 20 s. Aucun fichier de suivi :
le conteneur (`--rm`) et son `/tmp` (tmpfs) disparaissent à la fin.

## Rapport

Dashboard HTML autonome : KPIs, couverture par dimension (secrets, dépendances, code, audit, et le dynamique déclaré
non couvert), zones avec part de code analysé et cause du non-analysé (tests, exclusions du dépôt, autres), liste
des limites, déroulé, constats filtrables avec l'outil qui les a détectés.

Avec `--audit=<run>`, le rapport affiche aussi les tokens consommés par l'audit par agent (lus dans `run-metadata.json`,
champ `token_usage_subagents`), par phase. Affichage seulement : le scan lui-même ne consomme aucun token, son seul
garde-fou est le budget de temps.

## Config du dépôt (optionnelle)

Lue dans `tests/security/` du dépôt scanné : `gitleaks.toml`, `osv-scanner.toml`, `semgrep-exclusions.json`
(`{"paths":[{"pattern":"..."}],"rules":[{"id":"..."}]}`). Absente : valeurs par défaut des outils.

## Points à savoir

- **Réseau :** requis par OSV-Scanner (base de vulnérabilités). Les règles Semgrep sont dans l'image : `--rebuild` les rafraîchit.
- **Tests :** Semgrep ignore par défaut les dossiers `test/` et `tests/`. Le rapport les compte à part.
- **Isolation :** dépôt en lecture seule, conteneur `--read-only`, non root, `--cap-drop ALL`, `no-new-privileges`, 4 Go, 512 processus.
- **Architectures :** amd64 et arm64 (Apple Silicon, Graviton). L'image prend l'architecture de l'hôte ; pour en
  forcer une : `docker build --platform linux/arm64 -t security-kit:1 scanner`.
- **Versions :** changer un outil = changer la version et les deux sommes SHA-256 (amd64, arm64) dans le `Dockerfile`.
  `scan.py` et le rapport lisent les versions dans l'environnement de l'image.
- **Durée mesurée :** 002-wnext (776 fichiers, 521 commits) 30 à 50 s ; ark 26 s.
