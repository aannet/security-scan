# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : [SemVer](https://semver.org/lang/fr/),
source unique dans `VERSION`.

## Non publié

## 1.1.0 - 2026-10-25

### Ajouté

- Numéro de version du kit : fichier `VERSION`, tag de l'image (`security-kit:<version>`, reconstruite
  automatiquement au changement de version), affiché en console, dans `resume.json` et le rapport.
- `./scan.sh --version`.
- Validation des règles Semgrep au build par un scan à vide : une règle refusée fait échouer le build.

### Modifié

- Règles Semgrep converties en JSON au build : environ 10 s de chargement en moins par scan
  (11,3 → 5,0 s sur le kit, 22 → 13 s et 32 → 26 s sur deux dépôts applicatifs). Constats identiques.
- Tests d'intégrité du skill Cloudflare déplacés au build.
- Passes gitleaks en parallèle ; inventaire et fichiers non suivis en un seul appel `git ls-files -t`.

### Supprimé

- Repli vers le registre Semgrep pendant le scan : les règles viennent uniquement de l'image.

## 1.0.0 - 2026-10-25

### Ajouté

- Lanceur `scan.sh` et image durcie : gitleaks, OSV-Scanner, Semgrep et skill d'audit Cloudflare épinglés.
- Image amd64 et arm64, binaires vérifiés par somme SHA-256 par architecture.
- Étapes parallèles (secrets, dépendances, code, skill) sous budget de 10 minutes, progression en console.
- Secrets : historique git, modifications indexées et non indexées, fichiers non suivis ; dépôt sans commit
  analysé via le répertoire de travail.
- Rapport `report.html` autonome, JSON bruts et `resume.json` dans `reports/`.
