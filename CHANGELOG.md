# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : [SemVer](https://semver.org/lang/fr/),
source unique dans `VERSION`.

## 1.5.0 - 2026-11-26

### Ajouté

- Assistant `/scan`, skill Claude Code facultatif (`.claude/skills/scan/`) : questions sur le dépôt, le profil, la cible,
  le contrat OpenAPI et le mode, confirmation des données jetables et de l'autorisation sur un hôte distant, commande
  `scan.sh` affichée puis lancée après accord. Les options de `scan.sh` sont inchangées.
- Logo SECK (`assets/logo/`, SVG pour fond clair et sombre) dans le README, et intégré au rapport : barre latérale
  et icône d'onglet, sans ressource externe.
- Aperçu de dépôt `assets/logo/seck-apercu.png` (1280×640).

### Modifié

- Le kit s'appelle SECK : README, rapport, console, `--version` et libellé de l'image. Le dépôt, le tag de l'image
  (`security-kit:<version>`) et les noms de conteneurs ne changent pas.

## 1.4.0 - 2026-11-25

### Modifié

- Rapport réorganisé : verdict en une phrase avec sa règle, constats en deuxième position avec le correctif indiqué,
  tableau « Périmètre » (outil, état, testé, non testé), preuves repliées. Barre latérale, thème clair ou sombre au
  choix, habillage `design.md` en polices système, lignes de tableau alternées.
- Une couleur, un sens : bleu analysé, vert refus vérifié, hachuré non testé, teintes chaudes pour constat ou erreur.
- Zones : arbre des dossiers jusqu'au fichier, à la place du tableau par zone ; `resume.json` enregistre l'état de
  chaque fichier (`inventory.file_states`).
- Constats d'une même règle groupés sur une ligne, copiables ensemble.

### Corrigé

- Couverture du code affichée à 99 % en tête et 100 % dans sa carte : un seul calcul.
- Échec dû à une étape en erreur affiché avec « 0 critique » sans cause : le verdict la nomme.
- Sévérité « Inconnu » absente des décomptes.

### Ajouté

- Fiches de correction : `corrections.md` à côté du rapport, une fiche autonome par constat (description, correctif
  indiqué, références, commande de vérification), à donner à l'IA du projet scanné ; boutons de copie dans le rapport.
- Sonde anonyme (avec `--zap-openapi`) : un `GET` sans identité par lecture du contrat ; section « Accès anonyme » du
  rapport, vert pour chaque refus vérifié, constat « haut » (`KIT-ANON-01`) si une lecture protégée répond.

## 1.3.0 - 2026-11-25

### Ajouté

- Dynamique optionnel avec OWASP ZAP 2.17.0 sur une application déjà lancée : `--zap=<url>`, passif par défaut,
  `--zap-active`, `--zap-ajax`, `--zap-openapi`, `--zap-network`, `--zap-allow-remote`. Image officielle épinglée par
  digest, lancée à part dans un conteneur durci, en parallèle du scan statique et dans le même budget.
- Rapport : section « Dynamique · OWASP ZAP », constats filtrables, phases partielles et limites déclarées ; `zap.json`.

## 1.2.2 - 2026-11-25

### Corrigé

- Semgrep : un fichier avec seulement des erreurs `PartialParsing` était annoncé « règles non appliquées » et compté
  comme non analysé. Il est désormais compté en analyse partielle, avec les lignes en cause, sans être compté comme
  couvert.

## 1.2.1 - 2026-11-24

### Modifié

- OSV-Scanner 2.7.0 → 2.7.1, Semgrep 1.181.0 → 1.187.0.

### Corrigé

- `--rebuild` réutilisait le cache Docker : les règles Semgrep et l'image de base n'étaient pas rafraîchies. La
  reconstruction se fait désormais avec `--pull --no-cache`.

## 1.2.0 - 2026-10-28

### Ajouté

- Rapport : section « Audit par agent · analyse » avec `--audit` : verdicts du skill, ledger, une ligne par piste.
- `triage.json` optionnel dans le run d'audit : gravité estimée si confirmée, attaquant, confiance, effort et action
  pour chaque piste, affichés comme estimation de l'agent. Validé par le scan (empreintes, valeurs).
- Les constats confirmés par le skill comptent dans les KPIs et le verdict avec leur sévérité.

## 1.1.1 - 2026-10-28

### Ajouté

- `README.md` à la racine : présentation, démarrage, options, sortie, limites.

### Corrigé

- Dépendances : les lockfiles sans vulnérabilité n'étaient pas comptés ; leurs manifestes apparaissaient à tort
  comme non couverts. La liste vient désormais du journal d'osv-scanner.

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
