# Security Kit

Scan de sécurité statique de **n'importe quel dépôt de code**, avec **Docker comme seule dépendance**.
Secrets, dépendances vulnérables, motifs de code dangereux : un rapport HTML autonome en moins de 10 minutes,
sans rien installer sur le poste et sans jamais modifier le dépôt scanné.

## Démarrage

```bash
git clone https://github.com/aannet/security-scan.git
cd security-scan
./scan.sh /chemin/vers/un/depot
```

L'image se construit au premier lancement (environ 1 minute), puis le scan s'affiche en console, étape par étape.
Rapport : `reports/<horodatage>-<dépôt>/report.html`.

Prérequis : Docker et un `sh` POSIX. Linux, macOS ou Windows (WSL), en x86_64 comme en ARM64 (Apple Silicon, Graviton).

## Options

```bash
./scan.sh <dépôt> --strict                     # échoue aussi sur un constat haut
./scan.sh <dépôt> --only=secrets,code          # sous-ensemble d'étapes : secrets, deps, code, skill
./scan.sh <dépôt> --audit=audits/<dépôt>/run-1 # valide en plus la sortie d'un audit par agent
./scan.sh <dépôt> --rebuild                    # reconstruit l'image
./scan.sh --version
SCAN_BUDGET=300 ./scan.sh <dépôt>              # budget de temps en secondes (défaut 570)
```

Code de sortie 1 sur un constat critique, une erreur d'outil ou un dépassement du budget : utilisable en CI.

## Ce qui est analysé

| Étape | Outil | Portée |
|-------|-------|--------|
| `secrets` | gitleaks | historique git complet, modifications indexées et non indexées, fichiers non suivis |
| `deps` | OSV-Scanner | tous les lockfiles du dépôt, récursivement |
| `code` | Semgrep | règles choisies selon les langages détectés, figées dans l'image |
| `skill` | validateurs Cloudflare | conformité d'un audit par agent monté avec `--audit` |

Aucun présupposé sur le dépôt : langages détectés, git facultatif. Une config propre au dépôt peut être placée dans
`tests/security/` (`gitleaks.toml`, `osv-scanner.toml`, `semgrep-exclusions.json`) ; sans elle, les valeurs par
défaut des outils s'appliquent. Les versions des outils sont épinglées dans [`scanner/Dockerfile`](scanner/Dockerfile).

## Sortie

Dans `reports/<horodatage>-<dépôt>/` :

- `report.html` : dashboard autonome (aucune ressource externe) : KPIs, couverture par zone, ce qui n'est pas
  couvert et pourquoi, constats filtrables ;
- `resume.json` : synthèse, comptes par sévérité, versions des outils ;
- `gitleaks.json`, `osv.json`, `semgrep.json` : sorties brutes.

## Isolation

Le dépôt est monté en lecture seule. Le conteneur tourne sans root, avec un système de fichiers en lecture seule,
sans capacité Linux ni élévation de privilèges, mémoire et processus plafonnés. Les binaires sont vérifiés par
somme SHA-256 au build. Aucun fichier de suivi : le conteneur et son `/tmp` disparaissent à la fin du scan.
Réseau : requis uniquement pour la base de vulnérabilités OSV.

## Audit par agent

En complément du scan, le kit embarque le skill [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
(MIT) dans `.agents/skills/security-audit/`. Dans une session d'agent de code ouverte sur le dépôt cible :
`security audit this codebase`. Les livrables arrivent dans `audits/<dépôt>/run-N/`, gardés en local (ignorés par
git) : ils décrivent les failles du dépôt audité. `./scan.sh <dépôt> --audit=audits/<dépôt>/run-N` valide leur format.

## Limites

- **Statique uniquement.** Rien n'est exécuté : API en fonctionnement, back-end sous charge et base de données
  réelle ne sont pas testés. Le rapport le déclare comme zone non couverte.
- Semgrep ignore par défaut les dossiers `test/` et `tests/` ; le rapport les compte à part.
- Un seul run d'audit par agent trouve environ la moitié de ce que des runs répétés trouvent (selon les auteurs du skill).

## Pour aller plus loin

- [`INTENT.md`](INTENT.md) : exigences du kit et piste pour le test dynamique ;
- [`scanner/README.md`](scanner/README.md) : détail du scanner, progression, config, durées mesurées ;
- [`CHANGELOG.md`](CHANGELOG.md) : historique des versions ;
- `README.html` et `ARTICLE.html` : présentation détaillée et retour sur le premier run.

## Licence

Aucune licence : le code du kit est publié sans licence, tous droits réservés.
Le skill Cloudflare embarqué reste sous sa propre licence MIT, dans [`LICENSES/`](LICENSES/).
