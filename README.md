# Security Kit

Scan de sécurité de **n'importe quel dépôt de code**, avec **Docker comme seule dépendance** : analyse statique, et en
option test d'une application qui tourne avec OWASP ZAP.
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
./scan.sh <dépôt> --rebuild                    # reconstruit l'image de zéro (base et règles à jour)
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
| `zap` | OWASP ZAP | application déjà lancée, avec `--zap=<url>` (voir ci-dessous) |

Aucun présupposé sur le dépôt : langages détectés, git facultatif. Une config propre au dépôt peut être placée dans
`tests/security/` (`gitleaks.toml`, `osv-scanner.toml`, `semgrep-exclusions.json`) ; sans elle, les valeurs par
défaut des outils s'appliquent. Les versions des outils sont épinglées dans [`scanner/Dockerfile`](scanner/Dockerfile).

## Dynamique avec ZAP

Lancer l'application, puis donner son URL :

```bash
./scan.sh <dépôt> --zap=http://localhost:3000                 # passif, application du poste
./scan.sh <dépôt> --zap=http://api:8000 --zap-network=app_net # application sur un réseau Docker
./scan.sh <dépôt> --zap=<url> --zap-openapi=docs/openapi.json # endpoints d'un contrat (fichier ou URL)
./scan.sh <dépôt> --zap=<url> --zap-ajax                      # explore aussi les écrans en JavaScript (SPA)
./scan.sh <dépôt> --zap=<url> --zap-active                    # envoie des attaques (injections, XSS...)
./scan.sh <dépôt> --zap=https://recette.exemple.fr --zap-allow-remote=recette.exemple.fr
```

Les résultats rejoignent le même `report.html` : section dédiée, constats filtrables, URL visitées, limites. Une alerte
ZAP « High » compte comme un constat haut (échec avec `--strict`). Le premier scan télécharge l'image ZAP (plus d'1 Go).

**Refus de l'accès anonyme.** Avec `--zap-openapi`, le kit envoie avant ZAP un `GET` sans cookie ni jeton à chaque
lecture du contrat. Une lecture déclarée protégée (`security`) doit répondre 401 ou 403 : elle apparaît en vert. Un
2xx devient un constat « haut » (contrôle d'accès absent, ou contrat faux). Tout autre code est « non concluant ».
Les paramètres de chemin reçoivent des valeurs factices, les écritures ne sont jamais appelées, et la sonde s'arrête à
20 s ou 500 lectures. Le vert ne dit rien des droits entre utilisateurs ni des injections.

> **Risque sur les données.** Sans `--zap-active`, aucune attaque n'est envoyée, le spider ne soumet pas les formulaires
> `POST` et les écritures du contrat OpenAPI ne sont pas appelées. Un `GET` à effet de bord reste possible. Avec
> `--zap-ajax` (le navigateur clique dans l'interface) ou `--zap-active`, **n'utiliser que des données jetables**.
> Ne scanner que ce que l'on est autorisé à tester.

- Une cible est **locale** si c'est le poste (`localhost`, `host.docker.internal`) ou un hôte du réseau donné par
  `--zap-network`. Toute autre cible exige `--zap-allow-remote=<hôte>`, même en passif.
- ZAP reste sur l'origine de l'URL (schéma, hôte, port). Une redirection vers une autre origine n'est pas suivie : donner
  l'URL finale. Le navigateur charge les scripts et styles tiers de la page, sans les tester.
- Un contrat OpenAPI doit être autonome (aucune `$ref` externe) ; ses serveurs sont remplacés par l'origine visée.
- Sans authentification : la surface protégée n'est pas testée.
- Les phases ont une durée maximale tenant dans le budget ; une phase interrompue est signalée comme partielle.
  `SCAN_BUDGET` doit être d'au moins 210 s en passif.
- Linux sans Docker Desktop : une application du poste doit écouter sur `0.0.0.0`, pas seulement `127.0.0.1`.

## Sortie

Dans `reports/<horodatage>-<dépôt>/` :

- `report.html` : page autonome (aucune ressource externe), dans l'ordre de lecture : verdict, constats filtrables
  et groupés par règle, périmètre testé et non testé par outil, puis les détails repliés (arbre des dossiers au fichier,
  accès anonyme, dynamique, limites, exécution). Thème clair ou sombre ;
- `corrections.md` : une fiche par constat, avec correctif indiqué et commande de vérification, à donner à l'IA du
  projet scanné (les mêmes fiches se copient depuis le rapport) ;
- `resume.json` : synthèse, comptes par sévérité, versions des outils ;
- `gitleaks.json`, `osv.json`, `semgrep.json`, `zap.json` (avec `--zap`) : sorties brutes.

## Isolation

Le dépôt est monté en lecture seule. Le conteneur tourne sans root, avec un système de fichiers en lecture seule,
sans capacité Linux ni élévation de privilèges, mémoire et processus plafonnés. Les binaires sont vérifiés par
somme SHA-256 au build. Aucun fichier de suivi : le conteneur et son `/tmp` disparaissent à la fin du scan.
Réseau : requis pour la base de vulnérabilités OSV et, avec `--zap`, pour joindre la cible.

Avec `--zap`, un second conteneur (image officielle ZAP) tourne en parallèle avec le même durcissement, 3 Go et 2048
processus au plus. Il ne voit pas le dépôt : seulement un dossier de travail temporaire, supprimé en fin de scan.

## Audit par agent

En complément du scan, le kit embarque le skill [`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
(MIT) dans `.agents/skills/security-audit/`. Dans une session d'agent de code ouverte sur le dépôt cible :
`security audit this codebase`. Les livrables arrivent dans `audits/<dépôt>/run-N/`, gardés en local (ignorés par
git) : ils décrivent les failles du dépôt audité. `./scan.sh <dépôt> --audit=audits/<dépôt>/run-N` valide leur format.
En fin d'audit, demander à l'agent un `triage.json` (format dans [`scanner/README.md`](scanner/README.md#rapport)) :
le skill ne note pas les pistes non confirmées, ce fichier donne pour chacune la gravité si elle se confirme, qui
peut l'exploiter, la confiance et l'action à mener. Le rapport HTML les affiche dans la section d'analyse de l'audit.

## Limites

- **Dynamique partiel.** Sans `--zap`, rien n'est exécuté. Avec, seule la surface HTTP non authentifiée est testée :
  autorisations, logique métier, charge et base de données ne le sont pas. Le rapport le déclare.
- Semgrep ignore par défaut les dossiers `test/` et `tests/` ; le rapport les compte à part.
- Un seul run d'audit par agent trouve environ la moitié de ce que des runs répétés trouvent (selon les auteurs du skill).

## Pour aller plus loin

- [`INTENT.md`](INTENT.md) : exigences du kit, dont le dynamique ;
- [`scanner/README.md`](scanner/README.md) : détail du scanner, progression, config, durées mesurées ;
- [`CHANGELOG.md`](CHANGELOG.md) : historique des versions ;
- `README.html` et `ARTICLE.html` : présentation détaillée et retour sur le premier run.

## Licence

Aucune licence : le code du kit est publié sans licence, tous droits réservés.
Le skill Cloudflare embarqué reste sous sa propre licence MIT, dans [`LICENSES/`](LICENSES/).
