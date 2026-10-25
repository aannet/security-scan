# CLAUDE.md — Security Kit

Lire [INTENT.md](INTENT.md) avant toute modification : c'est la référence des exigences.

Rappel des invariants :

- **Docker est la seule dépendance hôte.** Ne jamais ajouter d'outil à installer sur le poste ; tout va dans l'image.
- **amd64 et arm64.** Tout binaire ajouté à l'image doit exister pour les deux, avec une somme SHA-256 par architecture.
- **N'importe quel dépôt.** Pas de chemin, de langage ou de fichier de config supposé ; la config du dépôt (`tests/security/`) est optionnelle.
- **≤ 10 minutes** pour un scan complet. Étapes parallèles, budget global (`SCAN_BUDGET`), timeout par étape.
- **Progression en console uniquement**, sans fichier ni serveur de suivi. Tout asset temporaire est supprimé en fin de scan.
- **Sortie** : `report.html` (dashboard autonome, sans ressource externe) + JSON bruts + `resume.json`.
- **Lecture seule** sur le dépôt scanné, conteneur durci. Ne pas assouplir les options `docker run` du lanceur.
- Le dynamique (API, back-end, BDD en conditions réelles) n'est pas couvert : le rapport doit continuer à le déclarer.

## Carte

- `VERSION` : version du kit (SemVer), source unique. `scan.sh` en fait le tag de l'image et la passe au build (`KIT_VERSION`) ; affichée en console et dans le rapport. L'incrémenter à chaque modification livrée de `scanner/` ou `scan.sh`, avec une entrée dans `CHANGELOG.md` et un tag `vX.Y.Z`.
- `scan.sh` : lanceur (build de l'image si absente, puis scan).
- `scanner/` : contexte de build de l'image ; `.dockerignore` n'y laisse passer que `scan.py` et `report.py`.
- `scanner/Dockerfile` : image (outils et règles Semgrep épinglés au build). Source unique des versions : exposées en `ENV`, lues par `scan.py` (`VERSIONS`), jamais écrites en dur ailleurs.
- `scanner/scan.py` : orchestrateur parallèle et progression console.
- `scanner/report.py` : rendu du dashboard HTML.
- Après une modification de `scanner/`, relancer avec `--rebuild` : l'image n'est pas reconstruite automatiquement.
- `reports/<horodatage>-<dépôt>/` : rapports de scan (générés, ignorés par git, hors du contexte de build).
- `.agents/skills/security-audit/` : skill d'audit Cloudflare (MIT), version figée dans `skills-lock.json`, licence dans `LICENSES/`. L'image clone sa propre copie épinglée.
- `audits/<dépôt>/run-N/` : sorties d'audits par agent (versionnées, contrairement à `reports/`).
- `LICENSES/` : licences des composants tiers.

Dépôt git (branche `main`). Test rapide sur le kit lui-même : `./scan.sh .` (environ 10 s).

Écrire en français, style direct.
