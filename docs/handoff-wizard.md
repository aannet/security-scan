# Handoff — wizard du Security Kit

Rédigé le 2026-11-25 pour une session indépendante. Sujet : un assistant qui fait découvrir les possibilités du kit et
lance le bon scan. **Statut : premier jet, rien de validé ni d'implémenté.**

## À lire avant de commencer

1. `CLAUDE.md` : invariants et carte du dépôt. Écrire en français, style direct.
2. `INTENT.md` : exigences, dont le dynamique (D1 à D8).
3. `README.md` : options, dynamique avec ZAP, limites.
4. `scan.sh` : lanceur POSIX, analyse des options et contrôles. C'est l'interface que le wizard pilote.
5. `scanner/zap.py` (`parse_url`, `locate`, `limits`) : règles de localité et de budget appliquées au dynamique.

## État du kit à la rédaction

- Version 1.3.0 (ajout d'OWASP ZAP) commitée et taguée `v1.3.0`. Vérifier `git status` et `git log` avant toute
  modification : un autre chantier peut être en cours dans le répertoire de travail.
- Un autre chantier est envisagé en parallèle : transmission des constats à une IA (boutons « Copier »,
  `corrections.md`). Il touche `scanner/report.py` et `scanner/scan.py`. Le wizard ne devrait pas les modifier.

## Intention exprimée par l'utilisateur

« Travailler un brief de wizard des différentes possibilités offertes par le kit scan. » Le livrable attendu est
d'abord le **brief**, à construire avec l'utilisateur en lui posant des questions, avant tout code.

## Possibilités à couvrir

| Option | Effet | Contrainte |
|---|---|---|
| `<dépôt>` | scan statique : secrets, dépendances, code, skill | dossier existant |
| `--only=secrets,deps,code,skill` | sous-ensemble d'étapes statiques | n'écarte pas ZAP si `--zap` est présent |
| `--strict` | échec aussi sur un constat haut | |
| `--audit=<dossier>` | valide et affiche un audit par agent | sortie déjà produite hors du kit |
| `--rebuild` | reconstruit l'image de zéro | long |
| `--version` | version du kit | |
| `SCAN_BUDGET=<s>` | budget global (défaut 570) | avec ZAP : 210 s au minimum en passif, davantage avec AJAX ou actif (calcul dans `limits`) |
| `--zap=<url>` | dynamique passif sur une application déjà lancée | URL HTTP(S), sans identifiants |
| `--zap-ajax` | explore les écrans en JavaScript | clique dans l'interface : peut modifier les données |
| `--zap-active` | envoie des attaques, appelle les écritures du contrat | données jetables |
| `--zap-openapi=<fichier ou URL>` | endpoints d'un contrat | autonome, sans `$ref` externe ; écritures retirées en passif |
| `--zap-network=<réseau>` | cible sur un réseau Docker nommé | `host`, `none`, `container:*` refusés |
| `--zap-allow-remote=<hôte>` | cible non locale assumée | même hôte que l'URL, exigé même en passif |

Non couvert dans tous les cas : surface authentifiée, autorisations, logique métier, charge, base de données.

Codes de sortie : 0 aucun constat critique ; 1 constat critique, erreur d'outil ou budget dépassé (haut compris avec
`--strict`) ; 2 option ou cible refusée. Config optionnelle du dépôt scanné : `tests/security/`.

## Premier jet du brief

- **Objectif :** découvrir les possibilités et lancer le bon scan sans connaître les options.
- **Principe :** le wizard compose la commande, l'affiche, puis la lance après confirmation. La ligne de commande reste
  la référence, notamment en CI.

| Étape | Question | Aide |
|---|---|---|
| 1 | Quel dépôt ? | chemin courant par défaut |
| 2 | Quel profil ? | rapide, complet, avec application qui tourne |
| 3 | Statique : étapes, mode strict, audit existant ? | défauts proposés |
| 4 | Quelle cible ? | détection des conteneurs et ports publiés |
| 5 | Quel contrat OpenAPI ? | recherche dans le dépôt |
| 6 | Passif, AJAX ou actif ? | risque sur les données affiché ; données jetables à confirmer |
| 7 | Récapitulatif | commande, durée maximale, ce qui ne sera pas couvert |
| 8 | Après le scan | ouvrir le rapport ; transmission des constats si elle existe |

## Forme

| Option | Pour | Contre |
|---|---|---|
| Script `sh` (`./wizard.sh`) — recommandé | respecte « Docker seule dépendance », voit les conteneurs et les fichiers | interface sobre, POSIX à tenir sur Linux, macOS, WSL |
| Page HTML autonome qui génère la commande | plus lisible, partageable | aucune détection, risque de dériver de `scan.sh` |
| Interface dans le conteneur du kit | Python disponible | ne voit pas le Docker de l'hôte sans monter son socket, à écarter |

La recommandation `sh` est une proposition non validée.

## Contraintes non négociables

- Aucune dépendance hôte hors Docker et `sh` POSIX.
- N'importe quel dépôt : aucun chemin, langage ou fichier supposé.
- Ne pas assouplir les options `docker run` ; ne rien écrire dans le dépôt scanné.
- Les garde-fous restent dans `scan.sh` et `zap.py` : le wizard les explique, il ne les contourne ni ne les duplique.
- Aucun fichier de suivi.
- Le dépôt du kit est public : aucun constat ni nom de dépôt tiers dans ce qui est commité.

## Questions à poser à l'utilisateur

1. Pour qui : usage personnel, équipe, découverte par un tiers ?
2. Découvrir les possibilités, ou surtout lancer vite le bon scan ?
3. Script `sh` ou page HTML ?
4. Faut-il mémoriser les réponses pour rejouer un scan (conflit possible avec « aucun fichier de suivi » et « rien dans
   le dépôt ») ?
5. Comment le wizard accompagne-t-il l'environnement jetable avant un scan AJAX ou actif ? Retenu (voir `INTENT.md`) :
   le projet scanné ou son IA le prépare et donne l'URL ; le kit fournit une recette et demande une déclaration
   « données jetables », pas encore implémentée. Pour une pile compose locale : autorisation de la personne qui lance
   le scan, accès au fichier compose, variables et secrets, migrations et jeu de données, absence de volumes externes ou
   de noms de conteneurs fixes.
6. Livraison visée : 1.5.0 après la transmission des constats (découpage proposé, non confirmé) ?

## Critères de fin du brief

Utilisateur et usage nommés, parcours validé étape par étape, forme choisie, hors périmètre écrit, mesure de réussite
(par exemple : lancer un scan dynamique correct sans lire le README), version cible.
