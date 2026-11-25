# Intention — Security Kit

## Objectif

Un kit de sécurité qui scanne **n'importe quel dépôt de code** en analyse statique, et en option une application qui tourne (dynamique avec OWASP ZAP), avec **Docker comme seule
dépendance** sur la machine qui l'exécute.

## Exigences

| # | Exigence | Mesure |
|---|----------|--------|
| 1 | Zéro dépendance hôte hormis Docker (et un `sh` POSIX pour le lanceur), sur x86_64 comme sur ARM64 | rien à installer : ni Node, ni Python, ni binaire de scan ; image native amd64 et arm64 (Apple Silicon, Graviton) |
| 2 | Générique | aucun présupposé sur le dépôt : langages détectés, lockfiles trouvés récursivement, config du dépôt optionnelle |
| 3 | Rapide | **≤ 10 minutes** pour un scan complet. Étapes en parallèle, budget global avec timeout par étape |
| 4 | Progression visible | dans la console, étapes qui se ferment au fil de l'eau. Pas de serveur, pas de fichier de suivi |
| 5 | Empreinte minimale | tout asset de suivi créé pendant le scan est supprimé à la fin. Seuls restent les rapports |
| 6 | Rapport final HTML | dashboard autonome (sans dépendance externe) : KPIs, zones couvertes, zones non couvertes |
| 7 | Lecture seule | le dépôt scanné n'est jamais modifié ; conteneur durci (read-only, non root, sans capacités) |

## Dynamique (option `--zap`)

ZAP teste une application **déjà lancée**, dont on fournit l'URL. Sans `--zap`, le kit ne change pas de comportement.

| # | Exigence | Mesure |
|---|----------|--------|
| D1 | Optionnel | image ZAP officielle, épinglée par digest, téléchargée au premier usage seulement |
| D2 | Même contrat | budget global de 10 minutes, phases bornées, un seul `report.html`, assets temporaires supprimés |
| D3 | Passif par défaut | exploration et analyse passive ; les attaques exigent `--zap-active` |
| D4 | Cible locale par défaut | poste ou réseau Docker désigné ; tout autre hôte exige `--zap-allow-remote=<hôte>`, même en passif |
| D5 | Confiné à l'origine | ZAP n'explore et n'attaque que l'origine fournie, contrat OpenAPI compris |
| D6 | Découverte | spider HTML ; AJAX spider (`--zap-ajax`) et contrat OpenAPI (`--zap-openapi`) en option |
| D7 | Conteneur durci | lecture seule, non root, sans capacités, sans élévation, mémoire et processus plafonnés |
| D8 | Honnête | le rapport donne le mode, les URL visitées, les phases interrompues et ce qui reste non testé |

Limites assumées :

- en passif, le spider ne soumet pas les formulaires `POST` et les écritures du contrat OpenAPI ne sont pas appelées ;
  les `GET` à effet de bord restent possibles, et l'AJAX spider clique dans l'interface : il peut modifier les données.
  Avec l'AJAX spider ou le scan actif, n'utiliser que des données jetables ;
- le navigateur (AJAX spider, règle DOM XSS) charge les scripts et styles tiers de la page, comme tout visiteur ;
  ZAP ne les attaque pas.

## Ce que le kit ne couvre pas encore

Surface authentifiée, tests d'autorisation, logique métier, tenue en charge, base de données (rôles, privilèges, RLS).
Le rapport les déclare comme non couverts.

Piste pour une phase suivante (non implémentée), à valider :

- **environnement jetable préparé par le projet** (retenu le 2026-11-25) : le projet scanné, ou son IA, monte une pile
  avec des données factices, donne son URL au kit et la détruit ensuite. Le kit ne gère pas ce cycle de vie : il
  fournit une recette et exige une déclaration « données jetables » pour l'AJAX spider et le scan actif. Limites : la
  destruction n'est pas garantie par le kit, et la déclaration ne prouve rien. Écarté : le kit qui construit l'app
  (peu portable : compose absent ou dépendant de secrets, de migrations et de données propres au dépôt) ou qui exécute
  sur le poste des commandes fournies par le dépôt scanné. Piloter le compose d'un dépôt reste une assistance possible ;
- authentification (jeton, formulaire, SSO) et tests d'authz avec des principals factices ;
- côté BDD : rôles et privilèges, RLS, extensions, paramètres exposés ; quelques tests de charge bornés.

## Hors périmètre

- Lancer l'audit par agent (skill Cloudflare) : il demande un modèle. Le conteneur valide seulement sa sortie.
- Attaquer un environnement déployé ou partagé sans désignation explicite de l'hôte (D4). L'autorisation de le tester
  reste la responsabilité de l'utilisateur.
