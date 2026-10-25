# Intention — Security Kit

## Objectif

Un kit de sécurité qui scanne **n'importe quel dépôt de code** en analyse statique, avec **Docker comme seule dépendance** sur la machine qui l'exécute.

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

## Ce que le kit ne couvre pas encore : le dynamique

L'analyse statique ne dit rien de la solidité **en conditions réelles** : API qui tourne, back-end sous charge,
base de données avec ses droits et ses données. C'est le principal angle mort, et le rapport le déclare comme tel.

Piste pour une phase 2 (non implémentée), à valider :

- un `docker compose` éphémère sur un **réseau interne** (`internal: true`, aucune sortie internet) : la BDD
  (ex. `postgres:16-alpine`) avec données factices, l'app construite depuis le dépôt, et un conteneur d'attaque ;
- côté attaque : fuzzing d'API à partir du contrat OpenAPI (Schemathesis), scan DAST passif/actif (ZAP), tests d'authz
  avec des principals factices, quelques tests de charge bornés ;
- côté BDD : rôles et privilèges, RLS, extensions, paramètres exposés ;
- tout est détruit à la fin (`docker compose down -v`), budget de temps séparé du scan statique.

Le point dur : construire et lancer l'app d'un dépôt **quelconque** n'est pas générique. Il faudra un petit
descripteur côté dépôt (commande de build, port, variables factices, schéma de BDD) plutôt qu'une détection magique.

## Hors périmètre

- Lancer l'audit par agent (skill Cloudflare) : il demande un modèle. Le conteneur valide seulement sa sortie.
- Toucher à un environnement déployé ou partagé.
