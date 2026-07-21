# AegisAI — Couches de sécurité implémentées & priorités restantes

---

## 1. Couches de sécurité implémentées

### Couche 1 — Authentification Elasticsearch (moindre privilège)
- `xpack.security.enabled=true` sur le cluster.
- Compte dédié `aegisai_agent`, rôle limité aux index `aegisai-*` uniquement (lecture/écriture), **aucun droit cluster/admin**.
- Vérifié empiriquement : accès refusé (`403`) sur un index hors périmètre (`.security`).
- Protège contre : accès non autorisé aux données, mouvement latéral en cas de compromission d'un agent.

### Couche 2 — Sanitization avant tout appel LLM (prompt injection directe)
- Chaque message utilisateur passe par des règles regex (`security_rules.py`) **avant** d'atteindre le LLM.
- Détecte : SQL injection, command injection, template injection, XSS, prompt injection ("ignore previous instructions", "system: override"...).
- Message suspect → rejeté (`400`) sans jamais toucher le modèle.
- Protège contre : OWASP LLM01 (Prompt Injection) — cas direct.

### Couche 3 — Défense en profondeur (prompt injection indirecte)
- Toute donnée relue depuis Elasticsearch (ex. `device_id`) repasse par la même vérification avant d'être réinjectée dans un prompt LLM.
- Vérification dupliquée à deux niveaux indépendants : Chatbot **et** Decision Agent (le second ne fait pas confiance au premier).
- Affichage : tout identifiant suspect est masqué avant d'être montré à l'utilisateur.
- Protège contre : OWASP LLM01 — cas indirect, plus subtil et souvent oublié.

### Couche 4 — Intents fermés / RBAC applicatif
- Le LLM du Chatbot ne peut classifier un message que parmi 5 intentions prédéfinies — jamais d'action libre ou de texte arbitraire interprété comme une commande.
- Protège contre : OWASP LLM08 (Excessive Agency).

### Couche 5 — Human-in-the-loop sur les actions critiques
- Toute action destructive/critique passe par une file d'approbation (`pending_human_approval`) — jamais d'exécution automatique.
- Approbation avec `reviewer` obligatoire (audit trail) et vérification d'idempotence (`409` si déjà traitée, empêche double exécution/race condition).
- Protège contre : exécution non supervisée d'actions à impact réel, rejeu de requêtes.

### Couche 6 — Détection indépendante de la source
- Le Detection Agent ne se fie jamais à un champ auto-déclaré par l'émetteur (un attaquant réel ne déclare pas son attaque).
- Trois règles indépendantes : pattern-based (injection), rate-based (flood), threshold-based (anomalie statistique, baseline construite uniquement sur les valeurs saines).
- Protège contre : contournement de la détection par un attaquant qui maquille ses métadonnées.

### Couche 7 — API Gateway (cloisonnement + rate limiting)
- Point d'entrée unique ; les agents internes ne sont jamais exposés directement à un client externe.
- Clé API externe (`X-Api-Key`) pour les clients, clé interne distincte (`X-Internal-Api-Key`) entre Gateway et agents.
- Rate limiting (5–30 req/min) sur les endpoints coûteux (`/chat`).
- Agent inconnu demandé → `404` sans révéler la structure interne.
- Protège contre : exposition directe des agents, énumération de l'architecture interne, déni de service par flooding.

### Couche 8 — Rendu sécurisé côté frontend
- Les données potentiellement issues d'un attaquant (ex. payload capturé comme `device_id`) sont affichées en `textContent`, jamais en `innerHTML`.
- Protège contre : Stored XSS si une donnée malveillante remonte jusqu'à l'interface.

---

## 2. Ce qu'il reste de plus important à traiter (par priorité)

| # | Action | Pourquoi c'est important | Effort estimé |
|---|---|---|---|
| 1 | **mTLS ou certificats entre agents** (actuellement clé API statique partagée) | La clé interne, si divulguée, permet d'usurper n'importe quel appel inter-agents. C'est la limite la plus citée dans un vrai modèle Zero Trust. | Élevé |
| 2 | **Validation d'existence du device_id** avant toute action/approbation | Actuellement une action peut être proposée sur un device qui n'existe pas — incohérence exploitable. | Faible |
| 3 | **Chiffrement du trafic inter-agents (TLS interne)** | Tout circule en HTTP clair entre agents sur la même machine — acceptable en démo, pas en déploiement réel. | Moyen |
| 4 | **Restreindre CORS** (`allow_origins=["*"]` actuellement) au domaine réel du frontend | Actuellement n'importe quel site web pourrait appeler le Gateway depuis le navigateur d'un utilisateur. | Faible |
| 5 | **Rotation des clés API** (internes/externes) — aucun mécanisme de renouvellement actuellement | Une clé compromise reste valide indéfiniment. | Moyen |
| 6 | **Limiter la dérive lente de la baseline statistique** (Detection Agent) | Une attaque progressive et lente peut, avec le temps, se faire passer pour "normale". | Moyen |
| 7 | **Journalisation centralisée signée/inaltérable** des décisions d'approbation | Actuellement les logs sont dans Elasticsearch mais rien n'empêche une modification a posteriori par un compte à privilèges élevés. | Élevé |

**Priorité recommandée si le temps est limité avant la soutenance : #2 (rapide, corrige une incohérence réelle) puis documenter #1, #3, #5, #7 comme axes d'amélioration identifiés — cela démontre une bonne compréhension des limites du système, ce qui est valorisé autant que l'implémentation elle-même.**
