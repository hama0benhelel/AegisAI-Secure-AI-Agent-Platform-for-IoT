# AegisAI-Secure-AI-Agent-Platform-for-IoT


Plateforme de sécurisation d'agents IA multi-composants déployés en environnement IoT. Projet réalisé dans le cadre d'un stage d'ingénierie cybersécurité , inspiré de l'architecture cliente .



---

## Aperçu

AegisAI simule un pipeline IoT complet — capteurs → ingestion → détection d'anomalies → recommandation par IA → action supervisée par un humain — avec une couche de sécurité de bout en bout (authentification, moindre privilège, défense contre le prompt injection, human-in-the-loop).

```
IoT Simulator → EMQX (MQTT) → Monitoring Agent → Elasticsearch (authentifié)
                                                        ↓
                                                Detection Agent (règles indépendantes)
                                                        ↓
API Gateway ← Chatbot/Orchestrator ← Decision Agent (recommandations LLM)
    ↓                ↓
Frontend      Response Agent (exécution post-approbation)
(dashboard + chat, page unique)
```
## 1. Architecture globale
 
```
Frontend (index.html — dashboard + chat, une seule page)
        │
   API Gateway (:8000)  ← auth externe, rate limiting, logging centralisé
        │
   ┌────┴─────────────────────────────────┐
   │                                       │
Chatbot/Orchestrator (:8010)      Decision Agent (:8012)
   │  sanitization, scoped intents,        │  recommandations LLM
   │  human approval gate                  │
   │                                       │
   └────────────┬──────────────────────────┘
                 │
     Response Agent (:8013) — exécution post-approbation
                 │
   ┌─────────────┴─────────────┐
Monitoring Agent          Detection Agent
(ingestion MQTT→ES)       (règles indépendantes)
                 │
         Elasticsearch (authentifié, least privilege)
                 │
     IoT Simulator (EMQX) — trafic normal + attaques simulées
```
 
Pipeline conceptuel calqué sur le cycle OÉRIX : **Détecter → Comprendre → Recommander → Planifier/Exécuter**.
 
---
 
## 2. Composants livrés
 
| Composant | Rôle | Port |
|---|---|---|
| `iot_simulator.py` | Génère trafic MQTT normal + attaques (flood, injection, outlier) | — |
| `monitoring_agent.py` | Ingestion MQTT → Elasticsearch | — (worker) |
| `detection_agent.py` | Analyse indépendante (regex, rate-limit, stats) → alertes | — (worker) |
| `decision_agent.py` | Recommandation via LLM (Groq) à partir des détections | 8012 |
| `response_agent.py` | Exécution des actions approuvées (état des devices) | 8013 |
| `chatbot_orchestrator.py` | Point d'entrée conversationnel, NLU, RBAC, approbation humaine | 8010 |
| `gateway.py` | Point d'entrée unique, auth externe, rate limit, `/stats` | 8000 |
| `es_auth.py` | Authentification Elasticsearch partagée (compte least-privilege) | — |
| `security_rules.py` | Patterns de détection d'injection, source unique partagée | — |
| `index.html` | Dashboard temps réel + chat, page unique | — |
 
---
 
## 3. Mesures de sécurité implémentées
 
### 3.1 Authentification & moindre privilège
 
- **Elasticsearch** : `xpack.security.enabled=true`, compte dédié `aegisai_agent` (rôle `aegisai_agent_role`) limité aux index `aegisai-*` — **aucun accès** aux index systèmes (`.security`, etc.). Vérifié empiriquement (403 sur `.security`).
- **Gateway** : clé API externe (`X-Api-Key`) exigée de tout client, distincte de la clé interne.
- **Inter-agents** : clé API interne (`X-Internal-Api-Key`) entre le Gateway et les agents — un agent ne répond pas à un appel non authentifié.
### 3.2 Défense contre le prompt injection (OWASP LLM01)
 
- **Sanitization avant tout appel LLM** : chaque message utilisateur passe par `security_rules.sanitize_input()` (regex : SQLi, command injection, template injection, XSS, prompt injection) **avant** d'atteindre le LLM. Un message qui matche est rejeté (HTTP 400) sans jamais toucher le modèle.
- **Prompt injection indirecte détectée et corrigée en cours de test** : un `device_id` contenant un payload d'attaque capturé plus tôt (stocké en base par un attaquant) pouvait être relu et réinjecté tel quel dans le prompt du Decision Agent. Corrigé par :
  - vérification `is_suspicious()` côté Chatbot avant l'appel au Decision Agent ;
  - **défense en profondeur** : la même vérification est dupliquée côté Decision Agent lui-même, indépendamment de l'appelant (le endpoint `/recommend` peut être atteint directement via le Gateway sans passer par le Chatbot).
- **Affichage sécurisé** : tout `device_id` suspect est masqué (`[identifiant suspect masqué]`) avant d'être renvoyé à l'utilisateur, plutôt que d'échoer le payload brut dans l'UI.
- **System prompt hardening** : instructions explicites interdisant au LLM de révéler son prompt système ou de changer de rôle sur demande.
### 3.3 Excessive agency / RBAC (OWASP LLM08)
 
- **Intents fermés** : le LLM du Chatbot ne peut classifier un message que parmi 5 intentions prédéfinies (`read_sensor_status`, `get_anomaly_report`, `get_recommendation`, `trigger_corrective_action`, `unknown`) — jamais d'action libre.
- **Human-in-the-loop** : toute intention marquée `critical` (`trigger_corrective_action`) est mise en file d'attente (`aegisai-pending-approvals`) au lieu d'être exécutée directement.
### 3.4 Workflow d'approbation humaine
 
- Endpoint `/approve/{approval_id}` avec décision `approve`/`reject` + `reviewer` obligatoire (audit trail).
- **Idempotence vérifiée** : une demande déjà traitée renvoie `409 Conflict` sur une seconde tentative — empêche double exécution / race condition.
- Bug corrigé en cours de développement : recherche par `approval_id` échouait à cause de la tokenisation Elasticsearch sur les tirets d'un UUID (`term` sur champ `text` analysé au lieu de `.keyword`).
### 3.5 Détection indépendante (Detection Agent)
 
- Les règles de détection **ne se fient jamais** au champ `status` auto-déclaré par la source (un attaquant réel ne déclarerait pas son attaque). Trois familles de règles :
  - pattern-based (injection dans tous les champs texte),
  - rate-based (flood par device, fenêtre glissante),
  - threshold-based (anomalie statistique, baseline construite uniquement sur des valeurs jugées saines pour éviter la contamination de la baseline par l'attaque elle-même).
### 3.6 Rate limiting
 
- `/chat` (Gateway et Chatbot) limité à 5–30 requêtes/minute selon le point d'entrée — protection contre le flooding des appels LLM (coûteux, et Groq applique lui-même des quotas).
### 3.7 Cloisonnement réseau applicatif (API Gateway)
 
- Les agents internes (Chatbot, Decision, Response) ne sont **jamais exposés directement** à un client externe — seul le Gateway connaît leurs adresses (`AGENT_REGISTRY`). Un nom d'agent inconnu renvoie `404` sans révéler la structure interne.
- CORS restreint en prévision d'un déploiement (actuellement ouvert en dev, à restreindre au domaine du frontend en production).
---
 
## 4. Tests de sécurité validés (end-to-end, par curl)
 
| Scénario | Résultat attendu | Statut |
|---|---|---|
| Requête normale (ex. statut capteurs) | Données réelles retournées | ✅ |
| Prompt injection directe (`ignore all previous instructions...`) | 400, bloqué avant le LLM | ✅ |
| Prompt injection indirecte (device_id empoisonné réinjecté) | Recommandation refusée | ✅ (corrigé) |
| Action critique sans approbation | `pending_human_approval`, pas d'exécution | ✅ |
| Approbation | `approved_and_executed` | ✅ |
| Rejet | `rejected` | ✅ |
| Double traitement de la même approbation | `409 Conflict` | ✅ |
| Accès Gateway sans clé API | `401 Unauthorized` | ✅ |
| Accès à un agent non enregistré | `404 Not Found` | ✅ |
| Compte `aegisai_agent` sur index hors périmètre | `403 Forbidden` | ✅ |
| Flood MQTT (50 msg/s) | Détecté par règle rate-based | ✅ |
| Valeurs aberrantes (ex. -93°C, 644°C) | Détecté par règle threshold-based | ✅ |
 
---
 
## 5. Modèle de menaces (synthèse STRIDE)
 
| # | Menace | Catégorie STRIDE | Vecteur | Mitigation implémentée | Statut |
|---|---|---|---|---|---|
| T1 | Prompt injection directe (utilisateur → LLM) | Tampering | Message chat contenant des instructions malveillantes | Sanitization regex avant tout appel LLM (`security_rules.py`) | ✅ Mitigé |
| T2 | Prompt injection indirecte (donnée stockée → LLM) | Tampering | `device_id` empoisonné relu depuis Elasticsearch et réinjecté dans un prompt | Vérification `is_suspicious()` à deux niveaux indépendants (Chatbot + Decision Agent) | ✅ Mitigé |
| T3 | Exécution d'action critique non autorisée | Elevation of Privilege | LLM classifie à tort une requête comme légitime pour une action destructive | Intents fermés (RBAC) + file d'approbation humaine obligatoire | ✅ Mitigé |
| T4 | Double exécution d'une action approuvée | Tampering | Rejeu de la requête d'approbation | Vérification d'idempotence (`409` si déjà traité) | ✅ Mitigé |
| T5 | Accès non autorisé à Elasticsearch | Information Disclosure / Tampering | Appel direct à l'API ES sans passer par les agents | Authentification obligatoire (`xpack.security`), compte dédié least-privilege | ✅ Mitigé |
| T6 | Mouvement latéral via le compte agent | Elevation of Privilege | Compte `aegisai_agent` compromis utilisé pour accéder à d'autres index/fonctions cluster | Rôle limité à `aegisai-*`, aucun privilège cluster (vérifié : 403 sur `.security`) | ✅ Mitigé |
| T7 | Déni de service sur le Chatbot (flood LLM) | Denial of Service | Volume élevé de requêtes `/chat` | Rate limiting (5–30 req/min) au niveau Gateway et Chatbot | ✅ Mitigé |
| T8 | Flood MQTT sur les capteurs IoT | Denial of Service | Un device (ou attaquant usurpant un device) publie à haute fréquence | Détection rate-based (fenêtre glissante, seuil/device) | ✅ Détecté (pas de blocage automatique de l'émetteur) |
| T9 | Usurpation d'un agent interne | Spoofing | Un tiers appelle directement un agent en se faisant passer pour le Gateway | Clé API interne partagée entre Gateway et agents | ⚠️ Partiel — clé statique, pas de mTLS/certificats |
| T10 | Divulgation du system prompt / des instructions internes | Information Disclosure | Demande explicite ("reveal your system prompt") | Regex de détection + consigne explicite dans le system prompt | ✅ Mitigé |
| T11 | Reflected/Stored XSS via données de capteur affichées | Tampering | Payload `<script>` stocké comme device_id, affiché dans le dashboard | Rendu en `textContent` côté frontend (jamais `innerHTML`) + masquage `safe_label()` côté Chatbot | ✅ Mitigé |
| T12 | Action sur un device inexistant | Tampering | Demande d'action sur un `device_id` qui n'existe pas dans le système | — | ❌ Non traité (voir §6) |
| T13 | Interception réseau (MITM) entre composants | Information Disclosure | Trafic HTTP en clair entre agents (pas de TLS interne) | — | ❌ Non traité (démo locale, mono-hôte) |
| T14 | Contamination de la baseline statistique du Detection Agent | Tampering | Attaque progressive conçue pour être apprise comme "normale" | Seules les valeurs jugées saines alimentent la baseline (les outliers en sont exclus) | ✅ Mitigé partiellement — reste vulnérable à une dérive lente sous le seuil |

## Composants

| Dossier / fichier | Rôle |
|---|---|
| `simulator/iot_simulator.py` | Génère du trafic MQTT normal et des attaques simulées |
| `agents/monitoring_agent.py` | Ingestion MQTT → Elasticsearch |
| `agents/detection_agent.py` | Détection indépendante (patterns, rate-limit, anomalies statistiques) |
| `agents/decision_agent.py` | Recommandations via LLM (Groq) |
| `agents/response_agent.py` | Exécution des actions approuvées |
| `agents/chatbot_orchestrator.py` | Point d'entrée conversationnel, NLU, RBAC, approbation humaine |
| `agents/security_rules.py` | Patterns de détection d'injection, partagés entre agents |
| `agents/es_auth.py` | Authentification Elasticsearch partagée |
| `gateway/gateway.py` | Point d'entrée unique (auth externe, rate limiting, stats) |
| `security/setup_es_security.sh` | Provisionnement du compte Elasticsearch dédié (least privilege) |
| `frontend/index.html` | Dashboard temps réel + chat, page unique |
| `docs/RECAP_SECURITE.md` | Threat model, mesures de sécurité, tests validés |

---

## Prérequis

- Python 3.12+, `venv`
- Docker (EMQX, Elasticsearch, Kibana)
- Un compte [Groq](https://console.groq.com) (niveau gratuit suffisant)

## Installation

```bash
git clone <url-du-repo>
cd aegisai

python3 -m venv venv
source venv/bin/activate

pip install fastapi uvicorn requests groq slowapi httpx paho-mqtt
```

## Variables d'environnement

À définir avant de lancer quoi que ce soit (idéalement dans `~/.bashrc` ou un fichier `.env` non commité) :

```bash
export ES_USER=aegisai_agent
export ES_PASSWORD='<mot_de_passe_choisi>'
export GROQ_API_KEY='<votre_clé_groq>'
export AEGISAI_INTERNAL_API_KEY=$(openssl rand -hex 16)
export AEGISAI_EXTERNAL_API_KEY=$(openssl rand -hex 16)
```

### Provisionnement Elasticsearch (une seule fois)

```bash
cd security
export ELASTIC_PASSWORD='<mot_de_passe_superuser_elastic>'
export AEGISAI_AGENT_PASSWORD="$ES_PASSWORD"
chmod +x setup_es_security.sh
./setup_es_security.sh
```

---

## Lancement (ordre recommandé)

Chaque commande dans un terminal séparé (ou via `tmux`/`screen`) :

```bash
# 1. Infrastructure (si pas déjà lancée)
cd elk-stack && docker compose up -d

# 2. Monitoring Agent
cd agents && python3 monitoring_agent.py

# 3. Detection Agent
cd agents && python3 detection_agent.py

# 4. Decision Agent
cd agents && uvicorn decision_agent:app --reload --port 8012

# 5. Response Agent
cd agents && uvicorn response_agent:app --reload --port 8013

# 6. Chatbot/Orchestrator
cd agents && uvicorn chatbot_orchestrator:app --reload --port 8010

# 7. API Gateway
cd gateway && uvicorn gateway:app --reload --port 8000

# 8. Simulateur IoT (génère du trafic)
cd simulator && python3 iot_simulator.py --mode mixed
```

### Frontend

Éditer `frontend/index.html`, renseigner `EXTERNAL_API_KEY` avec la valeur de `$AEGISAI_EXTERNAL_API_KEY`, puis :

```bash
cd frontend && python3 -m http.server 8080
# ouvrir http://localhost:8080
```

---

## Vérification rapide

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/chatbot/chat \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $AEGISAI_EXTERNAL_API_KEY" \
  -d '{"client_id": "site1", "message": "Quel est le statut des capteurs energy?"}'
```

---

## Stack technique

Python · FastAPI · Elasticsearch · Kibana · EMQX (MQTT) · Groq (LLaMA 3.3 70B) · Docker



