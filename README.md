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

