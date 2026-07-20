"""
AegisAI - Decision Agent (v0: recommendation engine)

Correspond à l'étape "Recommander" du pipeline OÉRIX : lit les détections
récentes (produites par le Detection Agent, indépendamment de tout champ
auto-déclaré), et demande à un LLM de formuler une recommandation
actionnable - PAS d'exécution ici, uniquement une proposition.

Ce n'est PAS le module qui parle au client (ça, c'est chatbot_orchestrator.py)
- c'est un service interne, appelé par le Gateway ou par le Chatbot quand
l'intent est "get_recommendation".

Usage:
    pip install fastapi uvicorn groq
    export GROQ_API_KEY=...
    export ES_USER=aegisai_agent
    export ES_PASSWORD=...
    uvicorn decision_agent:app --reload --port 8012
"""

import os
import json
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from groq import Groq

from es_auth import es_post
from security_rules import is_suspicious

GROQ_MODEL = "llama-3.3-70b-versatile"
DETECTIONS_INDEX = "aegisai-detections"
RECOMMENDATIONS_INDEX = "aegisai-recommendations"

client = Groq()
app = FastAPI(title="AegisAI Decision Agent")

SYSTEM_PROMPT = """Tu es le module de recommandation d'AegisAI, une plateforme
de supervision IoT. On te donne une liste d'événements de détection (anomalies,
tentatives d'injection, floods) pour un device donné.

Ton rôle : proposer UNE recommandation courte et actionnable pour l'opérateur
humain. Tu ne dois JAMAIS déclarer qu'une action a été exécutée - tu proposes
uniquement.

Réponds UNIQUEMENT avec un JSON valide :
{"recommendation": "<phrase courte, actionnable>", "severity": "low|medium|high", "suggested_action": "<ex: isolate_device, ignore, monitor_closer>"}
N'ajoute aucun texte avant ou après ce JSON.
"""


class RecommendRequest(BaseModel):
    device_id: str


def fetch_recent_detections(device_id: str, size: int = 20):
    query = {
        "size": size,
        "sort": [{"detected_at": "desc"}],
        "query": {"term": {"device_id": device_id}},
    }
    r = es_post(f"/{DETECTIONS_INDEX}/_search", json=query)
    r.raise_for_status()
    return [h["_source"] for h in r.json()["hits"]["hits"]]


@app.post("/recommend")
def recommend(req: RecommendRequest):
    # Défense en profondeur : ce endpoint peut être appelé directement (ex: via
    # le Gateway) sans passer par les vérifications du Chatbot. device_id lu
    # depuis Elasticsearch par l'appelant n'est pas une donnée de confiance.
    if is_suspicious(req.device_id):
        raise HTTPException(status_code=400,
                             detail="device_id refusé : motif suspect détecté.")

    detections = fetch_recent_detections(req.device_id)
    if not detections:
        return {"device_id": req.device_id, "recommendation": "Aucune anomalie récente détectée.",
                "severity": "low", "suggested_action": "none"}

    summary = json.dumps(detections, ensure_ascii=False)[:4000]  # borne la taille envoyée au LLM
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        max_tokens=200,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Détections récentes pour {req.device_id} : {summary}"},
        ],
    )
    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Réponse LLM invalide")

    record = {
        "device_id": req.device_id,
        "recommendation": parsed.get("recommendation"),
        "severity": parsed.get("severity", "low"),
        "suggested_action": parsed.get("suggested_action"),
        "based_on_detections": len(detections),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    es_post(f"/{RECOMMENDATIONS_INDEX}/_doc", json=record)
    return record


@app.get("/health")
def health():
    return {"status": "ok"}
