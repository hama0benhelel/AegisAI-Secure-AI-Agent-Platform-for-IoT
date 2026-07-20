"""
AegisAI - Response Agent (v0: execution)

Correspond à l'étape "Planifier / Exécuter" du pipeline OÉRIX. Ce service
NE reçoit JAMAIS de requête directement d'un client - il n'est appelé que
par le Chatbot/Orchestrator APRÈS qu'une action critique a été approuvée
par un humain (voir /approve dans chatbot_orchestrator.py).

Simule une action physique (isoler un device, le remettre en ligne) en
maintenant un état par device dans Elasticsearch - suffisant pour une
démo/PFA sans accès à du matériel réel.

Usage:
    pip install fastapi uvicorn
    export ES_USER=aegisai_agent
    export ES_PASSWORD=...
    uvicorn response_agent:app --reload --port 8013
"""

from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

from es_auth import es_post, es_head, es_put

DEVICE_STATE_INDEX = "aegisai-device-states"
ACTIONS_LOG_INDEX = "aegisai-executed-actions"

app = FastAPI(title="AegisAI Response Agent")

VALID_ACTIONS = {"isolate_device", "restore_device", "ignore", "monitor_closer"}


def ensure_index():
    resp = es_head(f"/{DEVICE_STATE_INDEX}")
    if resp.status_code == 404:
        mapping = {"mappings": {"properties": {
            "device_id": {"type": "keyword"},
            "state": {"type": "keyword"},
            "updated_at": {"type": "date"},
        }}}
        es_put(f"/{DEVICE_STATE_INDEX}", json=mapping)


class ExecuteRequest(BaseModel):
    approval_id: str
    device_id: str
    action: str
    reviewer: str


@app.on_event("startup")
def startup():
    ensure_index()


@app.post("/execute")
def execute(req: ExecuteRequest):
    action = req.action if req.action in VALID_ACTIONS else "monitor_closer"
    now = datetime.now(timezone.utc).isoformat()

    new_state = {
        "isolate_device": "isolated",
        "restore_device": "online",
        "ignore": "online",
        "monitor_closer": "watched",
    }[action]

    es_post(f"/{DEVICE_STATE_INDEX}/_doc", json={
        "device_id": req.device_id, "state": new_state, "updated_at": now,
    })

    es_post(f"/{ACTIONS_LOG_INDEX}/_doc", json={
        "approval_id": req.approval_id, "device_id": req.device_id,
        "action": action, "reviewer": req.reviewer, "executed_at": now,
    })

    return {"device_id": req.device_id, "action": action, "new_state": new_state, "executed_at": now}


@app.get("/health")
def health():
    return {"status": "ok"}
