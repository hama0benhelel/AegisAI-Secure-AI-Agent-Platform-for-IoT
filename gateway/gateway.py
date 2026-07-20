"""
AegisAI - API Gateway (v0)

Point d'entrée UNIQUE pour tous les clients externes. Au lieu que chaque
agent gère sa propre authentification/rate-limiting (duplication), le
Gateway centralise ces contrôles une seule fois, puis transmet (proxy)
la requête vers l'agent interne concerné.

Ceci correspond à la couche "API Gateway" du schéma d'architecture
(Frontend -> API Gateway -> Orchestrator -> Agents -> DB commune).

Contrôles appliqués ICI, avant que quoi que ce soit n'atteigne un agent :
  - Authentification (clé API externe, différente de la clé interne
    utilisée entre agents)
  - Rate limiting global (protège tous les agents, pas juste le chatbot)
  - Logging centralisé de chaque requête (audit trail unique)

Usage:
    pip install fastapi uvicorn httpx slowapi
    export AEGISAI_EXTERNAL_API_KEY=<clé donnée aux clients externes>
    export AEGISAI_INTERNAL_API_KEY=<même clé que chatbot_orchestrator.py>
    uvicorn gateway:app --reload --port 8000
"""

import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends, Response
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
  # <- déjà utilisé côté chatbot/decision
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parent.parent / "agents"))

from security_rules import is_suspicious 
from es_auth import es_post

app = FastAPI(title="AegisAI API Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev uniquement - restreindre au domaine du front en prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Registre des agents internes (le Gateway est le SEUL point qui les connaît) ---
AGENT_REGISTRY = {
    "chatbot": "http://localhost:8010",
    "decision": "http://localhost:8012",
    "response": "http://localhost:8013",
    # "monitoring": "http://localhost:8001",
    # "detection":  "http://localhost:8002",
}

INTERNAL_API_KEY = os.environ.get("AEGISAI_INTERNAL_API_KEY")   # transmis aux agents internes
EXTERNAL_API_KEY = os.environ.get("AEGISAI_EXTERNAL_API_KEY")   # exigé des clients externes
GATEWAY_LOG_INDEX = "aegisai-gateway-events"

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return HTTPException(status_code=429, detail="Trop de requêtes, réessayez plus tard.")


external_api_key_header = APIKeyHeader(name="X-Api-Key", auto_error=False)

if not EXTERNAL_API_KEY:
    print("[WARN] AEGISAI_EXTERNAL_API_KEY non défini - Gateway accessible SANS clé externe.")
if not INTERNAL_API_KEY:
    print("[WARN] AEGISAI_INTERNAL_API_KEY non défini - impossible de s'authentifier auprès des agents.")


def require_external_key(provided: str = Depends(external_api_key_header)):
    if EXTERNAL_API_KEY and provided != EXTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Clé API invalide ou manquante.")


def log_request(client_ip: str, path: str, agent: str, status_code: int):
    try:
        es_post(f"/{GATEWAY_LOG_INDEX}/_doc", json={
            "client_ip": client_ip,
            "path": path,
            "target_agent": agent,
            "status_code": status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        print(f"[ES ERROR] {e}")


@app.post("/api/{agent_name}/{path:path}")
@limiter.limit("30/minute")   # limite globale, plus large que celle du chatbot seul
async def proxy(agent_name: str, path: str, request: Request,
                 _: None = Depends(require_external_key)):
    if agent_name not in AGENT_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Agent inconnu : {agent_name}")

    target_base = AGENT_REGISTRY[agent_name]
    body = await request.body()

    async with httpx.AsyncClient() as http_client:
        try:
            response = await http_client.post(
                f"{target_base}/{path}",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Internal-Api-Key": INTERNAL_API_KEY or "",
                },
                timeout=15,
            )
        except httpx.RequestError as e:
            log_request(request.client.host, path, agent_name, 502)
            raise HTTPException(status_code=502, detail=f"Agent '{agent_name}' injoignable : {e}")

    log_request(request.client.host, path, agent_name, response.status_code)
    return Response(status_code=response.status_code, content=response.content,
                     media_type="application/json")


@app.get("/api/{agent_name}/{path:path}")
@limiter.limit("30/minute")
async def proxy_get(agent_name: str, path: str, request: Request,
                     _: None = Depends(require_external_key)):
    if agent_name not in AGENT_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Agent inconnu : {agent_name}")

    target_base = AGENT_REGISTRY[agent_name]

    async with httpx.AsyncClient() as http_client:
        try:
            response = await http_client.get(
                f"{target_base}/{path}",
                headers={"X-Internal-Api-Key": INTERNAL_API_KEY or ""},
                timeout=15,
            )
        except httpx.RequestError as e:
            log_request(request.client.host, path, agent_name, 502)
            raise HTTPException(status_code=502, detail=f"Agent '{agent_name}' injoignable : {e}")

    log_request(request.client.host, path, agent_name, response.status_code)
    return Response(status_code=response.status_code, content=response.content,
                     media_type="application/json")


@app.get("/stats")
def stats(_: None = Depends(require_external_key)):
    """Agrégations pour le dashboard front-end - le navigateur ne parle
    jamais directement à Elasticsearch, ni ne détient ses identifiants."""

    def count(index, query=None):
        try:
            body = {"query": query} if query else {"query": {"match_all": {}}}
            r = es_post(f"/{index}/_count", json=body)
            return r.json().get("count", 0) if r.status_code == 200 else 0
        except Exception:
            return 0

    def agg_by(index, field, size=10):
        try:
            body = {"size": 0, "aggs": {"by_field": {"terms": {"field": field, "size": size}}}}
            r = es_post(f"/{index}/_search", json=body)
            if r.status_code != 200:
                return []
            buckets = r.json()["aggregations"]["by_field"]["buckets"]
            return [{"key": b["key"], "count": b["doc_count"]} for b in buckets]
        except Exception:
            return []

    return {
        "total_events": count("aegisai-sensors"),
        "total_detections": count("aegisai-detections"),
        "pending_approvals": count("aegisai-pending-approvals", {"term": {"status.keyword": "pending"}}),
        "events_by_status": agg_by("aegisai-sensors", "status"),
        "detections_by_reason": agg_by("aegisai-detections", "reasons"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "registered_agents": list(AGENT_REGISTRY.keys())}



@app.get("/devices")
def devices(_: None = Depends(require_external_key)):
    """Liste des devices connus, dérivée du dernier document reçu par
    device_id dans aegisai-sensors (pas de collection 'devices' dédiée)."""
    try:
        body = {
            "size": 0,
            "aggs": {
                "by_device": {
                    "terms": {"field": "device_id.keyword", "size": 500},
                    "aggs": {
                        "latest": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "_source": ["device_id", "site", "sensor_type",
                                            "status", "value", "unit", "timestamp"]
                            }
                        }
                    }
                }
            }
        }
        r = es_post("/aegisai-sensors/_search", json=body)
        if r.status_code != 200:
            # Avant: on renvoyait [] silencieusement ici, ce qui rend le bug
            # invisible côté frontend ("Aucun device trouvé" alors que c'est
            # en fait une erreur de requête ES : mapping, champ manquant, etc.)
            print(f"[ES ERROR] /devices _search failed: {r.status_code} - {r.text}")
            raise HTTPException(
                status_code=502,
                detail=f"Requête Elasticsearch échouée ({r.status_code}): {r.text[:300]}"
            )
 
        buckets = r.json().get("aggregations", {}).get("by_device", {}).get("buckets", [])
        if not buckets:
            print("[DEBUG] /devices: _search a réussi mais 0 buckets. "
                  "Vérifie que 'device_id.keyword' existe (GET /aegisai-sensors/_mapping) "
                  "et que l'index n'est pas vide.")
        now = datetime.now(timezone.utc)
        devices_out = []
 
        for b in buckets:
            hits = b["latest"]["hits"]["hits"]
            if not hits:
                continue
            src = hits[0]["_source"]
            raw_device_id = src.get("device_id", b["key"])
 
            # Un device_id qui matche les patterns d'injection ne doit jamais
            # être réaffiché brut à un opérateur dans le dashboard.
            suspicious = is_suspicious(raw_device_id)
 
            # "Online/Offline" = fraîcheur de la dernière lecture, pas le champ
            # status auto-déclaré (même principe que le Detection Agent :
            # on ne fait jamais confiance à une source pour dire d'elle-même
            # qu'elle va bien).
            last_seen_raw = src.get("timestamp")
            connectivity = "unknown"
            if last_seen_raw:
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                    connectivity = "online" if (now - last_seen_dt).total_seconds() < 300 else "offline"
                except Exception:
                    connectivity = "unknown"
 
            devices_out.append({
                "device_id": "[identifiant suspect masqué]" if suspicious else raw_device_id,
                "site": src.get("site", "—"),
                "type": src.get("sensor_type", "—"),
                "status": connectivity,          # online / offline / unknown -> badge principal
                "last_status": src.get("status"),  # ok / anomalous_value / suspicious_payload / flood_test
                "last_value": src.get("value"),
                "unit": src.get("unit"),
                "last_seen": last_seen_raw,
                "suspicious": suspicious,
            })
 
        # Devices suspects en premier (plus utile pour un opérateur qui scanne la liste)
        devices_out.sort(key=lambda d: (not d["suspicious"], d["device_id"]))
        return devices_out
 
    except Exception as e:
        print(f"[ES ERROR] /devices: {e}")
        raise HTTPException(status_code=502,
                             detail="Impossible de récupérer la liste des devices depuis Elasticsearch.")
