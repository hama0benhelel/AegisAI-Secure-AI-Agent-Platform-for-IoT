"""
AegisAI - Monitoring Agent (v0: MQTT -> Elasticsearch bridge)

Subscribes to all sensor topics on EMQX and forwards each message
into Elasticsearch as a document.

Utilise le compte dédié "aegisai_agent" (least privilege) via es_auth.py,
au lieu d'un accès Elasticsearch anonyme/non authentifié.

Usage:
    pip install paho-mqtt requests
    export ES_USER=aegisai_agent
    export ES_PASSWORD=<mot_de_passe>
    python3 monitoring_agent.py
"""

import json
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

from es_auth import es_head, es_put, es_post

MQTT_HOST = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "sensors/#"

ES_INDEX = "aegisai-sensors"


def ensure_index():
    resp = es_head(f"/{ES_INDEX}")
    if resp.status_code == 404:
        mapping = {"mappings": {"properties": {
            "device_id": {"type": "keyword"}, "site": {"type": "keyword"},
            "sensor_type": {"type": "keyword"}, "value": {"type": "float"},
            "unit": {"type": "keyword"}, "status": {"type": "keyword"},
            "timestamp": {"type": "date"}, "ingested_at": {"type": "date"},
            "mqtt_topic": {"type": "keyword"}}}}
        r = es_put(f"/{ES_INDEX}", json=mapping)
        r.raise_for_status()
        print(f"[ES] Index '{ES_INDEX}' créé")
    else:
        print(f"[ES] Index '{ES_INDEX}' existe déjà")


def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connecté au broker (rc={rc}), souscription à {MQTT_TOPIC}")
    client.subscribe(MQTT_TOPIC, qos=1)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
    except json.JSONDecodeError:
        payload = {"raw_payload": msg.payload.decode("utf-8", errors="replace"),
                   "status": "malformed_payload"}

    payload["mqtt_topic"] = msg.topic
    payload["ingested_at"] = datetime.now(timezone.utc).isoformat()

    try:
        r = es_post(f"/{ES_INDEX}/_doc", json=payload)
        r.raise_for_status()
        print(f"  -> indexed: {msg.topic} | status={payload.get('status', 'ok')}")
    except Exception as e:
        print(f"[ES ERROR] {e}")


def main():
    ensure_index()

    client = mqtt.Client(client_id="aegisai-monitoring-agent")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)

    print("[Monitoring Agent] démarré, Ctrl+C pour arrêter")
    client.loop_forever()


if __name__ == "__main__":
    main()
