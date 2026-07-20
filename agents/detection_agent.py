"""
AegisAI - Detection Agent (v0: rule-based, independent analysis)

Contrairement au champ `status` auto-déclaré par le simulateur (ou par un
attaquant réel dans un vrai déploiement), cet agent analyse lui-même le
contenu et le comportement des événements, indépendamment de ce que la
source prétend être.

Trois familles de règles :
  1. Pattern-based  : détection d'injection (SQLi, command injection,
                       template injection, prompt injection) dans les
                       champs texte via regex.
  2. Rate-based      : flooding / DoS - trop de messages pour un même
                       device_id sur une fenêtre de temps glissante.
  3. Threshold-based : valeurs statistiquement aberrantes par sensor_type
                       (au-delà de N écarts-types de la moyenne observée).

Chaque détection produit un document dans un index séparé
`aegisai-detections`, avec le document source, les patterns/raisons
détectés et un risk_score - ceci reste distinct et traçable par rapport
au pipeline d'ingestion brut (`aegisai-sensors`).

Usage:
    pip install requests
    python3 detection_agent.py
"""

import re
import time
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone

from es_auth import es_head, es_put, es_post
from security_rules import INJECTION_PATTERNS

SOURCE_INDEX = "aegisai-sensors"
DETECTIONS_INDEX = "aegisai-detections"

POLL_INTERVAL_SECONDS = 5
RATE_WINDOW_SECONDS = 10
RATE_THRESHOLD = 15          # + de 15 messages/device sur la fenêtre = flood
OUTLIER_STD_MULTIPLIER = 4   # valeur au-delà de 4x l'écart-type = anomalie
MIN_SAMPLES_FOR_BASELINE = 10

# --- Patterns d'injection : voir security_rules.py (partagé avec Chatbot et Decision Agent) ---

# état en mémoire (fenêtre glissante par device + baseline statistique par sensor_type)
device_timestamps = defaultdict(lambda: deque())
sensor_baselines = defaultdict(lambda: deque(maxlen=200))

last_processed_ts = None


def es_query(query, size=200):
    r = es_post(f"/{SOURCE_INDEX}/_search", json=query, timeout=10)
    r.raise_for_status()
    return r.json()["hits"]["hits"]


def ensure_detections_index():
    resp = es_head(f"/{DETECTIONS_INDEX}")
    if resp.status_code == 404:
        mapping = {"mappings": {"properties": {
            "device_id": {"type": "keyword"},
            "sensor_type": {"type": "keyword"},
            "site": {"type": "keyword"},
            "reasons": {"type": "keyword"},
            "risk_score": {"type": "integer"},
            "source_doc_id": {"type": "keyword"},
            "detected_at": {"type": "date"},
        }}}
        es_put(f"/{DETECTIONS_INDEX}", json=mapping).raise_for_status()
        print(f"[ES] Index '{DETECTIONS_INDEX}' créé")


def scan_text_fields_for_injection(doc):
    """Cherche des patterns d'injection dans TOUS les champs texte du document,
    sans se fier au champ status déclaré par la source."""
    reasons = []
    for key, value in doc.items():
        if not isinstance(value, str):
            continue
        for pattern, label in INJECTION_PATTERNS:
            if re.search(pattern, value):
                reasons.append(label)
    return list(set(reasons))


def check_rate_limit(doc, now_ts):
    """Flood detection : fenêtre glissante par device_id."""
    device_id = str(doc.get("device_id", "unknown"))
    dq = device_timestamps[device_id]
    dq.append(now_ts)
    while dq and now_ts - dq[0] > RATE_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) > RATE_THRESHOLD:
        return True, len(dq)
    return False, len(dq)


def check_outlier(doc):
    """Anomalie statistique : valeur trop loin de la baseline observée pour ce sensor_type."""
    sensor_type = doc.get("sensor_type")
    value = doc.get("value")
    if sensor_type is None or not isinstance(value, (int, float)):
        return False

    baseline = sensor_baselines[sensor_type]
    is_outlier = False

    if len(baseline) >= MIN_SAMPLES_FOR_BASELINE:
        mean = statistics.mean(baseline)
        stdev = statistics.pstdev(baseline) or 0.01
        if abs(value - mean) > OUTLIER_STD_MULTIPLIER * stdev:
            is_outlier = True

    # on n'ajoute à la baseline que les valeurs déjà jugées "normales"
    # (sinon une attaque massive pollue la baseline elle-même)
    if not is_outlier:
        baseline.append(value)

    return is_outlier


def index_detection(doc, doc_id, reasons, risk_score):
    detection = {
        "device_id": doc.get("device_id"),
        "sensor_type": doc.get("sensor_type"),
        "site": doc.get("site"),
        "reasons": reasons,
        "risk_score": risk_score,
        "source_doc_id": doc_id,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        r = es_post(f"/{DETECTIONS_INDEX}/_doc", json=detection)
        r.raise_for_status()
        print(f"  [ALERT] device={detection['device_id']} reasons={reasons} risk={risk_score}")
    except Exception as e:
        print(f"[ES ERROR] {e}")


def process_document(hit):
    doc = hit["_source"]
    doc_id = hit["_id"]
    now_ts = time.time()

    reasons = []
    risk_score = 0

    injection_reasons = scan_text_fields_for_injection(doc)
    if injection_reasons:
        reasons.extend(injection_reasons)
        risk_score += 40 * len(injection_reasons)

    is_flood, count_in_window = check_rate_limit(doc, now_ts)
    if is_flood:
        reasons.append("rate_flood")
        risk_score += 30

    if check_outlier(doc):
        reasons.append("statistical_outlier")
        risk_score += 25

    if reasons:
        risk_score = min(risk_score, 100)
        index_detection(doc, doc_id, reasons, risk_score)


def poll_loop():
    global last_processed_ts
    print("[Detection Agent] démarré (polling Elasticsearch)")

    while True:
        query = {
            "size": 200,
            "sort": [{"ingested_at": "asc"}],
            "query": {
                "range": {
                    "ingested_at": {"gt": last_processed_ts or "now-1m"}
                }
            },
        }
        try:
            hits = es_query(query)
            for hit in hits:
                process_document(hit)
                last_processed_ts = hit["_source"].get("ingested_at", last_processed_ts)
        except Exception as e:
            print(f"[POLL ERROR] {e}")

        time.sleep(POLL_INTERVAL_SECONDS)


def main():
    ensure_detections_index()
    poll_loop()


if __name__ == "__main__":
    main()
