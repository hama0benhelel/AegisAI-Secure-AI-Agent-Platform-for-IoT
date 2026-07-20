"""
AegisAI - Shared Elasticsearch auth helper

Tous les agents (Monitoring, Detection, Chatbot) utilisent ce module pour
parler à Elasticsearch - avec le compte dédié "aegisai_agent" (least
privilege), jamais le superuser "elastic".

Si ES_USER/ES_PASSWORD ne sont pas définis, on retombe sur un mode "no
auth" (utile en dev tant que la sécurité ES n'est pas encore activée),
mais un warning est affiché pour que ça ne parte pas en prod comme ça.
"""

import os
import requests

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER")
ES_PASSWORD = os.environ.get("ES_PASSWORD")

if not ES_USER or not ES_PASSWORD:
    print("[WARN] ES_USER/ES_PASSWORD non définis - appels Elasticsearch SANS authentification. "
          "À corriger avant tout déploiement au-delà du poste de dev.")

_AUTH = (ES_USER, ES_PASSWORD) if (ES_USER and ES_PASSWORD) else None


def es_get(path: str, **kwargs):
    return requests.get(f"{ES_HOST}{path}", auth=_AUTH, timeout=kwargs.pop("timeout", 5), **kwargs)


def es_head(path: str, **kwargs):
    return requests.head(f"{ES_HOST}{path}", auth=_AUTH, timeout=kwargs.pop("timeout", 5), **kwargs)


def es_put(path: str, json=None, **kwargs):
    return requests.put(f"{ES_HOST}{path}", auth=_AUTH, json=json, timeout=kwargs.pop("timeout", 5), **kwargs)


def es_post(path: str, json=None, **kwargs):
    return requests.post(f"{ES_HOST}{path}", auth=_AUTH, json=json, timeout=kwargs.pop("timeout", 5), **kwargs)
