"""
AegisAI - Shared injection detection patterns

Utilisé par TOUT composant qui envoie du texte à un LLM ou l'affiche tel
quel : Chatbot (input utilisateur direct), Detection Agent (payloads IoT),
Decision Agent (données ré-injectées dans un prompt LLM).

Point clé : un champ qui a déjà traversé le pipeline (ex: device_id stocké
en base) N'EST PAS "de confiance" juste parce qu'il vient d'Elasticsearch -
il peut contenir le texte brut d'une attaque capturée plus tôt. Toute
donnée relue depuis la base doit repasser par sanitize_input() avant
d'atteindre un prompt LLM (indirect prompt injection - OWASP LLM01).
"""

import re

INJECTION_PATTERNS = [
    (r"(?i)drop\s+table", "sql_injection"),
    (r"(?i)union\s+select", "sql_injection"),
    (r"['\"]\s*;\s*--", "sql_injection"),
    (r"\{\{.*\}\}", "template_injection"),
    (r"\$\(.*\)", "command_injection"),
    (r"(?i)rm\s+-rf", "command_injection"),
    (r"<script.*?>", "xss_injection"),
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "prompt_injection"),
    (r"(?i)system\s*:\s*override", "prompt_injection"),
    (r"(?i)you\s+are\s+now\s+in\s+(developer|debug|admin)\s+mode", "prompt_injection"),
    (r"(?i)reveal\s+(your\s+)?(system\s+prompt|instructions)", "prompt_injection"),
]


def sanitize_input(text: str) -> list:
    """Retourne la liste des labels d'attaque détectés dans `text` (vide si sain)."""
    if not isinstance(text, str):
        return []
    return list({label for pattern, label in INJECTION_PATTERNS if re.search(pattern, text)})


def is_suspicious(text: str) -> bool:
    return len(sanitize_input(text)) > 0
