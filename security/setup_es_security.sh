#!/usr/bin/env bash
#
# AegisAI - Setup script for Elasticsearch security (least privilege agent account)
#
# Prérequis : Elasticsearch doit tourner avec la sécurité activée
# (xpack.security.enabled=true) et un mot de passe défini pour le
# superuser "elastic" (voir instructions plus bas).
#
# Ce script crée :
#   1. Un rôle "aegisai_agent_role" limité aux index aegisai-* uniquement
#      (pas d'accès aux autres index du cluster, pas de droits admin/cluster)
#   2. Un utilisateur "aegisai_agent" avec ce rôle, utilisé par TOUS les
#      agents Python (Monitoring, Detection, Chatbot) - identité dédiée,
#      distincte du superuser "elastic".
#
# Usage:
#   export ELASTIC_PASSWORD=<mot_de_passe_superuser>
#   export AEGISAI_AGENT_PASSWORD=<nouveau_mot_de_passe_pour_les_agents>
#   ./setup_es_security.sh

set -euo pipefail

ES_HOST="http://localhost:9200"
ELASTIC_PASSWORD="bws123"
AEGISAI_AGENT_PASSWORD="bwsbws"

echo "[1/2] Création du rôle 'aegisai_agent_role' (accès limité aux index aegisai-*)..."
curl -s -k -u "elastic:${ELASTIC_PASSWORD}" -X PUT "${ES_HOST}/_security/role/aegisai_agent_role" \
  -H "Content-Type: application/json" -d '{
    "indices": [
      {
        "names": ["aegisai-*"],
        "privileges": ["read", "write", "create_index", "view_index_metadata"]
      }
    ],
    "cluster": []
  }' | jq .

echo "[2/2] Création de l'utilisateur 'aegisai_agent'..."
curl -s -k -u "elastic:${ELASTIC_PASSWORD}" -X PUT "${ES_HOST}/_security/user/aegisai_agent" \
  -H "Content-Type: application/json" -d "{
    \"password\": \"${AEGISAI_AGENT_PASSWORD}\",
    \"roles\": [\"aegisai_agent_role\"],
    \"full_name\": \"AegisAI Agents (Monitoring/Detection/Chatbot)\"
  }" | jq .

echo ""
echo "Terminé. Les agents doivent maintenant utiliser :"
echo "  ES_USER=aegisai_agent"
echo "  ES_PASSWORD=${AEGISAI_AGENT_PASSWORD}"
echo ""
echo "Ce compte NE PEUT PAS créer d'autres utilisateurs/rôles, ni accéder aux"
echo "index hors 'aegisai-*' - c'est le principe de moindre privilège appliqué."
