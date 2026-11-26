#!/usr/bin/env bash
# Creates the "Cowrie" data view in Kibana. Run once after Kibana is up. No sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
curl -fsS -u "elastic:$ELASTIC_PASSWORD" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "http://$WG_IP:5601/api/data_views/data_view" -d '{
    "override": true,
    "data_view": { "id": "cowrie", "name": "Cowrie", "title": "cowrie-*", "timeFieldName": "@timestamp" }
  }' >/dev/null
echo "Data view created. Open http://$WG_IP:5601 -> Discover -> 'Cowrie'"
