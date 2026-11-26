#!/usr/bin/env bash
# One-shot ES setup, run by the es-setup container. Safe to re-run (all PUTs).
set -euo pipefail
ES=http://es:9200

c() {
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"
  echo
}

echo "== kibana_system password"
c -X POST "$ES/_security/user/kibana_system/_password" -d "{\"password\":\"${KIBANA_PASSWORD}\"}"

echo "== cowrie_writer role (write-only to cowrie-*)"
c -X PUT "$ES/_security/role/cowrie_writer" -d '{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["cowrie-*"],
    "privileges": ["create_doc", "create_index", "view_index_metadata", "auto_configure"]
  }]
}'

echo "== filebeat_cowrie user"
c -X PUT "$ES/_security/user/filebeat_cowrie" -d "{\"password\":\"${FILEBEAT_PASSWORD}\",\"roles\":[\"cowrie_writer\"]}"

echo "== retention: delete daily indices after 60 days"
c -X PUT "$ES/_ilm/policy/cowrie-retention" -d '{
  "policy": { "phases": {
    "hot":    { "actions": {} },
    "delete": { "min_age": "60d", "actions": { "delete": {} } }
  }}
}'

echo "== ingest pipeline: event time, GeoIP, ASN"
c -X PUT "$ES/_ingest/pipeline/cowrie-enrich" -d '{
  "description": "Cowrie: keep raw line, use event timestamp, add GeoIP + ASN for attacker IP",
  "processors": [
    { "rename": { "field": "message", "target_field": "event.original", "ignore_missing": true } },
    { "date":  { "field": "cowrie.timestamp", "formats": ["ISO8601"], "target_field": "@timestamp", "ignore_failure": true } },
    { "geoip": { "field": "cowrie.src_ip", "target_field": "source.geo", "ignore_missing": true } },
    { "geoip": { "field": "cowrie.src_ip", "target_field": "source.as", "database_file": "GeoLite2-ASN.mmdb",
                 "properties": ["asn", "organization_name"], "ignore_missing": true } },
    { "set":   { "field": "event.ingested", "value": "{{{_ingest.timestamp}}}" } }
  ]
}'

echo "== index template for cowrie-*"
c -X PUT "$ES/_index_template/cowrie" -d '{
  "index_patterns": ["cowrie-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "cowrie-retention",
      "index.default_pipeline": "cowrie-enrich"
    },
    "mappings": {
      "dynamic_templates": [
        { "strings_as_keyword": { "match_mapping_type": "string",
                                  "mapping": { "type": "keyword", "ignore_above": 1024 } } }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "cowrie": { "properties": {
          "src_ip":   { "type": "ip" },
          "dst_ip":   { "type": "ip" },
          "src_port": { "type": "integer" },
          "dst_port": { "type": "integer" },
          "message":  { "type": "text" },
          "input":    { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 2048 } } }
        } },
        "event": { "properties": {
          "original": { "type": "keyword", "index": false, "doc_values": false }
        } },
        "source": { "properties": {
          "geo": { "properties": { "location": { "type": "geo_point" } } }
        } }
      }
    }
  }
}'

echo "== setup complete"
