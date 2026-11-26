#!/usr/bin/env bash
# Creates .env with random passwords. Won't overwrite an existing one.
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] && { echo ".env already exists, not touching it."; exit 0; }
umask 077
r() { openssl rand -hex "$1"; }
cat > .env <<EOF
COWRIE_VERSION=3.1.7
ELASTIC_VERSION=9.5.6
PUBLIC_IP=203.0.113.10
WG_IP=10.99.0.1

ELASTIC_PASSWORD=$(r 16)
KIBANA_PASSWORD=$(r 16)
FILEBEAT_PASSWORD=$(r 16)
KIBANA_KEY_SECURITY=$(r 16)
KIBANA_KEY_SAVEDOBJECTS=$(r 16)
KIBANA_KEY_REPORTING=$(r 16)
EOF
chmod 600 .env
echo "Wrote .env (mode 600). Kibana login: user 'elastic', password = ELASTIC_PASSWORD in .env"
