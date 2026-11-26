#!/usr/bin/env bash
# Starts the stack, refusing if any safety layer is missing. No sudo needed.
set -euo pipefail
cd "$(dirname "$0")"
fail() { echo "REFUSING TO START: $*"; exit 1; }

[[ -f .env ]] || fail ".env missing; run ./gen-env.sh"
systemctl is-active --quiet cowrie-firewall.service || fail "cowrie-firewall.service not active (host/04-cowrie-firewall.sh)"
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || fail "gVisor runtime not registered (host/03-host-prep.sh)"
ss -Htln '( sport = :22 )' | grep -qE '(0\.0\.0\.0|\*|\[::\]):22' && fail "real sshd still listens on all interfaces (host/02-ssh-wireguard-only.sh)"
[[ "$(stat -c %u data/cowrie/var/log/cowrie)" == 64999 ]] || fail "data dirs not prepared (host/03-host-prep.sh)"
[[ -f /var/lib/honeypot-ssh-revert.job ]] && fail "SSH change not confirmed yet (sudo host/02-ssh-wireguard-only.sh --confirm)"

echo "All safety checks passed. Starting..."
docker compose up -d
echo
echo "ES + Kibana take 1-3 minutes on first start. Then run ./verify.sh"
