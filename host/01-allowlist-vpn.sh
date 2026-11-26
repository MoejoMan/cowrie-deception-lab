#!/usr/bin/env bash
# STEP 1: make sure fail2ban and sshguard can never ban your own WireGuard IPs.
# Must run BEFORE step 2: once SSH is VPN-only, banning 10.99.0.2 = locked out.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with: sudo $0"; exit 1; }

VPN_NET=10.99.0.0/24

echo "== fail2ban: add $VPN_NET to ignoreip"
if grep -qE "^\s*ignoreip.*10\.66\.66\.0/24" /etc/fail2ban/jail.local; then
  echo "   already present"
else
  cp -a /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak.$(date +%F)
  sed -i -E "s|^(\s*ignoreip\s*=.*)$|\1 $VPN_NET|" /etc/fail2ban/jail.local
fi
grep -E '^\s*ignoreip' /etc/fail2ban/jail.local
fail2ban-client -t >/dev/null && systemctl restart fail2ban

echo "== sshguard: whitelist $VPN_NET"
grep -qxF "$VPN_NET" /etc/sshguard/whitelist || echo "$VPN_NET" >> /etc/sshguard/whitelist
systemctl restart sshguard

echo "== check nothing currently bans the VPN range"
fail2ban-client status sshd | grep -E 'Banned IP list' || true

echo "STEP 1 done."
