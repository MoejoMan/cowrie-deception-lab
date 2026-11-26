#!/usr/bin/env bash
# STEP 4: block ALL new connections originating from the Cowrie network (br-cowrie):
#   - to the internet          (FORWARD, via Docker's DOCKER-USER chain)
#   - to this host's services  (INPUT: Unbound, CrowdSec API, sshd on wg0, ES, Kibana...)
# Replies to attackers' inbound connections are still allowed (ESTABLISHED).
# Installed as a systemd unit that runs BEFORE docker, so Cowrie never starts unprotected.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with: sudo $0"; exit 1; }

cat > /usr/local/sbin/cowrie-firewall <<'EOF'
#!/bin/sh
# Egress lockdown for the Cowrie honeypot bridge. Idempotent.
set -eu
BR=br-cowrie
for ipt in iptables ip6tables; do
  $ipt -N COWRIE-EGRESS 2>/dev/null || $ipt -F COWRIE-EGRESS
  $ipt -A COWRIE-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  $ipt -A COWRIE-EGRESS -m limit --limit 6/min -j LOG --log-prefix "cowrie-egress-drop: "
  $ipt -A COWRIE-EGRESS -j DROP

  # Inbound fairness: max 10 simultaneous connections per attacker IP, so one
  # noisy bot can't exhaust Cowrie (256 MB / 128 processes) and lock others out.
  # DROP, not REJECT: after Docker's DNAT a reset would come from the container's
  # internal address and be ignored anyway; dropped SYNs just make the bot wait.
  $ipt -N COWRIE-INBOUND 2>/dev/null || $ipt -F COWRIE-INBOUND
  $ipt -A COWRIE-INBOUND -p tcp --syn --dport 2222 -m connlimit --connlimit-above 10 \
       -m limit --limit 6/min -j LOG --log-prefix "cowrie-connlimit: "
  $ipt -A COWRIE-INBOUND -p tcp --syn --dport 2222 -m connlimit --connlimit-above 10 \
       -j DROP

  $ipt -N DOCKER-USER 2>/dev/null || true
  $ipt -C DOCKER-USER -o $BR -j COWRIE-INBOUND 2>/dev/null || $ipt -I DOCKER-USER 1 -o $BR -j COWRIE-INBOUND
  $ipt -C DOCKER-USER -i $BR -j COWRIE-EGRESS 2>/dev/null || $ipt -I DOCKER-USER 1 -i $BR -j COWRIE-EGRESS
  $ipt -C INPUT       -i $BR -j COWRIE-EGRESS 2>/dev/null || $ipt -I INPUT       1 -i $BR -j COWRIE-EGRESS
done
EOF
chmod 755 /usr/local/sbin/cowrie-firewall

cat > /etc/systemd/system/cowrie-firewall.service <<'EOF'
[Unit]
Description=Block outbound traffic from the Cowrie honeypot network
Before=docker.service
DefaultDependencies=no
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/cowrie-firewall

[Install]
WantedBy=docker.service multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cowrie-firewall.service
# Re-apply now too, in case docker was already running
/usr/local/sbin/cowrie-firewall

echo "== rules in place:"
iptables -S COWRIE-EGRESS
iptables -S DOCKER-USER | grep br-cowrie
iptables -S INPUT | grep br-cowrie
echo "STEP 4 done."
