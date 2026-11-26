#!/usr/bin/env bash
# STEP 5: alerting. Installs scripts + systemd units; creates /etc/honeypot-alert.conf if missing.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with: sudo $0"; exit 1; }
SRC="$(cd "$(dirname "$0")/alerts" && pwd)"

for f in honeypot-alert honeypot-audit-watch honeypot-cowrie-watch honeypot-health honeypot-daily honeypot-contain; do
  install -m 755 -o root -g root "$SRC/$f" /usr/local/sbin/$f
done
install -d -m 755 /usr/local/share/honeypot
install -m 644 -o root -g root "$SRC/playbook.json" /usr/local/share/honeypot/playbook.json

if [[ ! -f /etc/honeypot-alert.conf ]]; then
  umask 077
  cat > /etc/honeypot-alert.conf <<EOF
# Honeypot alert channels. Root-only (mode 600): these are secrets.

# Discord: channel settings -> Integrations -> Webhooks -> Copy Webhook URL
DISCORD_WEBHOOK=""

# ntfy: subscribe to this topic in the ntfy app. Anyone who knows the
# topic name can read/send to it, so it's random and kept here only.
NTFY_SERVER="https://ntfy.sh"
NTFY_TOPIC="honeypot-$(openssl rand -hex 10)"
EOF
  chmod 600 /etc/honeypot-alert.conf
fi

cat > /etc/systemd/system/honeypot-audit-watch.service <<'EOF'
[Unit]
Description=Honeypot: alert on audit events (escape alarm)
After=auditd.service
Wants=auditd.service

[Service]
ExecStart=/usr/local/sbin/honeypot-audit-watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/honeypot-cowrie-watch.service <<'EOF'
[Unit]
Description=Honeypot: alert on attacker file uploads/downloads
After=docker.service

[Service]
ExecStart=/usr/local/sbin/honeypot-cowrie-watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/honeypot-health.service <<'EOF'
[Unit]
Description=Honeypot: health check

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-health
EOF

cat > /etc/systemd/system/honeypot-health.timer <<'EOF'
[Unit]
Description=Honeypot: health check every 2 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/honeypot-daily.service <<'EOF'
[Unit]
Description=Honeypot: daily heartbeat

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-daily
EOF

cat > /etc/systemd/system/honeypot-daily.timer <<'EOF'
[Unit]
Description=Honeypot: daily heartbeat at 09:00 UTC

[Timer]
OnCalendar=*-*-* 09:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-audit-watch.service honeypot-cowrie-watch.service honeypot-health.timer honeypot-daily.timer
systemctl --no-pager --no-legend list-timers 'honeypot-*'
systemctl is-active honeypot-audit-watch.service honeypot-cowrie-watch.service
echo "STEP 5 installed. Next: sudo nano /etc/honeypot-alert.conf  (paste Discord webhook)"
