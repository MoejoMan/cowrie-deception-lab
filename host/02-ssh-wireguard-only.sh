#!/usr/bin/env bash
# STEP 2: real SSH listens ONLY on WireGuard (10.99.0.1:22), freeing public :22 for Cowrie.
#
# Ubuntu 24.04 starts sshd from ssh.socket, so ListenAddress in sshd_config is ignored;
# we override the socket instead.
#
# DEAD-MAN SWITCH: the change auto-reverts after 10 minutes unless you confirm with
#   sudo ./02-ssh-wireguard-only.sh --confirm
# from a NEW ssh session to admin@10.99.0.1. Your current session stays connected either way.
#
# If everything goes wrong anyway: your provider's cloud console -> server -> Console (web VNC),
# log in as admin with your password, run  sudo /usr/local/sbin/honeypot-ssh-revert
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with: sudo $0"; exit 1; }

WG_IP=10.99.0.1
SOCK_DROPIN=/etc/systemd/system/ssh.socket.d/10-wireguard-only.conf
SSHD_DROPIN=/etc/ssh/sshd_config.d/10-honeypot-host.conf
REVERT=/usr/local/sbin/honeypot-ssh-revert
JOBFILE=/var/lib/honeypot-ssh-revert.job

if [[ "${1:-}" == "--confirm" ]]; then
  if [[ -f $JOBFILE ]]; then
    atrm "$(cat "$JOBFILE")" 2>/dev/null && echo "Auto-revert cancelled. SSH is now WireGuard-only for good."
    rm -f "$JOBFILE"
  else
    echo "No pending auto-revert found."
  fi
  exit 0
fi

echo "== pre-flight checks"
ip -4 addr show wg0 | grep -q "inet $WG_IP/" || { echo "wg0 does not have $WG_IP. Aborting."; exit 1; }
systemctl is-enabled --quiet wg-quick@wg0 || { echo "wg-quick@wg0 is not enabled at boot. Aborting (you'd be locked out after a reboot)."; exit 1; }
ss -Htn state established '( sport = :22 )' | grep -q ' 10\.66\.66\.' \
  || { echo "You are not currently connected over WireGuard. Connect via admin@$WG_IP first. Aborting."; exit 1; }
systemctl is-active --quiet atd || { echo "atd not running (needed for auto-revert). Aborting."; exit 1; }
echo "   ok: wg0 up, enabled at boot, you're connected over the VPN"

echo "== install revert helper ($REVERT)"
cat > "$REVERT" <<EOF
#!/bin/sh
# Undo honeypot step 2: SSH listens on all interfaces again.
rm -f $SOCK_DROPIN $SSHD_DROPIN
systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh.service
rm -f $JOBFILE
logger -t honeypot "SSH WireGuard-only change reverted"
EOF
chmod 700 "$REVERT"

echo "== sshd hardening ($SSHD_DROPIN)"
cat > "$SSHD_DROPIN" <<'EOF'
# Honeypot host hardening. Files in sshd_config.d are read first, so these win.
AllowUsers admin
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF
sshd -t || { echo "sshd config test failed. Removing drop-in."; rm -f "$SSHD_DROPIN"; exit 1; }

echo "== socket override ($SOCK_DROPIN)"
mkdir -p "$(dirname "$SOCK_DROPIN")"
cat > "$SOCK_DROPIN" <<EOF
[Socket]
# Clear the default 0.0.0.0:22 and [::]:22 listeners
ListenStream=
# Listen on the WireGuard address only (FreeBind=yes in the base unit
# lets this bind at boot even if wg0 comes up slightly later)
ListenStream=$WG_IP:22
EOF

echo "== arm auto-revert in 10 minutes"
job=$(echo "$REVERT" | at now + 10 minutes 2>&1 | awk '/^job/ {print $2}')
echo "$job" > "$JOBFILE"
echo "   at job $job"

echo "== apply"
systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh.service

echo "== listening now:"
ss -Htln '( sport = :22 )'

cat <<EOF

NEXT (within 10 minutes):
  1. Keep this session open.
  2. Open a NEW terminal and run:  ssh admin@$WG_IP
  3. If that works, in the new session run:
       sudo ~/honeypot/host/02-ssh-wireguard-only.sh --confirm
  If you do nothing, it reverts automatically at job $job.
EOF
