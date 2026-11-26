#!/usr/bin/env bash
# STEP 3: gVisor, Docker hardening, auditd, auto security reboots, sudoers check, data dirs.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with: sudo $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
HONEYPOT="$(dirname "$HERE")"
COWRIE_UID=64999

echo "== 1/7 packages"
apt-get update -qq
apt-get install -y -qq auditd curl gnupg ca-certificates >/dev/null

echo "== 2/7 gVisor (runsc) from the official repo"
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -qq
  apt-get install -y -qq runsc >/dev/null
fi
runsc --version | head -1
runsc install          # registers the "runsc" runtime in /etc/docker/daemon.json

echo "== 3/7 Docker daemon hardening"
python3 - <<'PY'
import json, pathlib
p = pathlib.Path("/etc/docker/daemon.json")
cfg = json.loads(p.read_text()) if p.exists() and p.read_text().strip() else {}
cfg.update({
    "no-new-privileges": True,     # default for every container
    "live-restore": True,          # containers survive a dockerd restart
    "userland-proxy": False,       # no docker-proxy processes; pure iptables DNAT
    "log-driver": "json-file",
    "log-opts": {"max-size": "10m", "max-file": "3"},
})
p.write_text(json.dumps(cfg, indent=2) + "\n")
print(p.read_text())
PY

# Docker must start after WireGuard, since Kibana's port is bound to 10.99.0.1
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/10-after-wireguard.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
systemctl daemon-reload
systemctl restart docker

echo "== 4/7 test gVisor actually works"
out=$(docker run --rm --runtime=runsc --network none cowrie/cowrie:3.1.7 \
        -c "print(open('/proc/version').read())" 2>&1) || { echo "$out"; echo "gVisor test FAILED"; exit 1; }
echo "   sandbox kernel says: $out"
echo "$out" | grep -qi 'linux version 4.4.0' && echo "   ok: running under gVisor" \
  || echo "   WARNING: unexpected output, check gVisor manually"

echo "== 5/7 honeypot data dirs (owned by uid $COWRIE_UID, not you)"
V="$HONEYPOT/data/cowrie/var"
install -d -o $COWRIE_UID -g $COWRIE_UID -m 755 "$V" "$V/log" "$V/log/cowrie"   # Filebeat needs to read log/cowrie
install -d -o $COWRIE_UID -g $COWRIE_UID -m 700 "$V/lib" "$V/lib/cowrie"        # host keys, tty logs, malware uploads
# Cowrie does NOT create these itself; without them uploads crash and are lost.
install -d -o $COWRIE_UID -g $COWRIE_UID -m 700 "$V/lib/cowrie/downloads" "$V/lib/cowrie/tty"
install -d -o $COWRIE_UID -g $COWRIE_UID -m 700 "$V/run"

echo "== 6/7 auditd rules"
install -m 640 "$HERE/audit/honeypot.rules" /etc/audit/rules.d/honeypot.rules
augenrules --load >/dev/null
systemctl enable --now auditd >/dev/null
auditctl -l | grep -cE 'key=|-k ' | xargs echo "   active audit rules:"

echo "== 7/7 auto-reboot when a security update needs it (04:30)"
cat > /etc/apt/apt.conf.d/52unattended-upgrades-honeypot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF

echo "== sudoers check"
if [[ -f /etc/sudoers.d/sshvigil-project ]]; then
  echo "   Found /etc/sudoers.d/sshvigil-project:"
  sed 's/^/     /' /etc/sudoers.d/sshvigil-project
  echo "   It grants passwordless apt/systemctl/tee, which is effectively passwordless root."
  read -r -p "   Delete it? [y/N] " a
  if [[ $a == [yY] ]]; then rm -f /etc/sudoers.d/sshvigil-project && visudo -c && echo "   removed"; fi
else
  echo "   ok: no sshvigil-project sudoers file"
fi
ls -la /etc/sudoers.d/

echo "STEP 3 done."
