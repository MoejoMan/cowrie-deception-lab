#!/usr/bin/env bash
# Checks every security layer is actually working, from the outside in. No sudo needed.
set -uo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a
P=0; F=0
ok()  { echo "  PASS  $*"; P=$((P+1)); }
bad() { echo "  FAIL  $*"; F=$((F+1)); }
banner() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2; read -r l <&3; echo \$l" 2>/dev/null | tr -d '\r'; }
NET=honeypot_cowrie_net

echo "== Ports"
b=$(banner "${COWRIE_LISTEN%:*}" "${COWRIE_LISTEN##*:}"); [[ $b == *Debian* ]] && ok "honeypot on $COWRIE_LISTEN is Cowrie ($b)" || bad "honeypot banner on $COWRIE_LISTEN: '$b'"
b=$(banner "$WG_IP" 22);      [[ $b == *Ubuntu* ]] && ok "real sshd on WireGuard ($b)" || bad "WireGuard :22 banner: '$b'"
ss -Htln | awk '{print $4}' | grep -qE '^(0\.0\.0\.0|\*|\[::\]):22$' && bad "something listens on *:22" || ok "nothing on *:22"
for port in 5601 9200; do
  timeout 3 bash -c "exec 3<>/dev/tcp/$PUBLIC_IP/$port" 2>/dev/null && bad "$port reachable on public IP" || ok "$port closed on public IP"
done
curl -s -o /dev/null -w '%{http_code}' "http://$WG_IP:5601/api/status" | grep -qE '200|401' && ok "Kibana up on $WG_IP:5601" || bad "Kibana not answering on $WG_IP:5601"

echo "== Cowrie container"
[[ $(docker inspect -f '{{.HostConfig.Runtime}}' honeypot-cowrie-1 2>/dev/null) == runsc ]] && ok "runtime = gVisor" || bad "not running under runsc"
[[ $(docker inspect -f '{{.Config.User}}' honeypot-cowrie-1 2>/dev/null) == 64999:64999 ]] && ok "user = 64999" || bad "unexpected user"
[[ $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' honeypot-cowrie-1 2>/dev/null) == true ]] && ok "read-only rootfs" || bad "rootfs writable"
docker inspect -f '{{.HostConfig.CapDrop}}' honeypot-cowrie-1 2>/dev/null | grep -q ALL && ok "all capabilities dropped" || bad "caps not dropped"
docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' honeypot-cowrie-1 | grep -q elk && bad "cowrie is on the ELK network!" || ok "cowrie not on ELK network"

echo "== Egress (a throwaway container on the Cowrie network, same runtime, tries to get out)"
# Read results via process substitution (not a pipe) so ok/bad counters survive.
egress=$(docker run --rm --runtime=runsc --network "$NET" --user 64999:64999 cowrie/cowrie:"$COWRIE_VERSION" -c '
import socket
def tcp(h,p):
    s=socket.socket(); s.settimeout(4)
    try: s.connect((h,p)); return "OPEN"
    except Exception as e: return "blocked"
def dns(n):
    try: socket.setdefaulttimeout(4); socket.getaddrinfo(n,80); return "RESOLVED"
    except Exception: return "blocked"
print("internet 1.1.1.1:443", tcp("1.1.1.1",443))
print("host unbound 10.99.0.1:53", tcp("10.99.0.1",53))
print("host sshd 10.99.0.1:22", tcp("10.99.0.1",22))
print("crowdsec api 172.30.66.1:8080", tcp("172.30.66.1",8080))
print("elasticsearch 172.30.66.1:9200", tcp("172.30.66.1",9200))
print("dns example.com", dns("example.com"))
' 2>&1)
[[ $(grep -c . <<<"$egress") -eq 6 ]] || bad "egress test did not report all 6 checks: $egress"
while read -r line; do
  [[ -z $line ]] && continue
  [[ $line == *blocked ]] && ok "$line" || bad "$line"
done <<<"$egress"

echo "== Pipeline"
n=$(curl -s -u "elastic:$ELASTIC_PASSWORD" "http://127.0.0.1:9200/cowrie-*/_count" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null)
[[ ${n:-0} -gt 0 ]] && ok "$n Cowrie events in Elasticsearch" || bad "no events in ES yet (normal for the first few minutes)"

echo
echo "$P passed, $F failed"
[[ $F -eq 0 ]]
