#!/bin/bash
# Start cowrie-twin on 127.0.0.1:2299 with the same patch mounts as live (from docker-compose.yml)
cd /opt/honeypot
T=/tmp/hp-test/twin
mkdir -p $T/var/log/cowrie $T/var/lib/cowrie/downloads $T/var/lib/cowrie/tty $T/var/run
M=""
for m in $(grep -oE '\./cowrie/patches/[a-z_]+\.py:/cowrie/cowrie-git/src/[^:]+' docker-compose.yml); do M="$M -v $PWD/${m#./}:ro"; done
docker rm -f cowrie-twin >/dev/null 2>&1
docker run -d --name cowrie-twin --runtime=runsc --memory 512m --cpus 0.5 --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges:true --network honeypot_cowrie_net --user $(id -u):$(id -g) --read-only --tmpfs /tmp:size=16m -p 127.0.0.1:2299:2222 -v ${ETC:-$PWD/cowrie/etc}:/cowrie/cowrie-git/etc:ro $M -v $T/var:/cowrie/cowrie-git/var cowrie/cowrie:$(grep ^COWRIE_VERSION .env | cut -d= -f2) >/dev/null
for i in $(seq 1 40); do timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2299; read -r l <&3; [[ $l == SSH-* ]]' 2>/dev/null && { echo twin up; exit 0; }; sleep 1; done; echo twin FAILED; docker logs --tail 20 cowrie-twin
