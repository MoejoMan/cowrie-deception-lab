#!/bin/bash
# runboth.sh FILE : run each line on the twin and on real Debian 12, print a diff
D=/tmp/hp-test
SETUP='mkdir -p /tmp/g/sub && touch /tmp/g/a.txt /tmp/g/b.txt /tmp/g/.hid /tmp/g/c.log /tmp/g/sub/x.txt && cd /tmp/g; '
while IFS= read -r l; do echo "### $l"; $D/venv/bin/python - "{ $SETUP $l ; } 2>&1" <<'PY'
import paramiko,sys
c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("127.0.0.1",port=2299,username="root",password="password",allow_agent=False,look_for_keys=False)
i,o,e=c.exec_command(sys.argv[1],timeout=20);sys.stdout.write(o.read().decode(errors="replace")+e.read().decode(errors="replace"))
PY
done < "$1" > $D/hp.out
while IFS= read -r l; do echo "### $l"; docker run --rm --network none -w /root debian:bookworm-20240612 bash -c "{ $SETUP $l ; } 2>&1"; done < "$1" > $D/real.out
diff $D/hp.out $D/real.out && echo IDENTICAL
