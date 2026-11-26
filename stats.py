#!/usr/bin/env python3
"""Quick summary of REAL attacker activity (internal test IPs excluded). Usage: ./stats.py"""
import collections, glob, json
LOG = "/opt/honeypot/data/cowrie/var/log/cowrie/cowrie.json"
ips, ev, creds, clients = (collections.Counter() for _ in range(4))
ok, cmds, files, first = [], [], [], None
for path in sorted(glob.glob(LOG + "*")):
    for line in open(path, errors="replace"):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        ip = e.get("src_ip", "")
        if ip.startswith(("172.30.", "10.99.")):
            continue
        first = first or e["timestamp"]
        eid = e["eventid"]
        ev[eid] += 1
        if eid == "cowrie.session.connect":
            ips[ip] += 1
        elif eid == "cowrie.client.version":
            clients[e.get("version", "")] += 1
        if eid.startswith("cowrie.login"):
            creds[(e.get("username"), e.get("password"))] += 1
        if eid == "cowrie.login.success":
            ok.append((e["timestamp"][5:16].replace("T", " "), ip, e.get("username"), e.get("password")))
        if eid == "cowrie.command.input":
            cmds.append((e["timestamp"][11:16], ip, e.get("input", "")[:110]))
        if eid.startswith("cowrie.session.file"):
            files.append((e["timestamp"][11:16], ip, eid[15:], e.get("url") or e.get("filename"), (e.get("shasum") or "")[:16]))
attempts = ev["cowrie.login.failed"] + ev["cowrie.login.success"]
print(f"first external contact: {first}")
print(f"connections: {sum(ips.values())} from {len(ips)} unique IPs | login attempts: {attempts} | "
      f"successful: {len(ok)} | commands: {len(cmds)} | file events: {len(files)}")
for title, rows in (("top IPs", [f"{n:5d}  {ip}" for ip, n in ips.most_common(6)]),
                    ("top credentials tried", [f"{n:5d}  {u}/{p}" for (u, p), n in creds.most_common(8)]),
                    ("SSH clients", [f"{n:5d}  {v[:60]}" for v, n in clients.most_common(4)]),
                    ("successful logins (latest)", ["  ".join(map(str, x)) for x in ok[-6:]]),
                    ("commands (latest)", ["  ".join(map(str, x)) for x in cmds[-12:]]),
                    ("file activity", ["  ".join(map(str, x)) for x in files[-6:]])):
    print(f"\n{title}:")
    for r in rows or ["none"]:
        print("  " + r)
