import paramiko, json, sys, socket, concurrent.futures as cf
cmds = json.load(open(sys.argv[1])); out = {}
def run(cmd):
    if cmd.startswith("scp ") or "scp -t" in cmd: return cmd, "SKIP(scp)"
    try:
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("127.0.0.1", port=2299, username="root", password="password", allow_agent=False, look_for_keys=False, timeout=10)
        i, o, e = c.exec_command(cmd, timeout=10); i.channel.shutdown_write()
        r = o.read().decode(errors="replace") + "\n[stderr]" + e.read().decode(errors="replace") + f"\n[rc={o.channel.recv_exit_status()}]"
        c.close(); return cmd, r
    except (socket.timeout, Exception) as ex:
        return cmd, f"ERROR {type(ex).__name__}: {ex}"
with cf.ThreadPoolExecutor(6) as ex:
    for cmd, r in ex.map(run, cmds): out[cmd] = r
json.dump(out, open(sys.argv[2], "w"), indent=0)
print(len(out), "done;", sum(1 for v in out.values() if v.startswith("ERROR")), "errors")
