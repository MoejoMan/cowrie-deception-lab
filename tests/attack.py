import paramiko, sys, time, threading, json
def conn():
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port=2299, username="root", password="password", allow_agent=False, look_for_keys=False, timeout=10)
    return c
stalls = []; stop = False
def canary():
    c = conn()
    while not stop:
        t = time.time()
        try:
            i, o, e = c.exec_command("echo ok", timeout=60); o.read()
        except Exception as ex:
            stalls.append(("err", str(ex))); c = conn()
        d = time.time() - t
        if d > 2: stalls.append(round(d, 1))
        time.sleep(0.5)
th = threading.Thread(target=canary, daemon=True); th.start()
for cmd in [l.rstrip("\n") for l in open(sys.argv[1]) if l.strip()]:
    t = time.time()
    try:
        c = conn(); i, o, e = c.exec_command(cmd, timeout=40)
        out = o.read()[:200].decode(errors="replace"); err = e.read()[:200].decode(errors="replace"); rc = o.channel.recv_exit_status(); c.close()
        res = f"rc={rc} out={out!r} err={err!r}"
    except Exception as ex:
        res = f"EXC {type(ex).__name__}: {ex}"
    print(f"[{time.time()-t:5.1f}s] {cmd[:90]}\n         {res[:230]}  stalls={stalls}", flush=True)
    stalls.clear()
stop = True
