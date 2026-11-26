import paramiko, time, sys
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("127.0.0.1", port=2299, username="root", password="password", allow_agent=False, look_for_keys=False)
ch = c.invoke_shell(width=200)
time.sleep(1.5); ch.recv(65535)
def drain(quiet=45.0):
    buf=b""; last=time.time()
    while time.time()-last < quiet:
        if ch.recv_ready(): buf+=ch.recv(65535); last=time.time()
        else: time.sleep(0.05)
    return buf.decode(errors="replace")
for cmd in sys.stdin.read().strip().split("\n"):
    ch.sendall(cmd + "\n"); print(drain())
c.close()
