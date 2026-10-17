"""One ping per second to each named target, logged with the round-trip time (Windows).

  python pingwin.py LOGFILE NAME HOST [NAME HOST ...]
"""
import re, subprocess, sys, threading, time
from ts import now
out = open(sys.argv[1], "a", buffering=1)
lock = threading.Lock()
def run(name, host):
    nxt = time.time()
    while True:
        p = subprocess.run(["ping", "-n", "1", "-w", "1000", host], capture_output=True, text=True)
        m = re.search(r"time[=<](\d+)ms", p.stdout)
        ok = m and "TTL=" in p.stdout
        with lock:
            out.write(f"{now()} PING {name} {host} {'OK ' + m.group(1) + 'ms' if ok else 'TIMEOUT'}\n")
        nxt += 1; time.sleep(max(0, nxt - time.time()))
for n, h in zip(sys.argv[2::2], sys.argv[3::2]):
    threading.Thread(target=run, args=(n, h), daemon=True).start()
while True: time.sleep(60)
