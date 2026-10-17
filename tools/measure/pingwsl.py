"""One ping per second from WSL to the board, logged with the round-trip time.

  python3 pingwsl.py LOGFILE HOST
"""
import re, subprocess, sys, time
from ts import now
out = open(sys.argv[1], "a", buffering=1)
host = sys.argv[2]
nxt = time.time()
while True:
    p = subprocess.run(["ping", "-c", "1", "-W", "1", host], capture_output=True, text=True)
    m = re.search(r"time=([\d.]+) ms", p.stdout)
    out.write(f"{now()} PING wsl->board {host} {'OK ' + m.group(1) + 'ms' if m else 'TIMEOUT ' + (p.stderr or p.stdout.splitlines()[-1] if p.stdout else '').strip()[:60]}\n")
    nxt += 1; time.sleep(max(0, nxt - time.time()))
