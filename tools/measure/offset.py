"""Prints the Windows time (UTC) and the offset WSL clock minus Windows clock, in seconds."""
import subprocess, sys, time
from datetime import datetime, timezone
a = time.time()
w = float(subprocess.run(["wsl", "-e", "python3", "-c", "import time;print(time.time())"], capture_output=True, text=True).stdout)
b = time.time()
mid = (a + b) / 2
print(datetime.fromtimestamp(mid, timezone.utc).isoformat(timespec="milliseconds"), "%.3f" % (w - mid))
