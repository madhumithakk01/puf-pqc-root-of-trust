"""Runs story_trace.py (the traced demo.py story) in WSL and stamps every output line.

  python3 story_ts2.py LOGFILE ROOT TRACEFILE STORY_TRACE_PY
"""
import subprocess, sys
from ts import now
out = open(sys.argv[1], "a", buffering=1)
root = sys.argv[2]; trace = sys.argv[3]
out.write(f"{now()} STORY start (traced)\n")
p = subprocess.Popen(["python3", "-u", sys.argv[4], root, trace], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=root)
for line in p.stdout:
    out.write(f"{now()} STORY {line.rstrip()}\n")
out.write(f"{now()} STORY exit {p.wait()}\n")
