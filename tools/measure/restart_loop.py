"""Tables 5.7 and 5.10: restart the board N times with an attestation request and record each boot report.

Run in WSL from the repository root:

  python3 tools/measure/restart_loop.py N OUTFILE.jsonl

Each iteration: QuietVendor.attest (the board restarts into the RoT, rebuilds the PUF key and returns a
signed report), then GET_BOOTREPORT. One line of JSON per restart: the verified ATR2 fields and the whole
boot report. Stops (exit 2) when two attempts in a row get no answer, so a frozen board is not hammered.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "demo"))
import demo  # noqa: E402
import vendor_lib as vl  # noqa: E402

n, outp = int(sys.argv[1]), sys.argv[2]
v = demo.vendor()
did = demo.device_id_of(v)
host = open(os.path.join(ROOT, "data", "demo", "device.ip")).read().strip()
fails = 0
done = 0
t_start = time.time()
with open(outp, "a", buffering=1) as out:
    for i in range(1, n + 1):
        rec = {"i": i, "t": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
        try:
            rep = v.attest(host, 7000, did)
            c = vl.Client(host, 7000, timeout=10)
            try:
                br = c.bootreport()
            finally:
                c.close()
            rec["atr2"] = {k: (x.hex() if isinstance(x, bytes) else x) for k, x in rep.items() if k in
                           ("reset_cause", "bits_corrected", "worst_block", "svn", "floor", "journal_seq", "alerts")}
            rec["boot"] = br
            fails = 0
            done += 1
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"[:200]
            fails += 1
        out.write(json.dumps(rec) + "\n")
        print(f"{i}/{n} {'ok' if 'error' not in rec else rec['error']} elapsed {time.time()-t_start:.0f}s", flush=True)
        if fails >= 2:
            print("two failures in a row: stopping", flush=True)
            sys.exit(2)
print(f"done {done}/{n} in {time.time()-t_start:.0f}s")
