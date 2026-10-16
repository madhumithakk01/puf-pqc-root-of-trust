"""One v1.1 update through QuietVendor (WSL, from the repository root); prints the outcome.

  python3 tools/measure/update_v11.py

Used for Figure 5.4 (with console_capture.py) and as the baseline that raises the floor to 2 before attacks A7
and A8. Installs data/demo/v1_1_0.sbi.bin; the board must be running and registered in data/registry.
"""

import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "demo"))
import demo  # noqa: E402

v = demo.vendor()
did = demo.device_id_of(v)
host = open(os.path.join(ROOT, "data", "demo", "device.ip")).read().strip()
t0 = time.time()
res = v.deploy(host, 7000, did, os.path.join(ROOT, "data", "demo", "v1_1_0.sbi.bin"), 2, "1.1.0", timeout=120)
res.pop("receipt", None)
res["status"] = {k: res["status"].get(k) for k in ("version", "svn", "floor", "slot", "trial", "receipt_seq")}
print(json.dumps(res, indent=1, default=str))
print("total %.1f s" % (time.time() - t0))
