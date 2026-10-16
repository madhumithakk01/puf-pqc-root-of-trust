"""Deploy v1.1 once, then read the boot report (WSL, from the repository root).

  python3 tools/measure/update_then_bootreport.py

Shows which stage cycle counts the boot report holds after a full update (Table 5.10: the install stage is 0
because the install runs in an earlier boot).
"""

import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "demo"))
import demo  # noqa: E402
import vendor_lib as vl  # noqa: E402

v = demo.vendor()
did = demo.device_id_of(v)
host = open(os.path.join(ROOT, "data", "demo", "device.ip")).read().strip()
res = v.deploy(host, 7000, did, os.path.join(ROOT, "data", "demo", "v1_1_0.sbi.bin"), 2, "1.1.0", timeout=120)
c = vl.Client(host, 7000, timeout=10)
try:
    br = c.bootreport()
finally:
    c.close()
print(res["outcome"], "floor", res["floor"])
print(json.dumps({k: br[k] for k in ("last_event", "last_reason", "bits_corrected", "worst_block", "temp_x10",
                                      "cycles", "attest", "new_receipt")}))
