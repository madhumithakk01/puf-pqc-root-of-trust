# Runs `demo.py story` with timestamped tracing of every vendor_lib connection and request.
import os, runpy, socket, sys, time
from datetime import datetime, timezone
root, trace = sys.argv[1], sys.argv[2]
sys.path[:0] = [root + "/tools/vendor", root + "/server/attest", root + "/tools/demo"]
import vendor_lib as vl
out = open(trace, "a", buffering=1)
def now(): return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
def log(s): out.write(f"{now()} TRACE {s}\n")
_init, _req = vl.Client.__init__, vl.Client.request
def init(self, host, port, timeout=20.0):
    t = time.time()
    try:
        _init(self, host, port, timeout)
        log(f"connect ok {1000*(time.time()-t):.0f}ms local_port={self.sock.getsockname()[1]} timeout={timeout}")
    except Exception as e:
        log(f"connect FAIL {type(e).__name__} errno={getattr(e,'errno',None)} {1000*(time.time()-t):.0f}ms timeout={timeout}")
        raise
def request(self, ftype, payload=b""):
    t = time.time()
    try:
        r = _req(self, ftype, payload)
        log(f"req type={ftype} lport={self.sock.getsockname()[1]} ok {1000*(time.time()-t):.0f}ms")
        return r
    except Exception as e:
        log(f"req type={ftype} FAIL {type(e).__name__} {1000*(time.time()-t):.0f}ms")
        raise
vl.Client.__init__, vl.Client.request = init, request
sys.argv = ["demo.py", "story"]
runpy.run_path(root + "/tools/demo/demo.py", run_name="__main__")
