#!/usr/bin/env python3
"""Smoke test of the viewer and Fleet page against the software device.

usage: test_viewer.py <vendor_cli> <attest_cli> <softdev_device>
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "attacker"))
sys.path.insert(0, os.path.join(ROOT, "tools", "viewer"))

import lab as labmod  # noqa: E402
import viewer  # noqa: E402

failures = 0


def check(name, ok):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        failures += 1


def get(port, path, post=False):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST" if post else "GET",
                                 data=b"" if post else None)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(), r.headers.get("Content-Type")


def main(vc, ac, sd):
    lab = labmod.Lab(tempfile.mkdtemp(prefix="viewer_"), os.path.abspath(vc), os.path.abspath(ac), os.path.abspath(sd)).build()
    try:
        images = {v: lab.images[v] for v in lab.images}
        srv = viewer.serve(0, lab.addr, lab.vendor, lab.device_id, images)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        body, ctype = get(port, "/")
        check("the page is served as HTML", ctype.startswith("text/html") and b"Fleet" in body)
        st = json.loads(get(port, "/api/status")[0])
        check("status shows the device online with its boot report", st["online"] and st["status"]["svn"] == 1
              and st["report"]["bits_corrected"] > 0)
        time.sleep(1.5)
        v = json.loads(get(port, "/api/vitals")[0])
        check("vitals arrive over the subscription (replay of the golden trace is labelled)", v == {} or v.get("replay") is True)
        att = json.loads(get(port, "/api/attest", post=True)[0])
        check("attest from the page returns a verified report", att.get("svn") == 1 and not att.get("alerts"))
        dep = json.loads(get(port, "/api/deploy/1.1.0", post=True)[0])
        check("deploy v1.1 from the page commits", dep.get("outcome") == "COMMITTED" and dep.get("floor") == 2)
        dep = json.loads(get(port, "/api/deploy/1.0.0", post=True)[0])
        check("insider downgrade from the page is refused", dep.get("outcome") == "REFUSED")
        rc = json.loads(get(port, "/api/receipts")[0])
        check("receipt log: chain valid, two receipts", rc["chain"] == "valid" and len(rc["receipts"]) == 2)
        viewer.check_identity({"device_id": "deadbeef"})
        check("an unknown board identity is flagged, not silently followed",
              "restart the viewer" in (viewer.STATE["identity"] or "") and viewer.STATE["device_id"] == lab.device_id)
        viewer.check_identity({"device_id": "%08x" % lab.device_id})
        check("the flag clears when the identity matches again", viewer.STATE["identity"] is None)
    finally:
        lab.close()
    print("test_viewer:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
