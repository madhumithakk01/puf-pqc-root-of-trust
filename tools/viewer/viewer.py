#!/usr/bin/env python3
"""
Viewer and Fleet page (standard library only).

  viewer.py --device HOST:PORT [--listen 8080] [--registry DIR --vendor-cli B --attest-cli B
            --vendor-sk F --device-id HEX --images DIR]

Serves one page with: live vitals (server-sent events from a PQW1 VITALS_SUB
connection), the boot report and security state, the last verified attestation,
the receipt log with signature and chain status, and, when vendor options are
given, deploy buttons (v1.1, v1.2, and the insider downgrade to v1.0).
Nothing here is trusted by the device: the page only shows what verifies.
"""

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "server", "attest"))

import vendor_lib as vl  # noqa: E402

VERSIONS = {"1.0.0": 1, "1.1.0": 2, "1.2.0": 3}
STATE = {"vendor": None, "device": None, "images": {}, "device_id": None, "last_attest": None,
         "last_deploy": None, "vitals": None, "lock": threading.Lock()}


def vitals_thread(host, port):
    while True:
        try:
            c = vl.Client(host, port, timeout=5)
            c.sock.sendall(vl.encode_frame(vl.VITALS_SUB, 1))
            while True:
                fr = vl.read_frame(c.sock, 5)
                if fr is None:
                    break
                if fr[0] == vl.R_VITALS:
                    STATE["vitals"] = json.loads(fr[2])
        except (OSError, ValueError):
            pass
        time.sleep(1)


def api_status():
    host, port = STATE["device"]
    try:
        c = vl.Client(host, port, timeout=3)
        try:
            st = c.hello()
            try:
                rep = c.bootreport()
            except vl.ProtocolError:
                rep = None
        finally:
            c.close()
        return {"online": True, "status": st, "report": rep}
    except (OSError, ConnectionError, vl.ProtocolError, ValueError) as e:
        return {"online": False, "error": str(e)}


def api_receipts():
    v = STATE["vendor"]
    if not v or STATE["device_id"] is None:
        return {"receipts": [], "chain": None}
    try:
        parsed = v.fetch_receipts(*STATE["device"], STATE["device_id"])
        chain = "valid"
    except Exception as e:  # a failed chain is itself the finding
        parsed, chain = [], f"INVALID: {e}"
    out = [{k: (x.hex() if isinstance(x, bytes) else x) for k, x in r.items()} for r in parsed]
    return {"receipts": out, "chain": chain}


def api_attest():
    v = STATE["vendor"]
    if not v:
        return {"error": "no vendor configured"}
    rep = v.attest(*STATE["device"], STATE["device_id"])
    out = {k: (x.hex() if isinstance(x, bytes) else x) for k, x in rep.items()}
    STATE["last_attest"] = out
    return out


def api_deploy(version):
    v = STATE["vendor"]
    if not v or version not in STATE["images"]:
        return {"error": "unknown version"}
    with STATE["lock"]:
        res = v.deploy(*STATE["device"], STATE["device_id"], STATE["images"][version], VERSIONS[version], version)
    res.pop("receipt", None)
    STATE["last_deploy"] = res
    return res


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = open(os.path.join(HERE, "index.html"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self._json(api_status())
        elif self.path == "/api/receipts":
            self._json(api_receipts())
        elif self.path == "/api/vitals":
            self._json(STATE["vitals"] or {})
        elif self.path == "/api/last":
            self._json({"attest": STATE["last_attest"], "deploy": STATE["last_deploy"]})
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            if self.path == "/api/attest":
                self._json(api_attest())
            elif self.path.startswith("/api/deploy/"):
                self._json(api_deploy(self.path.rsplit("/", 1)[1]))
            else:
                self.send_error(404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def serve(listen, device, vendor=None, device_id=None, images=None):
    STATE.update(device=device, vendor=vendor, device_id=device_id, images=images or {})
    threading.Thread(target=vitals_thread, args=device, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1" if listen < 0 else "0.0.0.0", abs(listen)), Handler)
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--listen", type=int, default=8080)
    ap.add_argument("--registry")
    ap.add_argument("--vendor-cli")
    ap.add_argument("--attest-cli")
    ap.add_argument("--vendor-sk")
    ap.add_argument("--device-id")
    ap.add_argument("--images")
    a = ap.parse_args()
    host, port = a.device.rsplit(":", 1)
    vendor, imgs = None, {}
    if a.registry and a.vendor_cli:
        vendor = vl.Vendor(a.registry, a.vendor_cli, a.attest_cli, a.vendor_sk)
        if a.images:
            imgs = {v: os.path.join(a.images, f"v{v}.sbi.bin") for v in VERSIONS}
    srv = serve(a.listen, (host, int(port)), vendor, int(a.device_id, 16) if a.device_id else None, imgs)
    print(f"viewer on http://localhost:{a.listen}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
