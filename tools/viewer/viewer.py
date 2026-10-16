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
import contextlib
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
         "last_deploy": None, "vitals": None, "lock": threading.Lock(), "busy": False,
         "cache_status": None, "cache_receipts": None, "vendor_args": None, "identity": None}


@contextlib.contextmanager
def exclusive():
    """One attest or deploy at a time, with every other connection to the board held back.

    The board serves three TCP clients and, when a fourth arrives, aborts the oldest. The
    vitals stream and the page's polling would otherwise evict the operation's own link."""
    with STATE["lock"]:
        STATE["busy"] = True
        try:
            yield
        finally:
            STATE["busy"] = False


def vitals_thread(host, port):
    while True:
        c = None
        try:
            if not STATE["busy"]:
                c = vl.Client(host, port, timeout=5)
                c.sock.sendall(vl.encode_frame(vl.VITALS_SUB, 1))
                while not STATE["busy"]:
                    fr = vl.read_frame(c.sock, 5)
                    if fr is None:
                        break
                    if fr[0] == vl.R_VITALS:
                        STATE["vitals"] = json.loads(fr[2])
        except (OSError, ValueError):
            pass
        finally:
            if c:
                c.close()
        time.sleep(1)


def check_identity(st):
    """Follow a re-enrolled board. A new device ID means a new registry entry: reload the
    registry and switch to it when it holds exactly that device, otherwise say so."""
    seen = st.get("device_id")
    if STATE["device_id"] is None or not isinstance(seen, str) or seen == "%08x" % STATE["device_id"]:
        STATE["identity"] = None
        return
    args = STATE["vendor_args"]
    if args:
        fresh = vl.Vendor(*args)
        if list(fresh.registry.devices) == [seen]:
            STATE.update(vendor=fresh, device_id=int(seen, 16), cache_status=None, cache_receipts=None,
                         last_attest=None, last_deploy=None)
            STATE["identity"] = None
            print(f"board identity changed: now device {seen}", flush=True)
            return
    STATE["identity"] = f"new board identity {seen}: restart the viewer"


def api_status():
    host, port = STATE["device"]
    if STATE["busy"] and STATE["cache_status"]:
        return STATE["cache_status"]
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
        if not STATE["busy"]:
            check_identity(st)
        STATE["cache_status"] = {"online": True, "status": st, "report": rep, "identity_alert": STATE["identity"]}
        return STATE["cache_status"]
    except (OSError, ConnectionError, vl.ProtocolError, ValueError) as e:
        return {"online": False, "error": str(e)}


def api_receipts():
    v = STATE["vendor"]
    if not v or STATE["device_id"] is None:
        return {"receipts": [], "chain": None}
    if STATE["busy"] and STATE["cache_receipts"]:
        return STATE["cache_receipts"]
    try:
        parsed = v.fetch_receipts(*STATE["device"], STATE["device_id"])
        chain = "valid"
    except Exception as e:  # a failed chain is itself the finding
        parsed, chain = [], f"INVALID: {e}"
    out = [{k: (x.hex() if isinstance(x, bytes) else x) for k, x in r.items()} for r in parsed]
    STATE["cache_receipts"] = {"receipts": out, "chain": chain}
    return STATE["cache_receipts"]


def api_attest():
    v = STATE["vendor"]
    if not v:
        return {"error": "no vendor configured"}
    with exclusive():
        time.sleep(1.5)   # let the vitals link and any poll in flight close
        rep = v.attest(*STATE["device"], STATE["device_id"])
    out = {k: (x.hex() if isinstance(x, bytes) else x) for k, x in rep.items()}
    STATE["last_attest"] = out
    return out


def api_deploy(version):
    v = STATE["vendor"]
    if not v or version not in STATE["images"]:
        return {"error": "unknown version"}
    with exclusive():
        time.sleep(1.5)
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


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            print(f"browser {client_address[0]} closed the connection mid-response", flush=True)
        else:
            super().handle_error(request, client_address)


def serve(listen, device, vendor=None, device_id=None, images=None):
    STATE.update(device=device, vendor=vendor, device_id=device_id, images=images or {})
    threading.Thread(target=vitals_thread, args=device, daemon=True).start()
    srv = Server(("127.0.0.1" if listen < 0 else "0.0.0.0", abs(listen)), Handler)
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
        STATE["vendor_args"] = (a.registry, a.vendor_cli, a.attest_cli, a.vendor_sk)
        if a.images:
            imgs = {v: os.path.join(a.images, f"v{v}.sbi.bin") for v in VERSIONS}
    srv = serve(a.listen, (host, int(port)), vendor, int(a.device_id, 16) if a.device_id else None, imgs)
    print(f"viewer on http://localhost:{a.listen}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
