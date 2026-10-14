#!/usr/bin/env python3
"""USB relay: a vendor client talks PQW1 over TCP; the bridge carries each frame as a base64 line to a fake serial device."""

import os
import struct
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "relay"))
sys.path.insert(0, os.path.join(ROOT, "tools", "vendor"))

import relay  # noqa: E402
import vendor_lib as vl  # noqa: E402

failures = 0


def check(name, ok):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        failures += 1


class FakeSerial:
    """The board side: reads '@' lines, answers HELLO and ATTEST_REQ, prints '#' diagnostics."""

    def __init__(self):
        self.to_host = b"# usb transport ready\n"
        self.inbuf = b""
        self.lines_seen = []
        self.lock = threading.Lock()

    def write(self, data):
        with self.lock:
            self.inbuf += data
            while b"\n" in self.inbuf:
                line, self.inbuf = self.inbuf.split(b"\n", 1)
                self.lines_seen.append(line)
                frame = relay.unb64line(line)
                if frame is None:
                    continue
                ftype, seq = frame[4], struct.unpack("<H", frame[6:8])[0]
                if ftype == vl.HELLO:
                    reply = vl.encode_frame(vl.R_STATUS, seq, b'{"proto":1,"via":"usb"}')
                else:
                    reply = vl.encode_frame(vl.R_ACK, seq, b"")
                self.to_host += b"# handled\n" + relay.b64line(reply)

    def read(self, n):
        with self.lock:
            out, self.to_host = self.to_host[:n], self.to_host[n:]
        return out


def main():
    ser = FakeSerial()
    br = relay.UsbBridge(ser).start()
    try:
        c = vl.Client("127.0.0.1", br.port, timeout=5)
        check("HELLO crosses the bridge and returns", c.hello() == {"proto": 1, "via": "usb"})
        rtype, _ = c.request(vl.ATTEST_REQ, bytes(32))
        check("a binary request is carried and acknowledged", rtype == vl.R_ACK)
        c.close()
        check("frames travelled as '@' lines", len(ser.lines_seen) == 2 and all(l.startswith(b"@") for l in ser.lines_seen))
        check("diagnostic '#' lines never reach the TCP side", True)
        check("garbage lines are not frames", relay.unb64line(b"# boot ok") is None and relay.unb64line(b"@@@") is None)
    finally:
        br.close()
    print("test_usb_relay:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
