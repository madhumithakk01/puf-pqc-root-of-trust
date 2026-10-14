"""
Vendor-side library: the PQW1 client, a device registry, and the attest and
deploy flows. Standard library only; ML-DSA and packaging go through the C
tools (attest_cli, vendor_cli).

The vendor trusts nothing the network delivers: an attestation counts only
when its ML-DSA signature verifies under the key recorded at enrollment,
carries the verifier's own nonce, and does not move the floor or the receipt
sequence backwards.
"""

import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server", "attest"))
import attest  # noqa: E402
import attest2  # noqa: E402

MAGIC = b"PQW1"
MAX_PAYLOAD = 8192

HELLO, VITALS_SUB, ATTEST_REQ, GET_ATTEST = 0x01, 0x02, 0x03, 0x04
PKG_BEGIN, PKG_CHUNK, PKG_END = 0x05, 0x06, 0x07
GET_RECEIPTS, GET_BOOTREPORT, GET_IDENTITY = 0x08, 0x09, 0x0A
R_STATUS, R_VITALS, R_ACK, R_ATTEST, R_READY, R_CHUNK_ACK, R_END_ACK = 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
R_RECEIPTS, R_BOOTREPORT, R_IDENTITY, R_ERR = 0x88, 0x89, 0x8A, 0xFF

CHUNK = 4096


class ProtocolError(Exception):
    def __init__(self, code, msg):
        super().__init__(f"device error {code}: {msg}")
        self.code = code
        self.msg = msg


def encode_frame(ftype, seq, payload=b"", flags=1):
    body = struct.pack("<BBHI", ftype, flags, seq & 0xFFFF, len(payload)) + payload
    return MAGIC + body + struct.pack("<I", zlib.crc32(body))


def read_frame(sock, timeout=10.0):
    """Read one frame from a socket. Returns (type, seq, payload) or None on a clean close."""
    sock.settimeout(timeout)
    buf = b""

    def need(n):
        nonlocal buf
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return False
            buf += chunk
        return True

    while True:
        # hunt for the magic one byte at a time
        buf = b""
        if not need(4):
            return None
        while buf != MAGIC:
            buf = buf[1:]
            if not need(4):
                return None
        if not need(12):
            return None
        ftype, flags, seq, length = struct.unpack("<BBHI", buf[4:12])
        if length > MAX_PAYLOAD:
            continue
        if not need(12 + length + 4):
            return None
        body = buf[4:12 + length]
        (crc,) = struct.unpack("<I", buf[12 + length:16 + length])
        if zlib.crc32(body) != crc:
            continue
        return ftype, seq, buf[12:12 + length]


class Client:
    """One PQW1 connection."""

    def __init__(self, host, port, timeout=10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.seq = 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def request(self, ftype, payload=b""):
        self.seq = (self.seq + 1) & 0xFFFF
        self.sock.sendall(encode_frame(ftype, self.seq, payload))
        while True:
            fr = read_frame(self.sock, self.timeout)
            if fr is None:
                raise ConnectionError("connection closed")
            rtype, rseq, rpayload = fr
            if rtype == R_VITALS:
                continue
            if rseq != self.seq:
                continue
            if rtype == R_ERR:
                j = json.loads(rpayload)
                raise ProtocolError(j.get("code"), j.get("msg"))
            return rtype, rpayload

    def hello(self):
        return json.loads(self.request(HELLO)[1])

    def bootreport(self):
        return json.loads(self.request(GET_BOOTREPORT)[1])

    def identity(self):
        _, p = self.request(GET_IDENTITY)
        return struct.unpack("<I", p[:4])[0], p[4:4 + 1312], p[4 + 1312:4 + 1312 + 800]

    def attest_req(self, nonce):
        self.request(ATTEST_REQ, nonce)

    def get_attest(self):
        return self.request(GET_ATTEST)[1]

    def get_receipts(self, since):
        _, p = self.request(GET_RECEIPTS, struct.pack("<I", since))
        (count,) = struct.unpack("<H", p[:2])
        size = attest2.RCP_TOTAL
        return [p[2 + i * size:2 + (i + 1) * size] for i in range(count)]

    def push_package(self, pkg, crc=None):
        crc = zlib.crc32(pkg) if crc is None else crc
        self.request(PKG_BEGIN, struct.pack("<II", len(pkg), crc))
        off = 0
        while off < len(pkg):
            part = pkg[off:off + CHUNK]
            _, ack = self.request(PKG_CHUNK, struct.pack("<I", off) + part)
            off = struct.unpack("<I", ack)[0]
        self.request(PKG_END)


def wait_for(host, port, pred, timeout=60.0, interval=0.1):
    """Poll HELLO on fresh connections until `pred(status)` holds."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            c = Client(host, port, timeout=3.0)
            try:
                st = c.hello()
            finally:
                c.close()
            last = st
            if pred(st):
                return st
        except (OSError, ConnectionError, ProtocolError, ValueError):
            pass
        time.sleep(interval)
    raise TimeoutError(f"device did not reach the expected state; last status {last}")


class AttestationError(Exception):
    pass


class Registry:
    """Devices the vendor has enrolled: keys and the highest state seen."""

    def __init__(self, path):
        self.path = path
        self.devices = {}
        if os.path.exists(path):
            self.devices = json.load(open(path))

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.devices, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def get(self, device_id):
        key = f"{device_id:08x}"
        if key not in self.devices:
            raise KeyError(f"device {key} is not in the registry")
        return self.devices[key]

    def add(self, device_id, dsa_pk, kem_pk, cert):
        self.devices[f"{device_id:08x}"] = {
            "device_id": device_id,
            "dsa_pk": dsa_pk.hex(),
            "kem_pk": kem_pk.hex(),
            "cert": cert.hex(),
            "max_floor": 0,
            "max_receipt_seq": 0,
            "max_journal_seq": 0,
            "receipts": [],
            "history": [],
        }
        self.save()


class Vendor:
    def __init__(self, workdir, vendor_cli, attest_cli, vendor_sk, ca_sk=None):
        self.workdir = workdir
        self.vendor_cli = vendor_cli
        self.mldsa = attest.Mldsa(attest_cli)
        self.vendor_sk = vendor_sk
        self.ca_sk = ca_sk
        self.registry = Registry(os.path.join(workdir, "registry.json"))
        os.makedirs(workdir, exist_ok=True)

    def cli(self, *args):
        p = subprocess.run([self.vendor_cli, *args], capture_output=True)
        if p.returncode != 0:
            raise RuntimeError(f"vendor_cli {args[0]} failed: {p.stderr.decode().strip()}")
        return json.loads(p.stdout) if p.stdout.strip() else {}

    # -- enrollment -----------------------------------------------------
    def register(self, enr1_path):
        enr1 = open(enr1_path, "rb").read()
        info = self.cli("inspect", enr1_path)
        if info.get("kind") != "ENR1" or not info.get("valid"):
            raise AttestationError("ENR1 proof of possession does not verify")
        device_id = struct.unpack("<I", enr1[4:8])[0]
        dsa_pk, kem_pk = enr1[8:8 + 1312], enr1[8 + 1312:8 + 1312 + 800]
        cert_path = os.path.join(self.workdir, f"{device_id:08x}.atc1")
        if self.ca_sk:
            self.cli("issue-cert", "--ca-sk", self.ca_sk, "--enr1", enr1_path, "--out", cert_path)
            cert = open(cert_path, "rb").read()
        else:
            cert = b""
        self.registry.add(device_id, dsa_pk, kem_pk, cert)
        return device_id

    # -- attestation ------------------------------------------------------
    def attest(self, host, port, device_id, wait=30.0):
        """Run the nonce handshake and return the verified report (a dict)."""
        dev = self.registry.get(device_id)
        nonce = secrets.token_bytes(32)
        c = Client(host, port)
        try:
            c.attest_req(nonce)
        finally:
            c.close()
        # The device reboots into the RoT to produce the report. A report that does not
        # carry our nonce is stale (or replayed): keep asking until the deadline.
        end = time.time() + wait
        report = None
        while time.time() < end:
            try:
                c = Client(host, port, timeout=3.0)
                try:
                    obj = c.get_attest()
                finally:
                    c.close()
                candidate = attest2.verify_atr2(obj, bytes.fromhex(dev["dsa_pk"]), self.mldsa)
            except (OSError, ConnectionError, ProtocolError, ValueError):
                time.sleep(0.1)
                continue
            if candidate["verifier_nonce"] == nonce:
                report = candidate
                break
            time.sleep(0.1)
        if report is None:
            raise AttestationError("no report carrying the verifier's nonce arrived")
        if report["device_id"] != device_id:
            raise AttestationError("report names another device")
        state = attest2.DeviceState()
        state.max_floor = dev["max_floor"]
        state.max_receipt_seq = dev["max_receipt_seq"]
        state.max_journal_seq = dev["max_journal_seq"]
        alerts = state.check(report)
        if not alerts:
            dev["max_floor"] = state.max_floor
            dev["max_receipt_seq"] = state.max_receipt_seq
            dev["max_journal_seq"] = state.max_journal_seq
        dev["history"].append({"t": time.time(), "svn": report["svn"], "floor": report["floor"],
                               "alerts": alerts})
        self.registry.save()
        report["alerts"] = alerts
        return report

    # -- deployment -------------------------------------------------------
    def make_package(self, device_id, rot_nonce, image_path, svn, version, key=None, out=None,
                     signer=None):
        dev = self.registry.get(device_id)
        kem_path = os.path.join(self.workdir, f"{device_id:08x}.kem.pk")
        open(kem_path, "wb").write(bytes.fromhex(dev["kem_pk"]))
        out = out or os.path.join(self.workdir, f"pkg-{device_id:08x}-{svn}.bin")
        self.cli("package", "--image", image_path, "--device-id", f"{device_id:08x}", "--kem-pk", kem_path,
                 "--nonce", rot_nonce.hex(), "--svn", str(svn), "--version", version,
                 "--key", signer or self.vendor_sk, "--out", out)
        return out

    def fetch_receipts(self, host, port, device_id):
        """Pull new receipts, verify signatures and the hash chain, remember them."""
        dev = self.registry.get(device_id)
        pk = bytes.fromhex(dev["dsa_pk"])
        have = [bytes.fromhex(r) for r in dev["receipts"]]
        since = attest2.parse_rcp(have[-1][:attest2.RCP_BODY])["seq"] if have else 0
        c = Client(host, port)
        try:
            while True:
                batch = c.get_receipts(since)
                if not batch:
                    break
                have.extend(batch)
                since = attest2.parse_rcp(batch[-1][:attest2.RCP_BODY])["seq"]
        finally:
            c.close()
        first_prev = b"\0" * 32
        first_seq = attest2.parse_rcp(have[0][:attest2.RCP_BODY])["seq"] if have else 1
        if first_seq != 1:
            first_prev = attest2.parse_rcp(have[0][:attest2.RCP_BODY])["prev_digest"]
        parsed = attest2.verify_chain(have, pk, self.mldsa, first_prev) if have else []
        dev["receipts"] = [r.hex() for r in have]
        if parsed:
            # what the receipts prove about the device's history is as good as an attestation
            dev["max_receipt_seq"] = max(dev["max_receipt_seq"], parsed[-1]["seq"])
            dev["max_floor"] = max(dev["max_floor"], parsed[-1]["floor_after"])
        self.registry.save()
        return parsed

    def deploy(self, host, port, device_id, image_path, svn, version, via=None, timeout=60.0,
               signer=None, tamper=None):
        """attest -> package -> push -> wait -> verified receipt. Returns a dict."""
        t0 = time.time()
        report = self.attest(host, port, device_id)
        t_attest = time.time()
        before = report["last_receipt_seq"]
        pkg_path = self.make_package(device_id, report["rot_nonce"], image_path, svn, version, signer=signer)
        pkg = open(pkg_path, "rb").read()
        if tamper:
            pkg = tamper(pkg)
        t_pkg = time.time()
        vh, vp = via if via else (host, port)
        c = Client(vh, vp)
        try:
            c.push_package(pkg)
        finally:
            c.close()
        t_push = time.time()
        st = wait_for(host, port, lambda s: s.get("receipt_seq", 0) > before and not s.get("trial"), timeout)
        t_done = time.time()
        receipts = self.fetch_receipts(host, port, device_id)
        newest = [r for r in receipts if r["seq"] > before]
        last = newest[-1] if newest else None
        return {
            "status": st,
            "receipt": last,
            "outcome": last["outcome_name"] if last else None,
            "reason": last["reason_text"] if last else None,
            "reason_code": last["reason"] if last else None,
            "floor": st.get("floor"),
            "svn": st.get("svn"),
            "timing": {"attest": t_attest - t0, "package": t_pkg - t_attest, "push": t_push - t_pkg,
                       "install_and_trial": t_done - t_push, "total": t_done - t0},
            "package_bytes": len(pkg),
        }
