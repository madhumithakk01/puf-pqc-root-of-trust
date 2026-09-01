"""
Minimal attestation server.

The device signs a report {device_id, fw_version, cnt, nonce} with its
attestation key. This module verifies a device's enrollment certificate against
the CA key, then the report signature, then nonce freshness. ML-DSA-44 itself
is delegated to the `attest_cli` C tool (see tools/attest/); everything here is
protocol and policy, stdlib only.
"""

import secrets
import struct
import subprocess

REPORT_MAGIC = b"ATR1"
REPORT_BYTES = 56
CERT_MAGIC = b"ATC1"
PUBKEY_BYTES = 1312
NONCE_BYTES = 32


def serialize_report(device_id: int, fw_version: int, cnt: int, nonce: bytes) -> bytes:
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be 32 bytes")
    return struct.pack("<4sIQQ", REPORT_MAGIC, device_id, fw_version, cnt) + nonce


def parse_report(report: bytes):
    if len(report) != REPORT_BYTES or report[:4] != REPORT_MAGIC:
        raise ValueError("bad report framing")
    device_id, fw_version, cnt = struct.unpack("<IQQ", report[4:24])
    return device_id, fw_version, cnt, report[24:56]


def make_cert(device_id: int, device_pubkey: bytes, ca_sk: bytes, mldsa) -> bytes:
    if len(device_pubkey) != PUBKEY_BYTES:
        raise ValueError("device pubkey size")
    body = struct.pack("<4sI", CERT_MAGIC, device_id) + device_pubkey
    sig = mldsa.sign(ca_sk, body)
    return body + struct.pack("<I", len(sig)) + sig


def parse_cert(cert: bytes):
    body_len = 8 + PUBKEY_BYTES
    if len(cert) < body_len + 4 or cert[:4] != CERT_MAGIC:
        raise ValueError("bad cert framing")
    (device_id,) = struct.unpack("<I", cert[4:8])
    device_pubkey = cert[8:body_len]
    (sig_len,) = struct.unpack("<I", cert[body_len:body_len + 4])
    sig = cert[body_len + 4:body_len + 4 + sig_len]
    if len(sig) != sig_len or body_len + 4 + sig_len != len(cert):
        raise ValueError("bad cert length")
    return device_id, device_pubkey, sig, cert[:body_len]


class Mldsa:
    """ML-DSA-44 via the attest_cli tool."""

    def __init__(self, cli_path: str):
        self.cli = cli_path

    def _run(self, cmd: str, stdin: str, check: bool = True):
        p = subprocess.run([self.cli, cmd], input=stdin.encode(),
                           capture_output=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"{cmd} failed ({p.returncode}): {p.stderr!r}")
        return p

    def keygen_det(self, seed: bytes):
        out = self._run("keygen-det", seed.hex() + "\n").stdout.decode().split()
        return bytes.fromhex(out[0]), bytes.fromhex(out[1])

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        out = self._run("sign", sk.hex() + "\n" + msg.hex() + "\n").stdout
        return bytes.fromhex(out.decode().strip())

    def verify(self, pk: bytes, sig: bytes, msg: bytes) -> bool:
        p = self._run("verify", pk.hex() + "\n" + sig.hex() + "\n" + msg.hex() + "\n",
                      check=False)
        return p.returncode == 0


class AttestVerifier:
    def __init__(self, ca_pubkey: bytes, mldsa: Mldsa):
        self.ca_pubkey = ca_pubkey
        self.mldsa = mldsa
        self._issued: set[bytes] = set()  # handed out, not yet consumed
        self._consumed: set[bytes] = set()  # already used in an accepted report

    def issue_challenge(self) -> bytes:
        n = secrets.token_bytes(NONCE_BYTES)
        self._issued.add(n)
        return n

    def verify(self, cert: bytes, report: bytes, sig: bytes):
        try:
            cert_id, device_pk, ca_sig, cert_body = parse_cert(cert)
        except ValueError as e:
            return False, f"malformed cert: {e}", None
        if not self.mldsa.verify(self.ca_pubkey, ca_sig, cert_body):
            return False, "bad cert chain", None

        try:
            r_id, r_fw, r_cnt, r_nonce = parse_report(report)
        except ValueError as e:
            return False, f"malformed report: {e}", None
        if r_id != cert_id:
            return False, "device id mismatch", None
        if not self.mldsa.verify(device_pk, sig, report):
            return False, "bad report signature", None

        if r_nonce in self._consumed:
            return False, "replayed nonce", None
        if r_nonce not in self._issued:
            return False, "unknown or stale nonce", None

        self._issued.discard(r_nonce)
        self._consumed.add(r_nonce)
        return True, "accepted", {"device_id": r_id, "fw_version": r_fw, "cnt": r_cnt}


def build_signed_report(device_id: int, fw_version: int, cnt: int, nonce: bytes,
                        device_sk: bytes, mldsa: Mldsa):
    """Client side: what a device would send."""
    report = serialize_report(device_id, fw_version, cnt, nonce)
    return report, mldsa.sign(device_sk, report)
