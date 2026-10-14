"""
ATR2 attestation reports and RCP1 install receipts (verifier side).

Both objects are signed by the device's ML-DSA-44 identity key. ML-DSA itself
is delegated to the `Mldsa` wrapper in attest.py; everything here is framing
and policy, stdlib only. The ATR1 code in attest.py is unchanged.
"""

import hashlib
import struct

ATR2_MAGIC = b"ATR2"
ATR2_BODY = 192
RCP_MAGIC = b"RCP1"
RCP_BODY = 256
SIG_BYTES = 2420
ATR2_TOTAL = ATR2_BODY + 4 + SIG_BYTES
RCP_TOTAL = RCP_BODY + 4 + SIG_BYTES

OUTCOME_COMMITTED, OUTCOME_ROLLED_BACK, OUTCOME_REFUSED = 1, 2, 3
OUTCOME_NAMES = {1: "COMMITTED", 2: "ROLLED_BACK", 3: "REFUSED"}

REASONS = {
    0: "OK",
    1: "package malformed",
    2: "unknown signer",
    3: "not for this device",
    4: "stale nonce",
    5: "SVN below floor",
    6: "package authentication failed (digest)",
    7: "package authentication failed (MAC)",
    8: "image malformed",
    9: "image signature invalid",
    10: "image SVN below floor",
    11: "image SVN mismatch",
    12: "app manifest invalid",
    20: "health check failed: heart rate",
    21: "health check failed: SpO2",
    22: "health check failed: sensor",
    23: "health check timed out",
    24: "power lost during trial",
    25: "health report SVN mismatch",
}


def _h(label: bytes, data: bytes) -> bytes:
    return hashlib.shake_256(label + data).digest(32)


def serialize_atr2(f: dict) -> bytes:
    body = struct.pack(
        "<4sIQQ32s32s32sBBBBIIHB",
        ATR2_MAGIC, f["device_id"], f["svn"], f["floor"], f["verifier_nonce"],
        f["rot_nonce"], f["image_digest"], f["active_slot"], f["trial_state"],
        f["reset_cause"], f["flags"], f["journal_seq"], f["last_receipt_seq"],
        f["bits_corrected"], f["worst_block"])
    body += b"\0"  # reserved at 135
    body += f["last_receipt_digest"] + f["version"].ljust(16, b"\0") + b"\0" * 8
    assert len(body) == ATR2_BODY
    return body


def parse_atr2(body: bytes) -> dict:
    if len(body) != ATR2_BODY or body[:4] != ATR2_MAGIC:
        raise ValueError("bad ATR2 framing")
    if body[135] != 0 or any(body[184:]):
        raise ValueError("ATR2 reserved bytes set")
    (dev, svn, floor) = struct.unpack("<IQQ", body[4:24])
    slot, trial, cause, flags, jseq, rseq, bits, worst = struct.unpack(
        "<BBBBIIHB", body[120:135])
    return {
        "device_id": dev, "svn": svn, "floor": floor,
        "verifier_nonce": body[24:56], "rot_nonce": body[56:88],
        "image_digest": body[88:120], "active_slot": slot, "trial_state": trial,
        "reset_cause": cause, "flags": flags, "sim_puf": bool(flags & 1),
        "pmp_locked": bool(flags & 2), "journal_seq": jseq,
        "last_receipt_seq": rseq, "bits_corrected": bits, "worst_block": worst,
        "last_receipt_digest": body[136:168],
        "version": body[168:184].rstrip(b"\0").decode("ascii", "replace"),
    }


def serialize_rcp(f: dict) -> bytes:
    body = struct.pack(
        "<4sIIBBBxQQQQ32s32s32s32s32sI16s28x",
        RCP_MAGIC, f["seq"], f["device_id"], f["outcome"], f["reason"], f["slot"],
        f["from_svn"], f["to_svn"], f["floor_before"], f["floor_after"],
        f["image_digest"], f["package_digest"], f["rot_nonce"],
        f["evidence_digest"], f["prev_digest"], f["journal_seq"],
        f["version"].ljust(16, b"\0"))
    assert len(body) == RCP_BODY
    return body


def parse_rcp(body: bytes) -> dict:
    if len(body) != RCP_BODY or body[:4] != RCP_MAGIC:
        raise ValueError("bad RCP1 framing")
    if body[15] != 0 or any(body[228:]):
        raise ValueError("RCP1 reserved bytes set")
    seq, dev, outcome, reason, slot = struct.unpack("<IIBBB", body[4:15])
    frm, to, fb, fa = struct.unpack("<QQQQ", body[16:48])
    (jseq,) = struct.unpack("<I", body[208:212])
    return {
        "seq": seq, "device_id": dev, "outcome": outcome,
        "outcome_name": OUTCOME_NAMES.get(outcome, "?"), "reason": reason,
        "reason_text": REASONS.get(reason, "?"), "slot": slot,
        "from_svn": frm, "to_svn": to, "floor_before": fb, "floor_after": fa,
        "image_digest": body[48:80], "package_digest": body[80:112],
        "rot_nonce": body[112:144], "evidence_digest": body[144:176],
        "prev_digest": body[176:208], "journal_seq": jseq,
        "version": body[212:228].rstrip(b"\0").decode("ascii", "replace"),
    }


def _split(obj: bytes, body_len: int, total: int):
    if len(obj) != total:
        raise ValueError("bad signed object length")
    (sig_len,) = struct.unpack("<I", obj[body_len:body_len + 4])
    if sig_len != SIG_BYTES:
        raise ValueError("bad signature length")
    return obj[:body_len], obj[body_len + 4:]


def verify_atr2(obj: bytes, device_pk: bytes, mldsa):
    """Returns the parsed report if the signature verifies, else raises."""
    body, sig = _split(obj, ATR2_BODY, ATR2_TOTAL)
    report = parse_atr2(body)
    if not mldsa.verify(device_pk, sig, body):
        raise ValueError("bad ATR2 signature")
    return report


def verify_rcp(obj: bytes, device_pk: bytes, mldsa):
    body, sig = _split(obj, RCP_BODY, RCP_TOTAL)
    receipt = parse_rcp(body)
    if not mldsa.verify(device_pk, sig, body):
        raise ValueError("bad RCP1 signature")
    return receipt


def chain_digest(obj: bytes) -> bytes:
    """Digest the next receipt carries as prev_digest."""
    return _h(b"rcp/v1/chain", obj)


def verify_chain(objs, device_pk: bytes, mldsa, first_prev: bytes = b"\0" * 32):
    """Verify consecutive receipts, oldest first. Returns the parsed list.

    Raises ValueError naming the 1-based index of the first bad receipt.
    """
    expect = first_prev
    out = []
    for i, obj in enumerate(objs, 1):
        try:
            r = verify_rcp(obj, device_pk, mldsa)
        except ValueError as e:
            raise ValueError(f"receipt {i}: {e}") from None
        if r["prev_digest"] != expect:
            raise ValueError(f"receipt {i}: chain break")
        if out and r["seq"] != out[-1]["seq"] + 1:
            raise ValueError(f"receipt {i}: sequence gap")
        out.append(r)
        expect = chain_digest(obj)
    return out


class DeviceState:
    """Per-device monotonicity policy applied to attestations.

    A decrease in the floor or the receipt sequence means the device's flash
    was restored from an older snapshot.
    """

    def __init__(self):
        self.max_floor = 0
        self.max_receipt_seq = 0
        self.max_journal_seq = 0

    def check(self, report: dict):
        """Returns a list of alerts; empty when the report is consistent."""
        alerts = []
        if report["floor"] < self.max_floor:
            alerts.append("STATE ROLLBACK: floor decreased")
        if report["last_receipt_seq"] < self.max_receipt_seq:
            alerts.append("STATE ROLLBACK: receipt sequence decreased")
        if report["journal_seq"] < self.max_journal_seq:
            alerts.append("STATE ROLLBACK: journal sequence decreased")
        if not alerts:
            self.max_floor = max(self.max_floor, report["floor"])
            self.max_receipt_seq = max(self.max_receipt_seq, report["last_receipt_seq"])
            self.max_journal_seq = max(self.max_journal_seq, report["journal_seq"])
        return alerts
