"""
The nine attack scenarios against the update path and the stored images.

Each scenario brings the device to a known baseline, runs the attack, and
returns {"expected", "observed", "ok", "detail"}. "Expected" is what a
correct RoT must do, taken from the design: for network attacks a REFUSED
receipt with a specific reason (and the point of the pipeline that stops
it); for the offline attacks SAFE mode with the image reason; for the faulty
genuine update a ROLLED_BACK receipt.
"""

import hashlib
import math
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "relay"))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))

import devproc  # noqa: E402
import relay as relaymod  # noqa: E402
import vendor_lib as vl  # noqa: E402

REASON = {"PKG_AUTH_FAILED": 6, "PKG_UNKNOWN_SIGNER": 2, "PKG_BELOW_FLOOR": 5, "PKG_STALE_NONCE": 4,
          "PKG_WRONG_DEVICE": 3, "IMG_BAD_SIGNATURE": 9, "IMG_BELOW_FLOOR": 10, "HEALTH_FAIL_BPM": 20}
DLV_PREFIX = 2552

NAMES = {
    "A1": "tampered package (one byte flipped in transit)",
    "A2": "forged vendor (own key, right device id, current nonce)",
    "A3": "downgrade with the genuine vendor key",
    "A4": "replay of a captured genuine package",
    "A5": "package for another device",
    "A6": "eavesdropping (ciphertext only)",
    "A7": "offline tamper of the active image",
    "A8": "offline downgrade of the active image",
    "A9": "faulty but genuine update (v1.2)",
}


def _result(expected, observed, ok, detail=""):
    return {"expected": expected, "observed": observed, "ok": ok, "detail": detail}


def baseline(lab):
    """v1.1 committed, floor 2 (or higher), device running."""
    lab.ensure_running()
    st = lab.status()
    if st.get("mode") == "SAFE":
        raise RuntimeError("device is in SAFE mode at the start of a scenario")
    if st["floor"] < 2:
        res = lab.deploy("1.1.0")
        if res["outcome"] != "COMMITTED":
            raise RuntimeError(f"baseline deploy failed: {res['outcome']} {res['reason']}")
    return lab.status()


def _outcome(res):
    return f"{res['outcome']}/{res['reason_code']}"


def a1(lab):
    st = baseline(lab)
    r = relaymod.Relay(0, lab.addr, flip=DLV_PREFIX + 500).start()
    try:
        res = lab.deploy("1.2.0", via=("127.0.0.1", r.port))
    finally:
        r.close()
    ok = res["outcome"] == "REFUSED" and res["reason_code"] == REASON["PKG_AUTH_FAILED"] and r.flipped >= 1
    ok = ok and res["floor"] == st["floor"] and res["svn"] == st["svn"]
    return _result("REFUSED/6", _outcome(res), ok, "stopped at the digest check under the vendor signature")


def a2(lab):
    baseline(lab)
    res = lab.deploy("1.2.0", signer=lab.p("mallory.sk"))
    return _result("REFUSED/2", _outcome(res), res["outcome"] == "REFUSED" and res["reason_code"] == REASON["PKG_UNKNOWN_SIGNER"],
                   "stopped at the sealed anchor")


def a3(lab):
    st = baseline(lab)
    res = lab.deploy("1.0.0")
    ok = res["outcome"] == "REFUSED" and res["reason_code"] == REASON["PKG_BELOW_FLOOR"] and res["floor"] == st["floor"]
    return _result("REFUSED/5", _outcome(res), ok, "stopped at the floor check, before decapsulation")


def a4(lab):
    baseline(lab)
    rec = os.path.join(lab.workdir, "capture")
    r = relaymod.Relay(0, lab.addr, record_dir=rec).start()
    try:
        genuine = lab.deploy("1.1.0", via=("127.0.0.1", r.port))
    finally:
        r.close()
    if genuine["outcome"] != "COMMITTED":
        return _result("REFUSED/4", "genuine deploy failed: " + _outcome(genuine), False)
    streams = sorted(f for f in os.listdir(rec) if f.startswith("stream-") and os.path.getsize(os.path.join(rec, f)) > 10000)
    stream = open(os.path.join(rec, streams[-1]), "rb").read()
    before = lab.status()["receipt_seq"]
    relaymod.replay(lab.addr, stream)
    st = vl.wait_for(*lab.addr, lambda s: s.get("receipt_seq", 0) > before and not s.get("trial"), 30)
    last = lab.vendor.fetch_receipts(*lab.addr, lab.device_id)[-1]
    ok = last["outcome"] == 3 and last["reason"] == REASON["PKG_STALE_NONCE"]
    return _result("REFUSED/4", f"{last['outcome_name']}/{last['reason']}", ok, "stopped by the one-time RoT nonce")


def a5(lab):
    baseline(lab)
    report = lab.vendor.attest(*lab.addr, lab.device_id)
    out = lab.p("pkg-for-other.bin")
    lab.cli("package", "--image", lab.images["1.2.0"], "--device-id", f"{lab.other_device_id:08x}", "--kem-pk",
            lab.p("other.kem.pk"), "--nonce", report["rot_nonce"].hex(), "--svn", "3", "--version", "1.2.0",
            "--key", lab.p("vendor.sk"), "--out", out)
    pkg = open(out, "rb").read()
    before = lab.status()["receipt_seq"]
    c = vl.Client(*lab.addr)
    try:
        c.push_package(pkg)
    finally:
        c.close()
    vl.wait_for(*lab.addr, lambda s: s.get("receipt_seq", 0) > before and not s.get("trial"), 30)
    last = lab.vendor.fetch_receipts(*lab.addr, lab.device_id)[-1]
    ok = last["outcome"] == 3 and last["reason"] == REASON["PKG_WRONG_DEVICE"]
    return _result("REFUSED/3", f"{last['outcome_name']}/{last['reason']}", ok, "stopped at the device id check")


def entropy(data):
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in hist if c)


def a6(lab):
    baseline(lab)
    rec = os.path.join(lab.workdir, "capture6")
    r = relaymod.Relay(0, lab.addr, record_dir=rec).start()
    try:
        res = lab.deploy("1.1.0", via=("127.0.0.1", r.port))
    finally:
        r.close()
    pkgs = [p for p in r.packages if len(p) > 10000]
    if not pkgs:
        return _result("ciphertext only", "nothing captured", False)
    pkg = pkgs[-1]
    ota = pkg[DLV_PREFIX:]
    ct = ota[8 + 768 + 24 + 8:-32]
    h = entropy(ct)
    plain = open(lab.images["1.1.0"], "rb").read()
    leaks = [s for s in (b"SBI1", b"APM1", b"pulse-oximeter application", b"1.1.0") if s in ota]
    ok = h > 7.9 and not leaks and plain[4096:4096 + 64] not in pkg and res["outcome"] == "COMMITTED"
    return _result("ciphertext only", f"{h:.3f} bits/byte, leaks={leaks}", ok,
                   "ML-KEM-512 + SHAKE256 encrypt-then-MAC; the plaintext image has visible version strings")


def a7(lab):
    st = baseline(lab)
    d = lab.dev
    d.stop()
    snap = d.snapshot()
    old = open(lab.images["1.0.0"], "rb").read()
    inactive = 1 - st["slot"]
    d.write_flash(devproc.SLOT_OFF[inactive], b"\xff" * len(old))
    d.provision_image(inactive, old)               # an image below the floor in the other slot
    d.tamper_byte(st["slot"], 5000)
    d.start()
    s = vl.wait_for(*d.addr, lambda x: x.get("mode") == "SAFE", 20)
    ok = s.get("reason") == "NO_VALID_IMAGE" and s.get("image_reason") == REASON["IMG_BAD_SIGNATURE"]
    d.stop()
    d.restore(snap)
    d.start()
    back = lab.status()
    ok = ok and back.get("mode") != "SAFE" and back["svn"] == st["svn"]
    return _result("SAFE/IMG_BAD_SIGNATURE", f"{s.get('mode')}/{s.get('reason')}/{s.get('image_reason')}", ok,
                   "refused at boot by ML-DSA verification; restored afterwards")


def a8(lab):
    st = baseline(lab)
    d = lab.dev
    d.stop()
    snap = d.snapshot()
    old = open(lab.images["1.0.0"], "rb").read()
    for slot in (0, 1):
        d.write_flash(devproc.SLOT_OFF[slot], b"\xff" * len(old))
        d.provision_image(slot, old)
    d.start()
    s = vl.wait_for(*d.addr, lambda x: x.get("mode") == "SAFE", 20)
    ok = s.get("reason") == "NO_VALID_IMAGE" and s.get("image_reason") == REASON["IMG_BELOW_FLOOR"]
    d.stop()
    d.restore(snap)
    d.start()
    back = lab.status()
    ok = ok and back.get("mode") != "SAFE" and back["floor"] == st["floor"]
    return _result("SAFE/IMG_BELOW_FLOOR", f"{s.get('mode')}/{s.get('reason')}/{s.get('image_reason')}", ok,
                   "genuine old images refused against the PUF-sealed floor; restored afterwards")


def a9(lab):
    st = baseline(lab)
    res = lab.deploy("1.2.0")
    ok = (res["outcome"] == "ROLLED_BACK" and res["reason_code"] == REASON["HEALTH_FAIL_BPM"]
          and res["floor"] == st["floor"] and res["svn"] == st["svn"])
    return _result("ROLLED_BACK/20", _outcome(res), ok, "trial ran, golden-trace BPM failed against the signed limits")


SCENARIOS = {"A1": a1, "A2": a2, "A3": a3, "A4": a4, "A5": a5, "A6": a6, "A7": a7, "A8": a8, "A9": a9}
