#!/usr/bin/env python3
"""
Attacks A7 and A8 on the real board: offline tampering of the stored application images.

  python tools\\demo\\offline_attacks.py A7|A8 [--workdir DIR] [--seconds 30]

Run from Windows PowerShell (needs picotool and pyserial). The board must be running, enrolled, reachable on
Wi-Fi and at floor 2 or higher, so that the v1.0 image is below the floor. Nothing here writes OTP.

  A7  the attacker flips one bit of the active image (offset 5000 of the slot) and puts the genuine v1.0 image
      in the other slot. By design the RoT refuses both at boot: SAFE mode, NO_VALID_IMAGE, image reason
      IMG_BAD_SIGNATURE (9).
  A8  the attacker overwrites both slots with the genuine, correctly signed v1.0 image. By design the RoT
      refuses them against the PUF-sealed floor: SAFE mode, NO_VALID_IMAGE, image reason IMG_BELOW_FLOOR (10).

The same tampering as tools/attacker/scenarios.py a7 and a8 use against the simulated device (through
tools/flash/pico_ops.PicoDevice), but the outcome is read from the RoT's USB console, because the RoT has no
network in SAFE mode. The full flash image of both slots and the rot_data region are saved before the attack; the
images are written back afterwards, verified byte for byte against the snapshot, and the board is checked to come
back with the same version, SVN, floor and slot. Lines the host cannot see (printed before the USB port was
re-opened) are not invented.
"""

import argparse
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for sub in ("flash", "attacker", "vendor"):
    sys.path.insert(0, os.path.join(ROOT, "tools", sub))
sys.path.insert(0, os.path.join(ROOT, "server", "attest"))
sys.path.insert(0, HERE)

import board       # noqa: E402  (picotool lookup and the BOOTSEL entry used by fresh-demo)
import devproc     # noqa: E402
import pico_ops    # noqa: E402
import vendor_lib as vl  # noqa: E402

IMAGE_AREA = 0x5E000          # the 380868-byte images rounded up to a 4 KB boundary
TAMPER_OFFSET = 5000
REASON = {"IMG_BAD_SIGNATURE": 9, "IMG_BELOW_FLOOR": 10}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Console:
    """Fast-reconnect reader of the board's USB console."""

    def __init__(self):
        self.lines = []
        self.stop = False

    def run(self, seconds):
        import serial
        from serial.tools import list_ports
        end = time.time() + seconds
        port = None
        while port is None and time.time() < end:
            port = next((p.device for p in list_ports.comports() if p.vid == 0x2E8A), None)
            time.sleep(0.05)
        buf = b""
        while time.time() < end and not self.stop and port:
            try:
                s = serial.Serial(port, 115200, timeout=0.05)
                s.dtr = True
                buf = b""
                while time.time() < end and not self.stop:
                    chunk = s.read(256)
                    if chunk:
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            text = line.decode("ascii", "replace").strip()
                            if text:
                                self.lines.append((now(), text))
                s.close()
            except (serial.SerialException, OSError):
                time.sleep(0.005)


def wait_board(host, want, timeout=120):
    """Poll HELLO every 2 s until the board answers; return the status or None."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            c = vl.Client(host, 7000, timeout=4)
            try:
                st = c.hello()
            finally:
                c.close()
            if not st.get("trial"):
                return st
        except (OSError, ConnectionError, vl.ProtocolError, ValueError):
            pass
        time.sleep(2)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attack", choices=["A7", "A8"])
    ap.add_argument("--workdir", default=os.path.join(ROOT, "data", "offline-attacks"))
    ap.add_argument("--seconds", type=float, default=30, help="how long to watch the console after the reboot")
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)
    tag = a.attack
    res = {"attack": tag, "started": now()}
    host = open(os.path.join(ROOT, "data", "demo", "device.ip")).read().strip()
    old = open(os.path.join(ROOT, "data", "demo", "v1_0_0.sbi.bin"), "rb").read()
    assert len(old) <= IMAGE_AREA

    print(f"[{tag}] reading the board's state over Wi-Fi", flush=True)
    c = vl.Client(host, 7000, timeout=10)
    try:
        before = c.hello()
    finally:
        c.close()
    res["before"] = {k: before.get(k) for k in ("device_id", "version", "svn", "floor", "slot", "slot_status", "receipt_seq")}
    print("   ", res["before"], flush=True)
    if before["floor"] < 2:
        sys.exit("floor is %s: the v1.0 image is not below it. Deploy v1.1 first." % before["floor"])

    dev = pico_ops.PicoDevice(a.workdir, picotool=board.picotool(), host=host)

    print(f"[{tag}] entering BOOTSEL and taking the snapshot (about 30 s)", flush=True)
    board.to_bootsel()
    dev.proc = None
    snap = {
        "rot_data": dev.read_flash(devproc.DATA_OFF, devproc.DATA_SIZE),
        "slot0": dev.read_flash(devproc.SLOT_OFF[0], devproc.SLOT_SIZE),
        "slot1": dev.read_flash(devproc.SLOT_OFF[1], devproc.SLOT_SIZE),
    }
    for k, v in snap.items():
        open(os.path.join(a.workdir, f"{tag}-snapshot-{k}.bin"), "wb").write(v)
    res["snapshot_sha256"] = {k: sha(v) for k, v in snap.items()}
    print("   snapshot sha256:", {k: h[:16] for k, h in res["snapshot_sha256"].items()}, flush=True)

    active = before["slot"]
    print(f"[{tag}] tampering", flush=True)
    if tag == "A7":
        dev.write_flash(devproc.SLOT_OFF[1 - active], old)
        head = bytearray(snap["slot%d" % active][:0x2000])
        head[TAMPER_OFFSET] ^= 0x01
        dev.write_flash(devproc.SLOT_OFF[active], bytes(head))
        res["tamper"] = f"genuine v1.0 image written to slot {'AB'[1 - active]}; bit 0 of byte {TAMPER_OFFSET} flipped in slot {'AB'[active]}"
        expect = REASON["IMG_BAD_SIGNATURE"]
    else:
        for slot in (0, 1):
            dev.write_flash(devproc.SLOT_OFF[slot], old)
        res["tamper"] = "genuine v1.0 image written to both slots"
        expect = REASON["IMG_BELOW_FLOOR"]
    print("   ", res["tamper"], flush=True)

    print(f"[{tag}] rebooting and watching the USB console for {a.seconds:.0f} s", flush=True)
    con = Console()
    th = threading.Thread(target=con.run, args=(a.seconds,), daemon=True)
    th.start()
    time.sleep(0.5)
    t_reboot = now()
    dev.start()
    th.join()
    res["reboot_at"] = t_reboot
    res["console"] = [{"t": t, "line": l} for t, l in con.lines]
    safe = [json.loads(l) for _, l in con.lines if l.startswith("{") and '"ev":"safe"' in l.replace(" ", "")]
    res["safe_events_seen"] = len(safe)
    observed = safe[-1] if safe else None
    res["observed"] = observed
    res["expected"] = {"ev": "safe", "reason": "NO_VALID_IMAGE", "image_reason": expect}
    res["outcome_ok"] = bool(observed and observed.get("reason") == "NO_VALID_IMAGE" and observed.get("image_reason") == expect)
    for t, l in con.lines:
        print("   ", t[11:23], l[:160], flush=True)
    print(f"[{tag}] observed: {observed}   expected image_reason {expect}   -> {'AS DESIGNED' if res['outcome_ok'] else 'NOT AS DESIGNED'}", flush=True)

    print(f"[{tag}] restoring the images from the snapshot (about 1 minute)", flush=True)
    board.to_bootsel()
    dev.proc = None
    for slot in (0, 1):
        dev.write_flash(devproc.SLOT_OFF[slot], snap["slot%d" % slot][:IMAGE_AREA])
    verify = {}
    for slot in (0, 1):
        back = dev.read_flash(devproc.SLOT_OFF[slot], IMAGE_AREA)
        verify["slot%d" % slot] = back == snap["slot%d" % slot][:IMAGE_AREA]
    after_data = dev.read_flash(devproc.DATA_OFF, devproc.DATA_SIZE)
    res["restore_images_identical"] = verify
    res["rot_data_changed_by_the_attacked_boot"] = after_data != snap["rot_data"]
    res["rot_data_bytes_changed"] = sum(1 for x, y in zip(after_data, snap["rot_data"]) if x != y)
    open(os.path.join(a.workdir, f"{tag}-rot_data-after.bin"), "wb").write(after_data)
    print("   images identical to the snapshot:", verify, "| rot_data bytes changed during the attacked boot:",
          res["rot_data_bytes_changed"], flush=True)
    dev.start()
    print(f"[{tag}] waiting for the board on Wi-Fi", flush=True)
    st = wait_board(host, before)
    res["after"] = ({k: st.get(k) for k in ("device_id", "version", "svn", "floor", "slot", "slot_status", "receipt_seq")}
                    if st else None)
    res["restore_ok"] = bool(st and all(verify.values()) and all(st.get(k) == before.get(k)
                                                                for k in ("device_id", "version", "svn", "floor", "slot")))
    print("   after:", res["after"], "-> restore", "OK" if res["restore_ok"] else "FAILED", flush=True)
    res["finished"] = now()
    out = os.path.join(a.workdir, f"{tag}-result.json")
    json.dump(res, open(out, "w"), indent=1)
    print("result written to", out)
    sys.exit(0 if res["outcome_ok"] and res["restore_ok"] else 1)


if __name__ == "__main__":
    main()
