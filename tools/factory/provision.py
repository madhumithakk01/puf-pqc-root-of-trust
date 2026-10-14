#!/usr/bin/env python3
"""
Factory flow for one board (requires the board; steps marked [HUMAN] need a person).

  1. [HUMAN] hold BOOTSEL, plug in USB.
  2. picotool load rot.uf2  -> the RoT image with the partition table.
  3. enroll over USB serial: ENROLL <vendor pk>; the RoT refreshes its SRAM five times,
     builds the helper data and prints ENR1.
  4. register ENR1 with the vendor (issues the certificate).
  5. load the v1.0 image into slot A with picotool --ignore-partitions, read it back,
     compare hashes, reboot.
  6. back up rot_data (public data) for recovery.

usage: provision.py --rot rot.uf2 --vendor-pk vendor.pk --image v1_0_0.sbi.bin --serial /dev/ttyACM0
                    --out DIR [--registry DIR --vendor-cli B --attest-cli B --vendor-sk F --ca-sk F]
"""

import argparse
import hashlib
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "flash"))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))

import pico_ops  # noqa: E402
import enroll as enroll_mod  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rot", required=True)
    ap.add_argument("--vendor-pk", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--serial", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--picotool", default=None)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    dev = pico_ops.PicoDevice(a.out, picotool=a.picotool)

    print("[HUMAN] hold BOOTSEL while plugging in USB, then press Enter")
    input()
    dev._pt("load", "-x", a.rot)
    time.sleep(3)

    enr1 = os.path.join(a.out, "device.enr1")
    enroll_mod.enroll(a.serial, a.vendor_pk, enr1)
    print("enrolled; ENR1 saved to", enr1)

    dev.stop()
    img = open(a.image, "rb").read()
    dev.provision_image(0, img)
    back = dev.read_flash(pico_ops.devproc.SLOT_OFF[0], len(img))
    ok = hashlib.sha256(back).digest() == hashlib.sha256(img).digest()
    print("slot A read-back", "matches" if ok else "DIFFERS")
    if not ok:
        return 1
    dev.dump_rot_data(os.path.join(a.out, "rot_data_enrolled.bin"))
    dev.start()
    print("done; register", enr1, "with the vendor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
