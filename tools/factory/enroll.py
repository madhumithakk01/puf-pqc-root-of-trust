#!/usr/bin/env python3
"""
Drive RoT enrollment over USB serial (needs pyserial).

  enroll.py --serial PORT --vendor-pk FILE --out device.enr1

The RoT, unenrolled, prints {"ev":"unenrolled"} every two seconds. We send
ENROLL <vendor public key in hex>; it then reboots five times through an SRAM
power-down (the port disappears and comes back each time), and finally prints
the ENR1 proof of possession as one hex line.
"""

import argparse
import sys
import time


def _open(port, timeout=1.0):
    import serial
    end = time.time() + 30
    while time.time() < end:
        try:
            return serial.Serial(port, 115200, timeout=timeout)
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"{port} did not come back")


def enroll(port, vendor_pk_path, out_path, overall_timeout=180):
    pk = open(vendor_pk_path, "rb").read()
    if len(pk) != 1312:
        raise ValueError("vendor public key must be an ML-DSA-44 key (1312 bytes)")
    ser = _open(port)
    sent = False
    end = time.time() + overall_timeout
    while time.time() < end:
        try:
            line = ser.readline().decode("ascii", "replace").strip()
        except Exception:
            ser.close()
            ser = _open(port)
            continue
        if not line:
            continue
        print(line)
        if '"ev":"unenrolled"' in line and not sent:
            ser.write(b"ENROLL " + pk.hex().encode() + b"\n")
            sent = True
        elif line.startswith("ENR1 "):
            data = bytes.fromhex(line[5:])
            open(out_path, "wb").write(data)
            ser.close()
            return data
        elif '"ev":"enroll_failed"' in line:
            raise RuntimeError(line)
    raise TimeoutError("enrollment did not finish")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", required=True)
    ap.add_argument("--vendor-pk", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    enroll(a.serial, a.vendor_pk, a.out)
    print("wrote", a.out)
