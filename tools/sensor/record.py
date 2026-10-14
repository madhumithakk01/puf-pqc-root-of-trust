#!/usr/bin/env python3
"""
Record a trace from the recorder firmware (needs pyserial).

  record.py --serial PORT --seconds 20 --out data/traces/rest1.csv

Writes "red,ir" rows of raw 18-bit values, dropping diagnostic '#' lines.
"""

import argparse
import os
import time


def main():
    import serial
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", required=True)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    ser = serial.Serial(a.serial, 115200, timeout=1)
    rows = 0
    end = time.time() + a.seconds
    with open(a.out, "w") as f:
        f.write("red,ir\n")
        while time.time() < end:
            line = ser.readline().decode("ascii", "replace").strip()
            if not line or line[0] in "#r":
                continue
            parts = line.split(",")
            if len(parts) == 2 and all(p.isdigit() for p in parts):
                f.write(line + "\n")
                rows += 1
    print(f"{rows} samples in {a.seconds:.0f} s ({rows / a.seconds:.1f} per second)")


if __name__ == "__main__":
    main()
