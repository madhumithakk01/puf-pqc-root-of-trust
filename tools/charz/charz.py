#!/usr/bin/env python3
"""
Drive the characterization firmware (needs pyserial) and tabulate the results.

  charz.py remanence --serial PORT --pairs 20 --method pstate:100 [--out data/charz]
  charz.py loop      --serial PORT --n 200 --ms 100
  charz.py zone      --serial PORT

remanence: for each pair, write 0x00 and then 0xFF over the whole zone, refresh by the
method, and compare the mean ones_permille of the next boot. Delta = mean(ones after FF)
- mean(ones after 00). Fresh SRAM gives |Delta| near 0; retained SRAM gives about +1000.
Raw lines go to DIR/*.jsonl. Key-candidate blocks are never dumped.
"""

import argparse
import json
import os
import statistics
import sys
import time


def open_port(port):
    import serial
    end = time.time() + 30
    while time.time() < end:
        try:
            return serial.Serial(port, 115200, timeout=1.0)
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(port)


def read_zone(ser, log, timeout=30):
    """Collect the 20 block lines printed after a boot; reconnects across reboots."""
    blocks, end = {}, time.time() + timeout
    while time.time() < end and len(blocks) < 20:
        try:
            line = ser.readline().decode("ascii", "replace").strip()
        except Exception:
            ser.close()
            ser = open_port(ser.port)
            continue
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        log.write(line + "\n")
        if j.get("ev") == "zone":
            blocks[j["block"]] = j
    return ser, blocks


def mean_ones(blocks):
    return statistics.mean(b["ones_permille"] for b in blocks.values())


def cmd_remanence(a):
    os.makedirs(a.out, exist_ok=True)
    ser = open_port(a.serial)
    name = a.method.replace(":", "_")
    deltas = []
    with open(os.path.join(a.out, f"remanence-{name}.jsonl"), "w") as log:
        for i in range(a.pairs):
            res = {}
            for pat in ("00", "ff"):
                ser.write(f"remanence {pat} {a.method}\n".encode())
                if a.method in ("run", "por"):
                    input(f"[HUMAN] {'touch RUN to GND for 1 s' if a.method == 'run' else 'unplug USB for 2 s'}, then Enter")
                time.sleep(1.0)
                ser, blocks = read_zone(ser, log)
                if len(blocks) < 20:
                    raise RuntimeError("did not get a full zone report")
                res[pat] = mean_ones(blocks)
            d = res["ff"] - res["00"]
            deltas.append(d)
            print(f"pair {i + 1}: after 00 {res['00']:.0f}, after ff {res['ff']:.0f}, delta {d:.0f}")
    print(f"method {a.method}: mean delta {statistics.mean(deltas):.1f} permille over {len(deltas)} pairs; "
          f"{'FRESH' if abs(statistics.mean(deltas)) <= 10 else 'NOT fresh'}")


def cmd_loop(a):
    os.makedirs(a.out, exist_ok=True)
    ser = open_port(a.serial)
    ser.write(f"loop {a.n} {a.ms}\n".encode())
    seen = 0
    bad = 0
    with open(os.path.join(a.out, "loop.jsonl"), "w") as log:
        while seen < a.n:
            ser, blocks = read_zone(ser, log, timeout=60)
            if len(blocks) < 20:
                break
            seen += 1
            key = blocks[8]
            if not (400 <= key["ones_permille"] <= 600) or key["zero32"] or key["ff32"]:
                bad += 1
    print(f"{seen} boots, {bad} with a key block outside 400-600 permille or with structured chunks")


def cmd_zone(a):
    ser = open_port(a.serial)
    ser.write(b"zone\n")
    with open(os.devnull, "w") as log:
        ser, blocks = read_zone(ser, log)
    for k in sorted(blocks):
        b = blocks[k]
        print(f"block {k:2d}  ones {b['ones_permille']:4d}  zero32 {b['zero32']:3d}  ff32 {b['ff32']:3d}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("remanence", "loop", "zone"):
        p = sub.add_parser(n)
        p.add_argument("--serial", required=True)
        p.add_argument("--out", default="data/charz")
    sub.choices["remanence"].add_argument("--pairs", type=int, default=20)
    sub.choices["remanence"].add_argument("--method", default="pstate:100")
    sub.choices["loop"].add_argument("--n", type=int, default=100)
    sub.choices["loop"].add_argument("--ms", type=int, default=100)
    a = ap.parse_args()
    {"remanence": cmd_remanence, "loop": cmd_loop, "zone": cmd_zone}[a.cmd](a)


if __name__ == "__main__":
    main()
