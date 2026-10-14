#!/usr/bin/env python3
"""
Run the attack scenarios N times each against a software device and write
one CSV row per run plus a summary table.

  runner.py --runs 20 --vendor-cli B --attest-cli B --softdev B [--only A1,A3] [--out DIR]

Exit status is 0 only if every run produced the expected outcome.
"""

import argparse
import csv
import os
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import lab as labmod  # noqa: E402
import scenarios  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--vendor-cli", required=True)
    ap.add_argument("--attest-cli", required=True)
    ap.add_argument("--softdev", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "..", "data", "attacks"))
    a = ap.parse_args()

    names = [n for n in scenarios.SCENARIOS if not a.only or n in a.only.split(",")]
    os.makedirs(a.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="attack_runner_")
    lab = labmod.Lab(work, os.path.abspath(a.vendor_cli), os.path.abspath(a.attest_cli), os.path.abspath(a.softdev)).build()

    rows, tally = [], {n: [0, 0] for n in names}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(a.out, f"attacks-{stamp}.csv")
    try:
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["scenario", "run", "expected", "observed", "ok", "seconds", "detail"])
            for n in names:
                for i in range(1, a.runs + 1):
                    t0 = time.time()
                    try:
                        r = scenarios.SCENARIOS[n](lab)
                    except Exception as e:  # a crash is a failed run, recorded with its trace
                        r = {"expected": "?", "observed": "exception: " + repr(e), "ok": False,
                             "detail": traceback.format_exc(limit=3).replace("\n", " | ")}
                        try:
                            lab.ensure_running()
                        except Exception:
                            pass
                    dt = time.time() - t0
                    w.writerow([n, i, r["expected"], r["observed"], int(r["ok"]), f"{dt:.2f}", r["detail"]])
                    f.flush()
                    tally[n][0] += 1
                    tally[n][1] += 1 if r["ok"] else 0
    finally:
        lab.close()

    total = sum(t[0] for t in tally.values())
    good = sum(t[1] for t in tally.values())
    lines = [f"{'#':<4}{'attack':<58}{'runs':>5}{'as expected':>13}"]
    for n in names:
        lines.append(f"{n:<4}{scenarios.NAMES[n]:<58}{tally[n][0]:>5}{tally[n][1]:>13}")
    lines.append(f"{'':<4}{'total':<58}{total:>5}{good:>13}")
    text = "\n".join(lines)
    print(text)
    with open(os.path.join(a.out, f"summary-{stamp}.txt"), "w") as f:
        f.write(text + "\n")
    print("rows:", path)
    return 0 if good == total else 1


if __name__ == "__main__":
    sys.exit(main())
