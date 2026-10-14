#!/usr/bin/env python3
"""
Reference heart rate and SpO2 for a recorded trace, by a method independent of
the firmware DSP (zero-crossing of the band-passed signal and a least-squares
ratio of ratios), for choosing and validating the golden trace.

  label.py trace.csv [--plot out.png]    (--plot needs matplotlib, optional)

Prints JSON: beats counted, reference BPM, reference SpO2 (uncalibrated formula
110 - 25 R), and the beat times so a person can count peaks on the plot.
"""

import argparse
import json
import math


def load(path):
    red, ir = [], []
    for line in open(path):
        line = line.strip()
        if not line or line[0] in "#r":
            continue
        a, b = line.split(",")[:2]
        red.append(int(a))
        ir.append(int(b))
    return red, ir


def moving_mean(x, w):
    out, acc = [], 0.0
    for i, v in enumerate(x):
        acc += v
        if i >= w:
            acc -= x[i - w]
        out.append(acc / min(i + 1, w))
    return out


def bandpass(x, fs=100):
    slow = moving_mean(x, fs)                       # remove DC and drift
    fast = moving_mean([a - b for a, b in zip(x, slow)], 5)   # smooth
    return fast


def beats(sig, fs=100):
    """Beat times from upward zero crossings of the inverted, band-passed signal."""
    inv = [-v for v in sig]
    out, last = [], -fs
    for i in range(fs * 2, len(inv)):
        if inv[i - 1] < 0 <= inv[i] and i - last >= 0.3 * fs:
            out.append(i / fs)
            last = i
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--plot")
    a = ap.parse_args()
    red, ir = load(a.trace)
    fs = 100
    sig = bandpass(ir, fs)
    bt = beats(sig, fs)
    rr = [b - c for c, b in zip(bt, bt[1:])]
    bpm = 60.0 / (sorted(rr)[len(rr) // 2]) if rr else None
    hr, hi = bandpass(red, fs), sig
    rms = lambda v: math.sqrt(sum(x * x for x in v[fs * 2:]) / max(1, len(v) - fs * 2))
    dc = lambda v: sum(v) / len(v)
    r = (rms(hr) / dc(red)) / (rms(hi) / dc(ir)) if rms(hi) else None
    out = {"samples": len(ir), "beats": len(bt), "reference_bpm": bpm,
           "reference_spo2": (110 - 25 * r) if r else None, "beat_times_s": [round(b, 2) for b in bt]}
    print(json.dumps(out))
    if a.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        t = [i / fs for i in range(len(sig))]
        plt.figure(figsize=(12, 3))
        plt.plot(t, [-v for v in sig])
        for b in bt:
            plt.axvline(b, color="r", lw=0.5)
        plt.savefig(a.plot, dpi=100)


if __name__ == "__main__":
    main()
