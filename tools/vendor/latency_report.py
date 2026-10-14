#!/usr/bin/env python3
"""
OTA latency breakdown against a running device (software or board).

  latency_report.py --device HOST:PORT --registry DIR --vendor-cli B --attest-cli B --vendor-sk F
                    --device-id HEX --image FILE --svn N --version V [--clk-hz 150000000]

Runs one deploy and prints: the vendor-side phases (attest, package, push,
install and trial), the RoT stage cycles from the boot report converted to
milliseconds at --clk-hz, and the package overhead against the image size.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vendor_lib as vl  # noqa: E402

STAGES = ["puf_read", "vn", "fuzzy", "kdf", "dsa_keygen", "kem_keygen", "records", "verify", "install", "attest",
          "total", "spare"]


def report(res, boot, clk_hz, image_len):
    out = {"vendor_s": {k: round(v, 3) for k, v in res["timing"].items()}, "outcome": res["outcome"]}
    cyc = boot.get("cycles", [])
    if cyc:
        out["rot_stage_ms"] = {n: round(c * 1000.0 / clk_hz, 2) for n, c in zip(STAGES, cyc) if c}
    out["package"] = {"bytes": res["package_bytes"], "image_bytes": image_len,
                      "overhead_bytes": res["package_bytes"] - image_len,
                      "overhead_pct": round(100.0 * (res["package_bytes"] - image_len) / image_len, 2)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--vendor-cli", required=True)
    ap.add_argument("--attest-cli", required=True)
    ap.add_argument("--vendor-sk", required=True)
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--svn", type=int, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--clk-hz", type=int, default=150_000_000)
    a = ap.parse_args()
    host, port = a.device.rsplit(":", 1)
    v = vl.Vendor(a.registry, a.vendor_cli, a.attest_cli, a.vendor_sk)
    did = int(a.device_id, 16)
    res = v.deploy(host, int(port), did, a.image, a.svn, a.version)
    c = vl.Client(host, int(port))
    try:
        boot = c.bootreport()
    finally:
        c.close()
    print(json.dumps(report(res, boot, a.clk_hz, os.path.getsize(a.image)), indent=2))


if __name__ == "__main__":
    main()
