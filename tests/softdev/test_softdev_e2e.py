#!/usr/bin/env python3
"""
End to end on the software device: enrollment, attestation, OTA with commit
and rollback, trial failures, receipts and their chain, state-rollback
detection by the vendor, the stored data region, and each attack scenario
once. The same flows run against the board with a different device backend.

usage: test_softdev_e2e.py <vendor_cli> <attest_cli> <softdev_device>
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "attacker"))
sys.path.insert(0, os.path.join(ROOT, "tools", "vendor"))
sys.path.insert(0, os.path.join(ROOT, "server", "attest"))

import lab as labmod  # noqa: E402
import scenarios  # noqa: E402
import vendor_lib as vl  # noqa: E402
import attest2  # noqa: E402

failures = 0


def check(name, ok):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        failures += 1


def main(vendor_cli, attest_cli, softdev):
    work = tempfile.mkdtemp(prefix="softdev_e2e_")
    lab = labmod.Lab(work, os.path.abspath(vendor_cli), os.path.abspath(attest_cli), os.path.abspath(softdev)).build()
    try:
        run(lab)
    finally:
        lab.close()
    print("test_softdev_e2e:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


def run(lab):
    v = lab.vendor
    st = lab.status()
    check("enrolled device boots v1.0 from slot A", st["svn"] == 1 and st["floor"] == 1 and st["slot"] == 0
          and st["version"] == "1.0.0" and st["device_id"] == f"{lab.device_id:08x}")
    check("the vendor registered the device from a verified ENR1", lab.device_id in
          [d["device_id"] for d in v.registry.devices.values()])
    check("an ATC1 certificate was issued", len(bytes.fromhex(v.registry.get(lab.device_id)["cert"])) > 3700)

    # a tampered ENR1 is not accepted for registration
    bad = bytearray(open(lab.p("device.enr1"), "rb").read())
    bad[100] ^= 1
    open(lab.p("bad.enr1"), "wb").write(bytes(bad))
    try:
        v.register(lab.p("bad.enr1"))
        check("a modified ENR1 is refused at registration", False)
    except Exception:
        check("a modified ENR1 is refused at registration", True)

    rep = v.attest(*lab.addr, lab.device_id)
    check("attestation verifies: nonce, signature, floor 1, no alerts", rep["svn"] == 1 and rep["floor"] == 1
          and not rep["alerts"] and rep["device_id"] == lab.device_id)
    check("the report carries the PUF health numbers", 0 < rep["bits_corrected"] < 400 and rep["worst_block"] <= 7)

    # v1.0 -> v1.1
    res = lab.deploy("1.1.0")
    print(f"       deploy v1.1: total {res['timing']['total']:.2f} s, package {res['package_bytes']} bytes")
    check("v1.1 is installed, trialled and committed (floor 2)", res["outcome"] == "COMMITTED"
          and res["floor"] == 2 and res["svn"] == 2 and res["status"]["slot"] == 1)
    check("the receipt records the transition", res["receipt"]["from_svn"] == 1 and res["receipt"]["to_svn"] == 2
          and res["receipt"]["floor_before"] == 1 and res["receipt"]["floor_after"] == 2)

    # v1.2 regression
    res = lab.deploy("1.2.0")
    check("v1.2 doubles the heart rate and is rolled back to v1.1", res["outcome"] == "ROLLED_BACK"
          and res["reason_code"] == 20 and res["svn"] == 2 and res["floor"] == 2)
    check("the device keeps serving v1.1 after the rollback", lab.status()["version"] == "1.1.0")

    # receipts and chain
    receipts = v.fetch_receipts(*lab.addr, lab.device_id)
    check("the receipt chain verifies end to end", len(receipts) >= 2 and receipts[-1]["seq"] == len(receipts))

    # trial failures
    dev = lab.dev
    for mode, code in (("hang", 23), ("nosensor", 22)):
        dev.trial_mode = mode
        dev.restart()
        res = lab.deploy("1.2.0")
        check(f"trial mode '{mode}' ends in ROLLED_BACK with reason {code}", res["outcome"] == "ROLLED_BACK"
              and res["reason_code"] == code and res["floor"] == 2)
    dev.trial_mode = "pass"
    dev.restart()

    # the data region holds only public records
    dev.stop()
    dev.dump_rot_data(lab.p("rot_data.bin"))
    out = subprocess.run([lab.vendor_cli, "inspect-rotdata", lab.p("rot_data.bin")], capture_output=True)
    info = json.loads(out.stdout)
    check("rot_data: every byte belongs to a public record (no key material stored)",
          info["holds_only_public_records"] and info["unaccounted_bytes_total"] == 0)
    recs = {s["record"] for s in info["sectors"] if s["present"]}
    check("rot_data: helper, anchor, counter, journal and receipts are present",
          {"HLP1", "ANC1", "RBC1", "JNL1", "RCP1"} <= recs)
    dev.start()

    # each attack scenario once
    for name in scenarios.SCENARIOS:
        r = scenarios.SCENARIOS[name](lab)
        check(f"{name} {scenarios.NAMES[name]}: expected {r['expected']}, got {r['observed']}", r["ok"])

    # full receipt chain at the end
    receipts = v.fetch_receipts(*lab.addr, lab.device_id)
    check("the receipt chain still verifies after the attacks", len(receipts) >= 10)
    refused = [r for r in receipts if r["outcome_name"] == "REFUSED"]
    check("refusals carry their reasons in signed receipts", {r["reason"] for r in refused} >= {2, 3, 4, 5, 6})

    # the vendor flags a state rollback after a flash snapshot is restored
    dev.stop()
    snap_before = dev.snapshot()
    dev.start()
    lab.deploy("1.1.0")                       # svn 2 again: allowed, floor unchanged, new receipt
    dev.stop()
    dev.restore(snap_before)                  # the attacker puts the old flash back
    dev.start()
    rep = v.attest(*lab.addr, lab.device_id)
    check("a restored older flash snapshot is flagged as STATE ROLLBACK", any("ROLLBACK" in a for a in rep["alerts"]))
    check("and the alert names the receipt sequence the vendor has already seen",
          any("receipt sequence" in a for a in rep["alerts"]))



if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
