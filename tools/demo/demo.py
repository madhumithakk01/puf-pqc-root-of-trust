#!/usr/bin/env python3
"""
Vendor-side demo, run in WSL or Linux (it uses the vendor tools built by `make -C tests`).

  demo.py setup                 create the vendor and CA keys if they do not exist
  demo.py register [--replace]  register the enrolled board (reads data/vendor/device.enr1);
                                --replace first moves data/registry to data/registry-old-<time>
  demo.py status                what the board reports
  demo.py story                 the whole demonstration, step by step, with PASS / FAIL for each
  demo.py attacks [A1,A2,...]   attacks on the real board (default A1,A2,A4,A5,A6)
  demo.py viewer                the live page: vitals, security state, receipts, deploy buttons

The board's address comes from --device, or from data/demo/device.ip (written by `board.py ip`).
Nothing is trusted from the board: attestation reports and receipts are verified with the keys
registered at enrollment.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for sub in ("vendor", "attacker", "relay"):
    sys.path.insert(0, os.path.join(ROOT, "tools", sub))
sys.path.insert(0, os.path.join(ROOT, "server", "attest"))
sys.path.insert(0, HERE)

import vendor_lib as vl  # noqa: E402

DATA = os.path.join(ROOT, "data")
KEYS = os.path.join(DATA, "vendor")
IMAGES = os.path.join(DATA, "demo")
REGISTRY = os.path.join(DATA, "registry")
VCLI = os.path.join(ROOT, "build", "tests", "vendor_cli")
ACLI = os.path.join(ROOT, "build", "tests", "attest_cli")
VERSIONS = {"1.0.0": 1, "1.1.0": 2, "1.2.0": 3}
REASON_SENSOR = 22


def host_of(a):
    if a.device:
        return a.device
    f = os.path.join(IMAGES, "device.ip")
    if os.path.exists(f):
        return open(f).read().strip()
    sys.exit("no board address: run `python tools\\demo\\board.py ip` or pass --device HOST")


def vendor():
    return vl.Vendor(REGISTRY, VCLI, ACLI, os.path.join(KEYS, "vendor.sk"), os.path.join(KEYS, "ca.sk"))


def device_id_of(v):
    ids = list(v.registry.devices.values())
    if len(ids) != 1:
        sys.exit("expected exactly one registered device, found %d: run `demo.py register`" % len(ids))
    return ids[0]["device_id"]


def cmd_setup(a):
    os.makedirs(KEYS, exist_ok=True)
    for name in ("vendor", "ca"):
        if not os.path.exists(os.path.join(KEYS, name + ".sk")):
            subprocess.run([VCLI, "keygen", os.path.join(KEYS, name)], check=True)
            print("created", name, "key pair in", KEYS)
        else:
            print(name, "key pair already exists")


def cmd_register(a):
    if a.replace and os.path.isdir(REGISTRY):
        old = "%s-old-%s" % (REGISTRY, time.strftime("%Y%m%d-%H%M%S"))
        shutil.move(REGISTRY, old)
        print("previous registry moved to", old)
    os.makedirs(REGISTRY, exist_ok=True)
    v = vendor()
    did = v.register(os.path.join(KEYS, "device.enr1"))
    print("registered device %08x (proof of possession verified, certificate issued)" % did)


def cmd_status(a):
    host = host_of(a)
    c = vl.Client(host, 7000, timeout=10)
    st = c.hello()
    c.close()
    c = vl.Client(host, 7000, timeout=10)
    rep = c.bootreport()
    c.close()
    print(json.dumps(st, indent=1))
    print("boot report: reset cause %s, PUF bits corrected %s (worst block %s), die temperature %.1f C" % (
        rep.get("reset_cause"), rep.get("bits_corrected"), rep.get("worst_block"), rep.get("temp_x10", 0) / 10))


class Story:
    def __init__(self, a):
        self.host = host_of(a)
        self.v = vendor()
        self.did = device_id_of(self.v)
        self.rows = []
        self.n = 0

    def deploy(self, ver):
        return self.v.deploy(self.host, 7000, self.did, os.path.join(IMAGES, "v%s.sbi.bin" % ver.replace(".", "_")),
                             VERSIONS[ver], ver, timeout=120)

    def step(self, title, fn, check, retries=2):
        """Run one step. A network hiccup or a sensor that did not answer at the health check is
        retried (and said so); a wrong security outcome is never retried."""
        self.n += 1
        print("\n[%d] %s" % (self.n, title), flush=True)
        t0 = time.time()
        for attempt in range(retries + 1):
            try:
                res = fn()
            except (OSError, vl.ProtocolError, vl.AttestationError, TimeoutError) as e:
                print("    network hiccup (%s: %s)%s" % (type(e).__name__, str(e)[:90], "; trying again" if attempt < retries else ""),
                      flush=True)
                time.sleep(6)
                res = None
                continue
            if isinstance(res, dict) and res.get("reason_code") == REASON_SENSOR and attempt < retries:
                print("    the sensor did not answer during the health check (loose wire?); trying again", flush=True)
                time.sleep(4)
                continue
            break
        if res is None:
            ok, shown = False, "no answer from the board"
        else:
            ok, shown = check(res)
        print("    %s  %s  (%.0f s)" % ("PASS" if ok else "FAIL", shown, time.time() - t0), flush=True)
        self.rows.append((self.n, title, ok, shown))
        return res

    def run(self):
        host = self.host
        c = vl.Client(host, 7000, timeout=15)
        st = c.hello()
        c.close()
        print("Board %s at %s: version %s, SVN %s, rollback floor %s, running slot %s" % (
            st["device_id"], host, st["version"], st["svn"], st["floor"], st["slot"]))

        def att():
            return self.v.attest(host, 7000, self.did)

        def chk_att(r):
            good = not r["alerts"] and r["device_id"] == self.did
            return good, "report signed by the PUF-derived key and fresh (our nonce); SVN %s, floor %s, alerts: %s" % (
                r["svn"], r["floor"], r["alerts"] or "none")
        self.step("Attestation: is this really the board we enrolled, and is it running what it says?", att, chk_att)

        def chk_commit(r):
            return r["outcome"] == "COMMITTED", "%s (%s); floor now %s" % (r["outcome"], r["reason"], r["floor"])
        self.step("Update to v1.1 (good update, signed, encrypted to this board): should be accepted",
                  lambda: self.deploy("1.1.0"), chk_commit)

        def chk_rb(r):
            return (r["outcome"] == "ROLLED_BACK" and r["reason_code"] == 20 and r["svn"] == 2), \
                "%s (%s); board back on SVN %s, floor %s" % (r["outcome"], r["reason"], r["svn"], r["floor"])
        self.step("Update to v1.2 (genuine but faulty: reports twice the heart rate): the board must roll back by itself",
                  lambda: self.deploy("1.2.0"), chk_rb)

        def chk_refuse5(r):
            return (r["outcome"] == "REFUSED" and r["reason_code"] == 5 and r["svn"] == 2), \
                "%s (%s); floor stays %s" % (r["outcome"], r["reason"], r["floor"])
        self.step("Downgrade to v1.0 with the genuine vendor key (an insider): the rollback counter must refuse it",
                  lambda: self.deploy("1.0.0"), chk_refuse5)

        import board_lab
        import scenarios
        lab = board_lab.BoardLab(os.path.join(DATA, "demo", "lab"), host, VCLI, ACLI, IMAGES,
                                 os.path.join(KEYS, "vendor.sk"), os.path.join(KEYS, "ca.sk"), REGISTRY, self.did)
        titles = {
            "A1": "Attack: one byte of the package flipped in transit",
            "A2": "Attack: an attacker's own signing key with the right device id and a fresh nonce",
            "A4": "Attack: replay of a captured genuine package",
            "A5": "Attack: a package made for a different board",
            "A6": "Eavesdropping: what an observer on the Wi-Fi sees",
        }
        for name in a_names(self.args):
            def run_attack(name=name):
                return scenarios.SCENARIOS[name](lab)

            def chk(r, name=name):
                return r["ok"], "expected %s, observed %s - %s" % (r["expected"], r["observed"], r["detail"])
            self.step(titles.get(name, scenarios.NAMES[name]), run_attack, chk)

        print("\nReceipts (each signed by the board's PUF-derived key and chained to the previous one):")
        try:
            for r in self.v.fetch_receipts(host, 7000, self.did)[-8:]:
                print("    #%-3d %-12s %-40s SVN %s -> %s, floor %s -> %s" % (
                    r["seq"], r["outcome_name"], r["reason_text"], r["from_svn"], r["to_svn"], r["floor_before"], r["floor_after"]))
        except Exception as e:
            print("    (could not fetch receipts: %s)" % type(e).__name__)

        good = sum(1 for _, _, ok, _ in self.rows if ok)
        print("\n%d of %d steps passed" % (good, len(self.rows)))
        for n, title, ok, shown in self.rows:
            print("  %s  [%d] %s" % ("PASS" if ok else "FAIL", n, title))
        return 0 if good == len(self.rows) else 1


def a_names(a):
    return [n for n in (a.only.split(",") if getattr(a, "only", None) else ["A1", "A2", "A4", "A5", "A6"]) if n]


def cmd_story(a):
    s = Story(a)
    s.args = a
    sys.exit(s.run())


def cmd_attacks(a):
    import board_lab
    import scenarios
    host = host_of(a)
    v = vendor()
    lab = board_lab.BoardLab(os.path.join(DATA, "demo", "lab"), host, VCLI, ACLI, IMAGES,
                             os.path.join(KEYS, "vendor.sk"), os.path.join(KEYS, "ca.sk"), REGISTRY, device_id_of(v))
    bad = 0
    for name in a_names(a):
        r = scenarios.SCENARIOS[name](lab)
        print("%s %-60s expected %-10s observed %-14s %s" % (name, scenarios.NAMES[name], r["expected"], r["observed"],
                                                           "PASS" if r["ok"] else "FAIL"))
        bad += 0 if r["ok"] else 1
    sys.exit(1 if bad else 0)


def cmd_viewer(a):
    host = host_of(a)
    v = vendor()
    imgs = os.path.join(IMAGES, "viewer")
    os.makedirs(imgs, exist_ok=True)
    for ver in VERSIONS:
        shutil.copy(os.path.join(IMAGES, "v%s.sbi.bin" % ver.replace(".", "_")), os.path.join(imgs, "v%s.sbi.bin" % ver))
    os.execv(sys.executable, [sys.executable, os.path.join(ROOT, "tools", "viewer", "viewer.py"),
                              "--device", "%s:7000" % host, "--listen", str(a.listen), "--registry", REGISTRY,
                              "--vendor-cli", VCLI, "--attest-cli", ACLI, "--vendor-sk", os.path.join(KEYS, "vendor.sk"),
                              "--device-id", "%08x" % device_id_of(v), "--images", imgs])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", help="board address (default: data/demo/device.ip)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").set_defaults(f=cmd_setup)
    p = sub.add_parser("register")
    p.add_argument("--replace", action="store_true", help="keep the old registry as registry-old-<time> and start a new one")
    p.set_defaults(f=cmd_register)
    sub.add_parser("status").set_defaults(f=cmd_status)
    p = sub.add_parser("story")
    p.add_argument("--only", help="attacks to include, e.g. A1,A2")
    p.set_defaults(f=cmd_story)
    p = sub.add_parser("attacks")
    p.add_argument("only", nargs="?")
    p.set_defaults(f=cmd_attacks)
    p = sub.add_parser("viewer")
    p.add_argument("--listen", type=int, default=8080)
    p.set_defaults(f=cmd_viewer)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
