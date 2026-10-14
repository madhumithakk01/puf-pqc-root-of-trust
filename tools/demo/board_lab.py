"""
A lab for the real board, with the interface the attack scenarios expect from tools/attacker/lab.Lab.

The factory steps (flashing, enrollment, provisioning) are done by tools/demo/board.py; this class
only attaches to a board that is already enrolled and running, and creates the attacker's keys.
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "attacker"))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "server", "attest"))

import lab as labmod  # noqa: E402
import vendor_lib as vl  # noqa: E402

VERSIONS = {"1.0.0": 1, "1.1.0": 2, "1.2.0": 3}


class BoardLab(labmod.Lab):
    def __init__(self, workdir, host, vendor_cli, attest_cli, images_dir, vendor_sk, ca_sk, registry, device_id):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.vendor_cli, self.attest_cli = vendor_cli, attest_cli
        self.p = lambda name: os.path.join(workdir, name)
        self.host, self.port = host, 7000
        self.wait_s = 90   # a refusal reboots the board into the RoT and back onto the hotspot
        self.dev = None
        self.device_id = device_id
        self.images = {v: os.path.join(images_dir, "v%s.sbi.bin" % v.replace(".", "_")) for v in VERSIONS}
        shutil.copy(vendor_sk, self.p("vendor.sk"))
        self.vendor = vl.Vendor(registry, vendor_cli, attest_cli, vendor_sk, ca_sk)
        # the attacker's own signing key and another device's identity
        self.cli("keygen", "mallory", "--seed", os.urandom(32).hex())
        other = self.cli("keygen-device", "other", "--seed", os.urandom(32).hex())
        self.other_device_id = int(other["device_id"], 16)

    @property
    def addr(self):
        return self.host, self.port

    def ensure_running(self):
        return self.status()

    def status(self):
        return vl.wait_for(self.host, self.port, lambda s: not s.get("trial"), timeout=60)

    def close(self):
        pass
