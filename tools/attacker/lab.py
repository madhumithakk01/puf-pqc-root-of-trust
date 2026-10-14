"""
A complete lab: vendor keys, three application versions, a device (software
or, later, the board) enrolled and provisioned with v1.0, and the vendor's
registry. Used by the end-to-end tests and the attack runner.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "server", "attest"))

import devproc  # noqa: E402
import vendor_lib as vl  # noqa: E402


class Lab:
    def __init__(self, workdir, vendor_cli, attest_cli, softdev_bin, puf_id=4242, trial_mode="pass"):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.vendor_cli = vendor_cli
        self.attest_cli = attest_cli
        self.p = lambda name: os.path.join(workdir, name)
        self.dev = devproc.SoftDevice(softdev_bin, os.path.join(workdir, "dev"), puf_id, trial_mode)
        self.images = {}
        self.device_id = None
        self.vendor = None

    def cli(self, *args):
        import json
        import subprocess
        pr = subprocess.run([self.vendor_cli, *args], capture_output=True, cwd=self.workdir)
        if pr.returncode != 0:
            raise RuntimeError(f"vendor_cli {args[0]}: {pr.stderr.decode().strip()}")
        return json.loads(pr.stdout) if pr.stdout.strip() else {}

    def build(self):
        w = self.workdir
        self.cli("keygen", "vendor", "--seed", "11" * 32)
        self.cli("keygen", "ca", "--seed", "22" * 32)
        self.cli("keygen", "mallory", "--seed", "33" * 32)           # an unrelated signer
        other = self.cli("keygen-device", "other", "--seed", "44" * 32)  # another device's identity
        self.other_device_id = int(other["device_id"], 16)

        for ver, svn, gf in (("1.0.0", 1, "v10"), ("1.1.0", 2, "v11"), ("1.2.0", 3, "v11")):
            app = self.p(f"app-{ver}.bin")
            body = (f"pulse-oximeter application {ver}\n" * 400).encode()[:6000 + svn * 500]
            open(app, "wb").write(body)
            out = self.p(f"v{ver}.sbi.bin")
            self.cli("sign-image", "--app", app, "--svn", str(svn), "--version", ver, "--key", self.p("vendor.sk"),
                     "--golden-from", gf, "--out", out)
            self.images[ver] = out

        # factory: enroll the blank device, then load v1.0 into slot A
        self.dev.start(enroll_pk=self.p("vendor.pk"), enr1_out=self.p("device.enr1"))
        self.dev.stop()
        self.dev.provision_image(0, open(self.images["1.0.0"], "rb").read())
        self.dev.start()

        self.vendor = vl.Vendor(os.path.join(w, "vendor"), self.vendor_cli, self.attest_cli,
                                self.p("vendor.sk"), self.p("ca.sk"))
        self.device_id = self.vendor.register(self.p("device.enr1"))
        return self

    @property
    def addr(self):
        return self.dev.addr

    def status(self):
        return vl.wait_for(*self.addr, lambda s: True, timeout=15)

    def deploy(self, version, **kw):
        svn = {"1.0.0": 1, "1.1.0": 2, "1.2.0": 3}[version]
        return self.vendor.deploy(*self.addr, self.device_id, self.images[version], svn, version, **kw)

    def ensure_running(self):
        """Make sure the device is up and not in SAFE mode; bring it back from a stopped state."""
        if self.dev.proc is None:
            self.dev.start()
        return self.status()

    def close(self):
        self.dev.stop()
