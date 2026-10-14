"""
Device backends for the attack scenarios. The scenarios talk to a device
through this small interface, so the same code runs against the software
device (SoftDevice here) and, later, the board (tools/flash/pico_ops.py).

Offline operations (flash edits) need the device stopped, exactly as a
physical attacker with USB access would have to power it down or reboot it
into BOOTSEL first.
"""

import os
import re
import subprocess
import threading
import time

# flash layout, from src/rot/rot_flash_map.h
SLOT_OFF = (0x040000, 0x170000)
SLOT_SIZE = 0x130000
DATA_OFF = 0x3D0000
DATA_SIZE = 0x030000
FLASH_SIZE = 0x400000


class SoftDevice:
    def __init__(self, softdev_bin, workdir, puf_id=4242, trial_mode="pass", noise=20000):
        self.bin = softdev_bin
        self.workdir = workdir
        self.puf_id = puf_id
        self.trial_mode = trial_mode
        self.noise = noise
        self.flash = os.path.join(workdir, f"flash-{puf_id}.bin")
        self.proc = None
        self.port = None
        self.lines = []
        self._cv = threading.Condition()
        os.makedirs(workdir, exist_ok=True)

    # -- process control ------------------------------------------------
    def _spawn(self, extra):
        cmd = [self.bin, "--flash", self.flash, "--port", "0", "--puf-id", str(self.puf_id),
               "--noise", str(self.noise), "--trial-mode", self.trial_mode, "--vitals-hz", "10",
               "--log", os.path.join(self.workdir, f"rot-{self.puf_id}.log")] + extra
        self.lines = []
        self.port = None
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            with self._cv:
                self.lines.append(line.rstrip())
                m = re.match(r"LISTENING (\d+)", line)
                if m:
                    self.port = int(m.group(1))
                self._cv.notify_all()

    def wait_listening(self, timeout=30.0):
        end = time.time() + timeout
        with self._cv:
            while self.port is None:
                if self.proc.poll() is not None:
                    raise RuntimeError("softdev exited: " + " | ".join(self.lines[-5:]))
                left = end - time.time()
                if left <= 0:
                    raise TimeoutError("softdev did not start listening")
                self._cv.wait(min(left, 0.2))
        return self.port

    def start(self, enroll_pk=None, enr1_out=None):
        extra = []
        if enroll_pk:
            extra += ["--enroll", enroll_pk, "--enr1-out", enr1_out]
        self._spawn(extra)
        self.wait_listening()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self.port = None

    def restart(self):
        self.stop()
        self.start()

    @property
    def addr(self):
        return "127.0.0.1", self.port

    def boot_lines(self):
        return [l for l in self.lines if l.startswith("BOOT")]

    # -- offline flash access (device stopped) ---------------------------
    def read_flash(self, off, n):
        with open(self.flash, "rb") as f:
            f.seek(off)
            return f.read(n)

    def write_flash(self, off, data):
        assert self.proc is None, "stop the device before editing its flash"
        with open(self.flash, "r+b") as f:
            f.seek(off)
            f.write(data)

    def provision_image(self, slot, image):
        """Factory step: write an SBI1 image into a slot (picotool load equivalent)."""
        self.write_flash(SLOT_OFF[slot], b"\xff" * 0 + image)

    def tamper_byte(self, slot, offset):
        b = bytearray(self.read_flash(SLOT_OFF[slot] + offset, 1))
        b[0] ^= 0x01
        self.write_flash(SLOT_OFF[slot] + offset, bytes(b))

    def snapshot(self):
        return open(self.flash, "rb").read()

    def restore(self, snap):
        assert self.proc is None
        open(self.flash, "wb").write(snap)

    def dump_rot_data(self, path):
        open(path, "wb").write(self.read_flash(DATA_OFF, DATA_SIZE))
