"""
Physical-access operations on the board through picotool: the offline side of
attacks A7 and A8, snapshots of the flash, and factory image loading. It
exposes the same interface as tools/attacker/devproc.SoftDevice, so the
attack scenarios run unchanged against the board.

Needs picotool on PATH (or PICOTOOL) and the board in BOOTSEL mode or running
SDK USB stdio (picotool reboot -u -f is used to enter BOOTSEL). Never writes
OTP: only `load`, `save` and `reboot` are used.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacker"))
import devproc  # noqa: E402

FLASH_BASE = 0x10000000


class PicoDevice:
    def __init__(self, workdir, serial_port=None, picotool=None, host=None, port=7000):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.picotool = picotool or os.environ.get("PICOTOOL", "picotool")
        self.serial_port = serial_port
        self.host, self.port = host, port
        self.proc = object()          # the board runs on its own; stop() means BOOTSEL
        self.trial_mode = "pass"

    def _pt(self, *args):
        p = subprocess.run([self.picotool, *args], capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"picotool {' '.join(args)}: {p.stderr.strip() or p.stdout.strip()}")
        return p.stdout

    @property
    def addr(self):
        return self.host, self.port

    def stop(self):
        """Put the board in BOOTSEL so its flash can be read and written."""
        self._pt("reboot", "-u", "-f")
        time.sleep(1.5)
        self.proc = None

    def start(self):
        self._pt("reboot", "-f")
        self.proc = object()
        time.sleep(3)

    def restart(self):
        self.stop()
        self.start()

    def read_flash(self, off, n):
        path = os.path.join(self.workdir, "read.bin")
        self._pt("save", "-r", hex(FLASH_BASE + off), hex(FLASH_BASE + off + n), path)
        return open(path, "rb").read()

    def write_flash(self, off, data):
        assert self.proc is None, "stop() the board first"
        path = os.path.join(self.workdir, "write.sbi.bin")   # *.bin so picotool treats it as raw
        open(path, "wb").write(data)
        self._pt("load", "--ignore-partitions", path, "-o", hex(FLASH_BASE + off))

    def provision_image(self, slot, image):
        self.write_flash(devproc.SLOT_OFF[slot], image)

    def tamper_byte(self, slot, offset):
        b = bytearray(self.read_flash(devproc.SLOT_OFF[slot] + offset, 1))
        b[0] ^= 0x01
        self.write_flash(devproc.SLOT_OFF[slot] + offset, bytes(b))

    def snapshot(self):
        return self.read_flash(devproc.DATA_OFF, devproc.DATA_SIZE) + b"".join(
            self.read_flash(devproc.SLOT_OFF[s], 0x40000) for s in (0, 1))

    def restore(self, snap):
        self.write_flash(devproc.DATA_OFF, snap[:devproc.DATA_SIZE])
        rest = snap[devproc.DATA_SIZE:]
        self.write_flash(devproc.SLOT_OFF[0], rest[:0x40000])
        self.write_flash(devproc.SLOT_OFF[1], rest[0x40000:])

    def dump_rot_data(self, path):
        open(path, "wb").write(self.read_flash(devproc.DATA_OFF, devproc.DATA_SIZE))

    def backup_identity(self, path):
        """Public enrollment data; erasing it forces a re-enrollment."""
        self.dump_rot_data(path)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="picotool-based flash operations")
    ap.add_argument("cmd", choices=["snapshot", "tamper-byte", "write-image", "restore", "info"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--dir", default="data/flash")
    a = ap.parse_args()
    d = PicoDevice(a.dir)
    if a.cmd == "info":
        print(d._pt("info", "-a"))
    elif a.cmd == "snapshot":
        d.stop()
        open(os.path.join(a.dir, "snapshot.bin"), "wb").write(d.snapshot())
    elif a.cmd == "tamper-byte":
        d.stop()
        d.tamper_byte(int(a.args[0] == "B"), int(a.args[1], 0))
    elif a.cmd == "write-image":
        d.stop()
        d.provision_image(int(a.args[0] == "B"), open(a.args[1], "rb").read())
    elif a.cmd == "restore":
        d.stop()
        d.restore(open(a.args[0], "rb").read())
