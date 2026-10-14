#!/usr/bin/env python3
"""Check that no allocated section of an ELF overlaps the protected SRAM ranges.

  check_map.py rot  FILE.elf   RoT and charz: R3 (PUF zone) and R4 (handoff) are never used
  check_map.py app  FILE.elf   application: R4 (handoff) is never used

Also reports where the core-0 stack ends for the "rot" profile (expected 0x20068000).
Uses readelf from PATH or $READELF.
"""

import os
import re
import subprocess
import sys

R3 = (0x20068000, 0x2007C000)
R4 = (0x2007C000, 0x20080000)
PROFILES = {"rot": [("R3 PUF zone", R3), ("R4 handoff", R4)], "app": [("R4 handoff", R4)]}


def sections(elf):
    readelf = os.environ.get("READELF", "riscv32-pico-elf-readelf")
    out = subprocess.run([readelf, "-S", "-W", elf], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S*)", line)
        if m and "A" in m.group(5):
            yield m.group(1), int(m.group(3), 16), int(m.group(4), 16)


def main(argv):
    profile, elf = argv[1], argv[2]
    bad = 0
    stack_end = None
    for name, addr, size in sections(elf):
        if size == 0:
            continue
        if name == ".stack_dummy":
            stack_end = addr + size
        for label, (lo, hi) in PROFILES[profile]:
            if addr < hi and addr + size > lo:
                print(f"check_map: section {name} [{addr:#x}, {addr + size:#x}) overlaps {label}")
                bad += 1
    if profile == "rot" and stack_end is not None and stack_end != 0x20068000:
        print(f"check_map: stack ends at {stack_end:#x}, expected 0x20068000")
        bad += 1
    if not bad:
        print(f"check_map: {os.path.basename(elf)} ok ({profile})" + (f", stack top {stack_end:#x}" if stack_end else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
