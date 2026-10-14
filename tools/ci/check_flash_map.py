#!/usr/bin/env python3
"""Check that src/rot/rot_flash_map.h matches firmware/pt/pt.json.

Also checks the invariants the layout depends on: partitions are
contiguous from the end of the RoT region, sector aligned, within 4 MB,
and every permission block grants the bootloader "rw".

usage: check_flash_map.py [pt.json] [rot_flash_map.h]
"""

import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SECTOR = 0x1000
FLASH_TOTAL = 0x400000


def parse_size(v):
    m = re.fullmatch(r"(\d+)([KM]?)", str(v))
    if not m:
        raise ValueError(f"bad size {v!r}")
    n = int(m.group(1))
    return n * {"": 1, "K": 1024, "M": 1024 * 1024}[m.group(2)]


def header_defines(path):
    out = {}
    for line in open(path):
        m = re.match(r"#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)u?\b", line)
        if m:
            out[m.group(1)] = int(m.group(2), 0)
    return out


def table_layout(path):
    pt = json.load(open(path))
    parts = {}
    cursor = None
    for p in pt["partitions"]:
        size = parse_size(p["size"])
        start = parse_size(p["start"]) if "start" in p else cursor
        if start is None:
            raise ValueError(f"{p['name']}: no start and no predecessor")
        parts[p["name"]] = (start, size)
        cursor = start + size
    return pt, parts


def check(pt_path, hdr_path):
    errors = []
    pt, parts = table_layout(pt_path)
    h = header_defines(hdr_path)

    expect = {
        "app_a": ("ROT_REGION_APP_A_OFF", "ROT_REGION_APP_A_SIZE"),
        "app_b": ("ROT_REGION_APP_B_OFF", "ROT_REGION_APP_B_SIZE"),
        "staging": ("ROT_REGION_STAGING_OFF", "ROT_REGION_STAGING_SIZE"),
        "rot_data": ("ROT_REGION_DATA_OFF", "ROT_REGION_DATA_SIZE"),
    }
    for name, (off_sym, size_sym) in expect.items():
        if name not in parts:
            errors.append(f"partition {name} missing from the table")
            continue
        start, size = parts[name]
        if h.get(off_sym) != start:
            errors.append(f"{off_sym} = {h.get(off_sym)} but {name} starts at {start:#x}")
        if h.get(size_sym) != size:
            errors.append(f"{size_sym} = {h.get(size_sym)} but {name} is {size:#x} bytes")
        if start % SECTOR or size % SECTOR:
            errors.append(f"{name} is not sector aligned")

    ordered = sorted(parts.values())
    if ordered and ordered[0][0] != h.get("ROT_REGION_ROT_SIZE"):
        errors.append("first partition does not start at the end of the RoT region")
    for (s0, z0), (s1, _) in zip(ordered, ordered[1:]):
        if s0 + z0 != s1:
            errors.append(f"gap or overlap after {s0:#x}+{z0:#x}")
    if ordered and ordered[-1][0] + ordered[-1][1] > FLASH_TOTAL:
        errors.append("layout exceeds 4 MB")
    if h.get("ROT_FLASH_TOTAL") != FLASH_TOTAL:
        errors.append("ROT_FLASH_TOTAL is not 4 MB")
    if h.get("ROT_DATA_SECTORS", 0) * SECTOR != h.get("ROT_REGION_DATA_SIZE"):
        errors.append("ROT_DATA_SECTORS does not cover rot_data")
    if h.get("ROT_SECTOR_RCP1_FIRST", 0) + h.get("ROT_RCP1_RING", 0) > h.get("ROT_SECTOR_SPARE_FIRST", 0):
        errors.append("receipt ring overlaps the spare sectors")

    perms = [pt.get("unpartitioned", {}).get("permissions", {})]
    perms += [p.get("permissions", {}) for p in pt["partitions"]]
    for i, pm in enumerate(perms):
        if pm.get("bootloader") != "rw":
            errors.append(f"permissions block {i}: bootloader is not rw")
    return errors


def selftest(pt_path, hdr_path):
    """A single changed offset must be reported."""
    text = open(hdr_path).read()
    mutated = re.sub(r"(ROT_REGION_APP_B_OFF\s+)0x170000u", r"\g<1>0x171000u", text)
    assert mutated != text
    tmp = hdr_path + ".mutated"
    try:
        open(tmp, "w").write(mutated)
        return bool(check(pt_path, tmp))
    finally:
        os.remove(tmp)


def main(argv):
    pt = argv[1] if len(argv) > 1 else os.path.join(ROOT, "firmware", "pt", "pt.json")
    hdr = argv[2] if len(argv) > 2 else os.path.join(ROOT, "src", "rot", "rot_flash_map.h")
    errors = check(pt, hdr)
    for e in errors:
        print("flash map:", e)
    if errors:
        return 1
    if not selftest(pt, hdr):
        print("flash map: self-test failed: a changed offset was not detected")
        return 1
    print("check-flashmap: PASS (layout matches; a changed offset is detected)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
