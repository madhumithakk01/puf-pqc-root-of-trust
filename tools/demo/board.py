#!/usr/bin/env python3
"""
Board-side steps of the demo, run from Windows PowerShell (needs pyserial and picotool).

  python tools\\demo\\board.py status                 what the board is doing right now
  python tools\\demo\\board.py flash-rot [rot.uf2]    load the root of trust (keeps stored data)
  python tools\\demo\\board.py wipe                   erase the stored RoT data: the board becomes unenrolled
  python tools\\demo\\board.py enroll                 enroll the board with the vendor key (writes device.enr1)
  python tools\\demo\\board.py provision [image]      write the signed application into slot A and start it
  python tools\\demo\\board.py ip                     wait for the board's Wi-Fi beacon and print its address
  python tools\\demo\\board.py console [seconds]      print the board's USB console

The board is put in BOOTSEL remotely when its firmware answers USB; when it does not (a hung
application, a blank board) the script asks for the BOOTSEL button. Nothing here writes OTP.
"""

import argparse
import glob
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "flash"))
sys.path.insert(0, os.path.join(ROOT, "tools", "vendor"))
sys.path.insert(0, os.path.join(ROOT, "tools", "factory"))

DEMO = os.path.join(ROOT, "data", "demo")
DATA_OFF, DATA_SIZE = 0x3D0000, 0x30000          # rot_data partition


def picotool():
    for c in (os.environ.get("PICOTOOL"), shutil.which("picotool"),
              os.path.expanduser(r"~\picotool-win\picotool\picotool.exe")):
        if c and os.path.exists(c):
            return c
    sys.exit("picotool not found: set PICOTOOL or put picotool on PATH")


def pt(*args, check=True):
    p = subprocess.run([picotool(), *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError("picotool %s: %s" % (" ".join(args), (p.stderr or p.stdout).strip()))
    return p


def in_bootsel():
    p = pt("info", check=False)
    out = p.stdout + p.stderr
    return p.returncode == 0 and "No accessible" not in out and "not in BOOTSEL" not in out


def to_bootsel():
    if in_bootsel():
        return
    for _ in range(12):
        pt("reboot", "-f", "-u", check=False)
        time.sleep(1.5)
        if in_bootsel():
            return
    print("\n[HUMAN] The board did not answer. Unplug USB, hold the BOOTSEL button, plug in, release.")
    for _ in range(120):
        if in_bootsel():
            return
        time.sleep(1)
    sys.exit("board never showed up in BOOTSEL")


def serial_port():
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.vid == 0x2E8A:
            return p.device
    return None


def port_busy(port):
    """True when another process holds the COM port (Windows ports are exclusive)."""
    import serial
    try:
        serial.Serial(port, 115200, timeout=0.2).close()
        return False
    except serial.SerialException:
        return True


def wait_port(seconds):
    end = time.time() + seconds
    while time.time() < end:
        port = serial_port()
        if port:
            return port
        time.sleep(0.5)
    return None


def cmd_status(a):
    print("BOOTSEL:", in_bootsel())
    port = serial_port()
    print("USB serial:", port)
    if port:
        import serial
        s = serial.Serial(port, 115200, timeout=0.5)
        s.dtr = True
        end = time.time() + 5
        while time.time() < end:
            line = s.readline().decode("ascii", "replace").strip()
            if line:
                print(" ", line[:200])


def cmd_flash_rot(a):
    uf2 = a.file or os.path.join(DEMO, "rot.uf2")
    if not os.path.exists(uf2):
        sys.exit("%s not found: run tools/demo/build_all.sh in WSL first" % uf2)
    to_bootsel()
    pt("load", uf2)
    print("RoT loaded from", uf2)
    pt("reboot", check=False)


def cmd_wipe(a):
    """Erase rot_data (enrollment, counters, journal, receipts) and both application slots."""
    to_bootsel()
    for start, end in ((DATA_OFF, DATA_OFF + DATA_SIZE), (0x40000, 0x40000 + 0x130000), (0x170000, 0x170000 + 0x130000)):
        pt("erase", "-r", hex(0x10000000 + start), hex(0x10000000 + end))
    print("rot_data and both application slots erased; the board is unenrolled")
    pt("reboot", check=False)


def cmd_enroll(a):
    import enroll
    pk = a.vendor_pk or os.path.join(ROOT, "data", "vendor", "vendor.pk")
    out = a.out or os.path.join(ROOT, "data", "vendor", "device.enr1")
    port = a.serial or serial_port()
    if not port:
        sys.exit("no board on USB")
    print("enrolling on", port, "(about 10 seconds: the board refreshes its SRAM five times)")
    enroll.enroll(port, pk, out)
    print("wrote", out)


def cmd_provision(a):
    import hashlib
    import pico_ops
    img = a.image or os.path.join(DEMO, "v1_0_0.sbi.bin")
    data = open(img, "rb").read()
    to_bootsel()
    d = pico_ops.PicoDevice(os.path.join(ROOT, "data", "provision"), picotool=picotool())
    d.stop()
    d.provision_image(0, data)
    back = d.read_flash(pico_ops.devproc.SLOT_OFF[0], len(data))
    ok = hashlib.sha256(back).digest() == hashlib.sha256(data).digest()
    print("slot A read-back:", "matches" if ok else "DIFFERS")
    if not ok:
        sys.exit(1)
    pt("reboot", check=False)
    print("started", os.path.basename(img))


def cmd_ip(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 7001))
    s.settimeout(a.timeout)
    try:
        data, addr = s.recvfrom(200)
    except socket.timeout:
        sys.exit("no beacon: is this laptop on the same hotspot as the board?")
    print(data.decode("ascii", "replace"))
    print("device address:", addr[0])
    os.makedirs(DEMO, exist_ok=True)
    open(os.path.join(DEMO, "device.ip"), "w").write(addr[0] + "\n")


def cmd_console(a):
    import serial
    port = serial_port()
    if not port:
        sys.exit("no board on USB")
    s = serial.Serial(port, 115200, timeout=0.5)
    s.dtr = True
    end = time.time() + a.seconds
    while time.time() < end:
        line = s.readline().decode("ascii", "replace").strip()
        if line:
            print(line[:240])


def board_status(host):
    from vendor_lib import Client
    c = Client(host, 7000, timeout=10)
    try:
        return c.hello()
    finally:
        c.close()


def cmd_fresh_demo(a):
    """Restart the story: unenrolled board -> enrolled, registered, running v1.0 at floor 1."""
    sys.path.insert(0, os.path.join(ROOT, "server", "attest"))
    steps = 6

    def say(n, text):
        print("\n[%d/%d] %s" % (n, steps, text), flush=True)

    port = serial_port()
    if port and port_busy(port):
        sys.exit("%s is held by another program (the console relay, a terminal or the viewer's console). "
                 "Close it and run fresh-demo again." % port)
    ns = argparse.Namespace
    say(1, "wipe: erase enrollment, counters, receipts and both slots")
    cmd_wipe(ns())
    say(2, "flash-rot: load the root of trust")
    cmd_flash_rot(ns(file=None))
    say(3, "enroll: board creates its identity and proves it to the vendor key")
    port = wait_port(30)
    if not port:
        sys.exit("the board did not show up on USB after flashing the root of trust")
    time.sleep(2)
    cmd_enroll(ns(vendor_pk=None, out=None, serial=port))
    say(4, "register: record the new device (previous registry is kept as registry-old-<time>)")
    r = subprocess.run(["wsl.exe", "--cd", ROOT, "-e", "python3", "tools/demo/demo.py", "register", "--replace"])
    if r.returncode != 0:
        sys.exit("registration failed (see above); the board is enrolled but not registered")
    say(5, "provision: write v1.0 into slot A and start it")
    cmd_provision(ns(image=None))
    say(6, "ip: wait for the board on Wi-Fi")
    cmd_ip(ns(timeout=120))
    host = open(os.path.join(DEMO, "device.ip")).read().strip()
    st = None
    for _ in range(10):
        try:
            st = board_status(host)
            break
        except OSError:
            time.sleep(2)
    if not st:
        sys.exit("the board beacons but does not answer on TCP 7000")
    print("\nfresh demo ready")
    print("  device ID: %s" % st["device_id"])
    print("  version:   %s (SVN %s)" % (st["version"], st["svn"]))
    print("  floor:     %s" % st["floor"])
    print("  address:   %s" % host)
    if st["version"] != "1.0.0" or st["floor"] != 1:
        sys.exit("expected version 1.0.0 at floor 1")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(f=cmd_status)
    p = sub.add_parser("flash-rot")
    p.add_argument("file", nargs="?")
    p.set_defaults(f=cmd_flash_rot)
    sub.add_parser("wipe").set_defaults(f=cmd_wipe)
    p = sub.add_parser("enroll")
    p.add_argument("--vendor-pk")
    p.add_argument("--out")
    p.add_argument("--serial")
    p.set_defaults(f=cmd_enroll)
    p = sub.add_parser("provision")
    p.add_argument("image", nargs="?")
    p.set_defaults(f=cmd_provision)
    p = sub.add_parser("ip")
    p.add_argument("--timeout", type=float, default=120)
    p.set_defaults(f=cmd_ip)
    p = sub.add_parser("console")
    p.add_argument("seconds", nargs="?", type=float, default=15)
    p.set_defaults(f=cmd_console)
    sub.add_parser("fresh-demo").set_defaults(f=cmd_fresh_demo)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
