"""USB console capture with a fast reconnect (Windows). Logs every line with a UTC timestamp.

  console_capture.py LOGFILE [--seconds N] [--show] [--lines-file F]

The board's USB port disappears at every reset. The port name is found once; after that the port is
re-opened every 5 ms, so the lines printed right after a reset are caught as early as Windows allows.
Lines printed before the host has opened the port are not seen; the log never contains invented lines.
--show also prints the lines (local time) to this window, for a screenshot.
"""
import argparse, sys, time
from datetime import datetime, timezone
import serial
from serial.tools import list_ports

ap = argparse.ArgumentParser()
ap.add_argument("log"); ap.add_argument("--seconds", type=float, default=0); ap.add_argument("--show", action="store_true")
ap.add_argument("--lines-file")
a = ap.parse_args()
out = open(a.log, "a", buffering=1, encoding="utf-8")
lines_out = open(a.lines_file, "a", buffering=1, encoding="utf-8") if a.lines_file else None
def now(): return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
end = time.time() + a.seconds if a.seconds else None
port = None
while port is None and (end is None or time.time() < end):
    port = next((p.device for p in list_ports.comports() if p.vid == 0x2E8A), None)
    time.sleep(0.05)
out.write(f"{now()} START port={port}\n")
up = False
buf = b""
while end is None or time.time() < end:
    try:
        s = serial.Serial(port, 115200, timeout=0.05)
        s.dtr = True
        out.write(f"{now()} CONNECT\n"); up = True; buf = b""
        while end is None or time.time() < end:
            chunk = s.read(256)
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("ascii", "replace").strip()
                    if text:
                        out.write(f"{now()} LINE {text}\n")
                        if lines_out: lines_out.write(text + "\n")
                        if a.show: print(datetime.now().strftime("[%H:%M:%S.%f")[:-3] + "] " + text, flush=True)
        s.close()
    except (serial.SerialException, OSError) as e:
        if up:
            out.write(f"{now()} DISCONNECT {type(e).__name__}\n"); up = False
        time.sleep(0.005)
out.write(f"{now()} END\n")
