"""USB console logger used by the validation runs: re-opens the port after every reset (Windows).

  python console.py LOGFILE

See console_capture.py for the version with a 5 ms reconnect and a --show mode.
"""
import sys, time, serial
from serial.tools import list_ports
from ts import now
out = open(sys.argv[1], "a", buffering=1)
out.write(f"{now()} START console logger\n")
state = None
while True:
    port = next((p.device for p in list_ports.comports() if p.vid == 0x2E8A), None)
    if not port:
        if state != "none":
            out.write(f"{now()} NOPORT\n"); state = "none"
        time.sleep(0.1); continue
    try:
        s = serial.Serial(port, 115200, timeout=0.3)
        s.dtr = True
        out.write(f"{now()} CONNECT {port}\n"); state = "up"
        buf = b""
        while True:
            chunk = s.read(256)
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.decode("ascii", "replace").strip()
                    if line:
                        out.write(f"{now()} LINE {line[:300]}\n")
    except (serial.SerialException, OSError) as e:
        out.write(f"{now()} DISCONNECT {type(e).__name__}\n"); state = "down"
        time.sleep(0.1)
