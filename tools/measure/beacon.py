"""Logs every UDP beacon (port 7001) the board sends: time, source IP, device id and version (Windows).

  python beacon.py LOGFILE
"""
import socket, sys
from ts import now
out = open(sys.argv[1], "a", buffering=1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 7001))
out.write(f"{now()} START beacon logger\n")
while True:
    data, addr = s.recvfrom(300)
    out.write(f"{now()} BEACON src={addr[0]} {data.decode('ascii','replace').strip()}\n")
