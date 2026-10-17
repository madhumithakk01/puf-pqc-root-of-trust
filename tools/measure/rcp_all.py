"""Fetches and verifies all receipts of the board and prints them as seq|outcome|reason|from|to|floor before|floor after|text.

  python3 tools/measure/rcp_all.py
"""
import os
import sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "demo"))
import demo
v = demo.vendor(); did = demo.device_id_of(v)
host = open(os.path.join(ROOT, "data", "demo", "device.ip")).read().strip()
rs = v.fetch_receipts(host, 7000, did)
print("chain verified", len(rs))
for r in rs:
    print("%d|%s|%s|%s|%s|%s|%s|%s" % (r["seq"], r["outcome_name"], r.get("reason"), r["from_svn"], r["to_svn"], r["floor_before"], r["floor_after"], r["reason_text"]))
