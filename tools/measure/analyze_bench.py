"""Table 5.9 (and the ML-DSA-44 verify time for Table 5.18) from the console lines of the bench image.

  python3 tools/measure/analyze_bench.py LINES.txt

LINES.txt is the --lines-file of console_capture.py. Prints cycles (min / mean / max), milliseconds at 150 MHz and
retired instructions per operation over all complete passes.
"""
import json, statistics as st, sys
f = sys.argv[1]
ops, starts, dones, clk = {}, 0, [], set()
for l in open(f, encoding="utf-8"):
    l = l.strip()
    if not l.startswith("{"): continue
    try: j = json.loads(l)
    except ValueError: continue
    if j.get("bench") == "start": starts += 1; clk.add(j["clk_hz"])
    elif j.get("bench") == "done": dones.append(j["kem_agree"])
    elif "op" in j: ops.setdefault(j["op"], []).append(j)
print("complete passes (start lines seen): %d, done lines %d, kem_agree all 1: %s, clk_hz %s" % (starts, len(dones), all(dones), sorted(clk)))
print("%-26s %3s | %12s %12s %12s | %8s %8s %8s | %12s %12s %12s | %s" % ("op", "n", "cyc min", "cyc mean", "cyc max", "ms min", "ms mean", "ms max", "instr min", "instr mean", "instr max", "IPC mean"))
for op, rs in ops.items():
    c = [r["cycles"] for r in rs]; i = [r["instret"] for r in rs]
    print("%-26s %3d | %12d %12.0f %12d | %8.2f %8.2f %8.2f | %12d %12.0f %12d | %.2f" % (op, len(rs), min(c), st.mean(c), max(c), min(c)/150000, st.mean(c)/150000, max(c)/150000, min(i), st.mean(i), max(i), st.mean(i)/st.mean(c)))
