"""Tables 5.7 and 5.10 from the output of restart_loop.py.

  python3 tools/measure/analyze_restarts.py DIR

DIR holds restarts.jsonl (from restart_loop.py) and, optionally, console.log (from console_capture.py) for the
cross-check of the die temperature. Prints min / mean / median / max of bits_corrected, worst_block and temp_x10
(Table 5.7) and the cycles of each boot stage (Table 5.10).
"""
import json, re, statistics as st, sys, os
d = sys.argv[1]
recs = [json.loads(l) for l in open(os.path.join(d, "restarts.jsonl"))]
ok = [r for r in recs if "boot" in r]
bad = [r for r in recs if "error" in r]
print("restarts requested/recorded: %d, with a boot report: %d, errors: %d" % (len(recs), len(ok), len(bad)))
for r in bad: print("   error at", r["i"], r["error"])

def stat(xs):
    return "n=%d  min %s  mean %.2f  median %s  max %s" % (len(xs), min(xs), st.mean(xs), st.median(xs), max(xs))

print("\n== Table 5.7: PUF reconstruction (boot report of each restart)")
for k in ("bits_corrected", "worst_block", "temp_x10", "refreshes"):
    print("  %-15s %s" % (k, stat([r["boot"][k] for r in ok])))
rc = {}
for r in ok: rc[r["boot"]["reset_cause"]] = rc.get(r["boot"]["reset_cause"], 0) + 1
print("  reset_cause counts:", rc)
agree = sum(1 for r in ok if r["atr2"]["bits_corrected"] == r["boot"]["bits_corrected"] and r["atr2"]["worst_block"] == r["boot"]["worst_block"])
print("  verified attestation report (ATR2) agrees with the boot report on bits_corrected and worst_block: %d of %d" % (agree, len(ok)))
print("  bits_corrected as fraction of 3840 PUF bits: mean %.2f %%" % (100 * st.mean([r["boot"]["bits_corrected"] for r in ok]) / 3840))
hist = {}
for r in ok: hist[r["boot"]["bits_corrected"]] = hist.get(r["boot"]["bits_corrected"], 0) + 1
print("  bits_corrected histogram:", dict(sorted(hist.items())))
wb = {}
for r in ok: wb[r["boot"]["worst_block"]] = wb.get(r["boot"]["worst_block"], 0) + 1
print("  worst_block histogram:", dict(sorted(wb.items())))

names = ["PUF read", "von Neumann", "fuzzy extractor decode", "KDF", "ML-DSA keygen", "ML-KEM keygen", "records", "verify", "install", "attest", "total", "(index 11)"]
print("\n== Table 5.10: boot stage cycles (cycles[] of the boot report); all %d restarts were attestation boots" % len(ok))
ev = {}
for r in ok: ev[r["boot"]["last_event"]] = ev.get(r["boot"]["last_event"], 0) + 1
print("  last_event counts (2 = attest):", ev)
print("  idx %-24s %8s %12s %12s %12s %10s %10s" % ("stage", "nonzero", "min", "mean", "max", "mean ms", "max ms"))
for i in range(12):
    xs = [r["boot"]["cycles"][i] for r in ok]
    nz = [x for x in xs if x]
    if nz:
        print("  %3d %-24s %8d %12d %12.0f %12d %10.2f %10.2f" % (i, names[i], len(nz), min(nz), st.mean(nz), max(nz), st.mean(nz) / 150000, max(nz) / 150000))
    else:
        print("  %3d %-24s %8d  (always 0)" % (i, names[i], 0))

# console cross-check
cl = os.path.join(d, "console.log")
if os.path.exists(cl):
    temps, causes, refr = [], {}, {}
    for l in open(cl, encoding="utf-8-sig", errors="replace"):
        m = re.search(r'"ev":"rot".*"cause":(\d+),"refreshes":(\d+),"temp_x10":(-?\d+)', l)
        if m:
            causes[int(m.group(1))] = causes.get(int(m.group(1)), 0) + 1
            refr[int(m.group(2))] = refr.get(int(m.group(2)), 0) + 1
            temps.append(int(m.group(3)))
    print("\n== console cross-check: %d 'rot' events seen on the USB console" % len(temps))
    if temps: print("  temp_x10 on console: %s;  cause counts %s; refreshes counts %s" % (stat(temps), causes, refr))
