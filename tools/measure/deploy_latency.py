"""Table 5.12: update latency per deploy stage from the request traces of validation runs.

  python tools/measure/deploy_latency.py [DIR [RUN ...]]        (default DIR data/results/validation, runs 19 20 21)

Reads runN/story.log and runN/trace.log (written by run_tip.ps1) and, for the three vendor deploys of each story
(steps 2, 3 and 4), splits the time into attest, package, push and install-and-trial, as vendor_lib.deploy does.
Prints one record per deploy and the mean (range) per kind of deploy and over all deploys. Times are WSL clock
differences, so no clock offset is involved.
"""
import os, re, statistics as st, sys, json
from datetime import datetime, timedelta
P = datetime.fromisoformat
D = sys.argv[1] if len(sys.argv) > 1 else os.path.join("data", "results", "validation")
RUNS = [int(x) for x in sys.argv[2:]] or [19, 20, 21]

def lines(f):
    for l in open(f, encoding="utf-8-sig", errors="replace"):
        t, _, r = l.rstrip("\n").partition(" ")
        try: yield P(t), r
        except ValueError: pass

rows = []   # (run, step, kind, attest, package, push, install, total, fetch)
for run in RUNS:
    story = list(lines(os.path.join(D, f"run{run}", "story.log")))
    ev = []
    for t, r in lines(os.path.join(D, f"run{run}", "trace.log")):
        m = re.match(r"TRACE connect ok (\d+)ms", r)
        if m: ev.append((t, "connect", int(m.group(1)), None)); continue
        m = re.match(r"TRACE req type=(\d+) lport=\d+ ok (\d+)ms", r)
        if m: ev.append((t, "req", int(m.group(2)), int(m.group(1))))
    for n, kind in ((2, "v1.1 committed"), (3, "v1.2 rolled back"), (4, "v1.0 refused")):
        s0 = next(t for t, r in story if r.startswith(f"STORY [{n}]"))
        s1 = next(t for t, r in story if t > s0 and re.match(r"STORY     (PASS|FAIL)", r))
        w = [e for e in ev if s0 <= e[0] <= s1]
        def start(i):   # start time of event i
            return w[i][0] - timedelta(milliseconds=w[i][2])
        i3 = next(i for i, e in enumerate(w) if e[1] == "req" and e[3] == 3)
        a_start = start(i3 - 1)                      # the connect before ATTEST_REQ
        i5 = next(i for i, e in enumerate(w) if e[1] == "req" and e[3] == 5)
        last4 = max(i for i, e in enumerate(w[:i5]) if e[1] == "req" and e[3] == 4)
        push_start = start(i5 - 1)                   # the connect before PKG_BEGIN
        i7 = next(i for i, e in enumerate(w) if e[1] == "req" and e[3] == 7)
        i8 = next(i for i, e in enumerate(w) if e[1] == "req" and e[3] == 8)
        last1 = max(i for i, e in enumerate(w[:i8]) if e[1] == "req" and e[3] == 1)
        att = (w[last4][0] - a_start).total_seconds()
        pkg = (push_start - w[last4][0]).total_seconds()
        push = (w[i7][0] - push_start).total_seconds()
        inst = (w[last1][0] - w[i7][0]).total_seconds()
        tot = (w[last1][0] - a_start).total_seconds()
        fetch = (w[-1][0] - start(i8 - 1)).total_seconds() if i8 else 0
        npoll_att = sum(1 for e in w[i3:i5] if e[1] == "req" and e[3] == 4)
        npoll_inst = sum(1 for e in w[i7:i8] if e[1] == "req" and e[3] == 1)
        pk = [e for e in w if e[1] == "req" and e[3] == 6]
        rows.append(dict(run=run, step=n, kind=kind, attest=att, package=pkg, push=push, install_trial=inst, total=tot,
                         chunks=len(pk), polls_attest=npoll_att, polls_install=npoll_inst))
print(json.dumps(rows, indent=0))
def stats(key, sel):
    xs = [r[key] for r in rows if sel(r)]
    return "%.2f (%.2f-%.2f)" % (st.mean(xs), min(xs), max(xs)), len(xs)
print()
for label, sel in (("all 9 deploys", lambda r: True), ("v1.1 committed", lambda r: r["step"] == 2),
                   ("v1.2 rolled back", lambda r: r["step"] == 3), ("v1.0 refused", lambda r: r["step"] == 4)):
    print(label, {k: stats(k, sel)[0] for k in ("attest", "package", "push", "install_trial", "total")}, "n=%d" % stats("total", sel)[1])
