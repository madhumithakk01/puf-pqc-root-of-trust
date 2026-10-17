"""Summarise one validation run: result, times, restart delays, rejoin times, receipts."""
import os
import re
import statistics as st
import sys
from datetime import datetime, timedelta

P = datetime.fromisoformat
run = sys.argv[1]


def rd(name):
    p = os.path.join(run, name)
    return open(p, encoding="utf-8-sig", errors="replace").read() if os.path.exists(p) else ""


def lines(name):
    for l in rd(name).splitlines():
        t, _, r = l.partition(" ")
        try:
            yield P(t), r
        except ValueError:
            pass


def fmt(xs):
    return "n=%d median %.1f max %.1f s" % (len(xs), st.median(xs), max(xs)) if xs else "none observed"


# clock offset WSL - Windows, interpolated between the start and end measurements
def off(name):
    t, o = rd(name).split()[:2]
    return P(t), float(o)


try:
    (ts, os_), (te, oe) = off("offset_start.txt"), off("offset_end.txt")
except Exception:
    ts = te = None
    os_ = oe = 0.8


def offset_at(t):
    if ts is None or te == ts:
        return os_
    f = min(1.0, max(0.0, (t - ts).total_seconds() / (te - ts).total_seconds()))
    return os_ + f * (oe - os_)


def to_win(t_wsl):
    return t_wsl - timedelta(seconds=offset_at(t_wsl))


story = list(lines("story.log"))
summary = [r for _, r in story if "steps passed" in r]
hic = sum(1 for _, r in story if "hiccup" in r)
sens = sum(1 for _, r in story if "sensor did not answer" in r)
acted = sum(1 for _, r in story if "already acted" in r)
steps = []
for t, r in story:
    m = re.match(r"STORY     (PASS|FAIL)\s+(.*)\((\d+) s\)", r)
    if m:
        steps.append((m.group(1), int(m.group(3)), m.group(2).strip()))
print("run dir:", run)
print("fresh-demo: %s s" % rd("fresh_seconds.txt").strip())
if os.path.exists(os.path.join(run, "freeze.txt")):
    print("FREEZE recorded:\n" + rd("freeze.txt"))
if story:
    wall = (story[-1][0] - story[0][0]).total_seconds()
else:
    wall = 0
print("result:", summary[0].replace("STORY ", "") if summary else "NO SUMMARY (story did not finish)")
print("steps:", "".join("P" if s == "PASS" else "F" for s, _, _ in steps), "step seconds", [t for _, t, _ in steps])
print("story wall time %.0f s (%.1f min); network hiccups %d; sensor retries %d; attempts not repeated after the board acted %d" % (wall, wall / 60, hic, sens, acted))

con = list(lines("console.log"))
discs = [t for t, r in con if r.startswith("DISCONNECT")]
req = {3: [], 7: []}
for t, r in lines("trace.log"):
    m = re.match(r"TRACE req type=(\d+) lport=\d+ ok (\d+)ms", r)
    if m and int(m.group(1)) in req:
        req[int(m.group(1))].append(to_win(t) - timedelta(milliseconds=int(m.group(2))))
for typ, label in ((3, "after an attest request"), (7, "after the install push (PKG_END)")):
    ds = []
    for a in req[typ]:
        nx = next((x for x in discs if x > a), None)
        if nx:
            ds.append((nx - a).total_seconds())
    print("restart delay %-34s %s%s" % (label, fmt(ds), "   [%s]" % " ".join("%.1f" % d for d in ds) if ds else ""))

rot = None
rj = []
joinfail = 0
for t, r in con:
    if '"ev":"rot"' in r:
        rot = rot or t
    elif "wifi join failed" in r:
        joinfail += 1
    elif r.startswith("LINE ip ") and rot:
        rj.append((t - rot).total_seconds())
        rot = None
print("Wi-Fi rejoin (rot line to ip line): %s; join-failed lines %d" % (fmt(rj), joinfail))

bc = [t for t, r in lines("beacon.log") if "BEACON" in r]
gaps = [(b - a).total_seconds() for a, b in zip(bc, bc[1:])]
gw = [("TIMEOUT" not in r) for t, r in lines("pingwin.log") if "PING gateway" in r]
print("beacons %d, longest silence %.0f s; gateway pings %d, timeouts %d" % (len(bc), max(gaps) if gaps else 0, len(gw), sum(1 for x in gw if not x)))

rc = rd("receipts_all.txt").splitlines()
chain = [l for l in rc if l.startswith("chain verified")]
rows = [l.split("|") for l in rc if re.match(r"\d+\|", l)]
bad = []
for r in rows:
    seq, out, reason, fs, ts_, fb, fa, text = r[0], r[1], r[2], int(r[3]), int(r[4]), int(r[5]), int(r[6]), r[7]
    if int(fa) < int(fb) or (out == "COMMITTED" and ts_ > 2) or int(fa) > 2:
        bad.append((seq, "floor or version moved wrongly", r))
    elif out == "REFUSED" and reason not in ("2", "3", "4", "5", "6"):
        bad.append((seq, "unexpected refusal reason", r))
    elif out == "ROLLED_BACK" and reason != "20":
        bad.append((seq, "rollback for a reason other than heart rate (reason %s: %s)" % (reason, text), r))
print("receipts: %s, %d receipts" % (chain[0] if chain else "NOT FETCHED", len(rows)))
expected = [("COMMITTED", "0"), ("ROLLED_BACK", "20"), ("REFUSED", "5"), ("REFUSED", "6"), ("REFUSED", "2"),
            ("COMMITTED", "0"), ("REFUSED", "4"), ("REFUSED", "3"), ("COMMITTED", "0")]
got = [(r[1], r[2]) for r in rows]
if got == expected:
    print("receipt sequence: exactly the 9 expected (commit, heart-rate rollback, SVN-below-floor, digest, unknown signer, genuine, stale nonce, not-for-this-device, genuine)")
else:
    print("receipt sequence differs from the 9 expected:", " ".join("%s/%s" % g for g in got))
print("receipts with a wrong security outcome:", "none" if not bad else "")
for b in bad:
    print("   #%s %s: %s" % b)
