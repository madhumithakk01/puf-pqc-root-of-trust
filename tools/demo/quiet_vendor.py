"""
Vendor wrapper for the real board: stop talking to it while it prepares to restart.

The application schedules its restart 300 ms after the last request once an attestation request or
an install has been accepted, and every later frame moves that deadline again. vendor_lib polls the
board about seven times a second right after those requests, so the restart waits until the polling
stalls or ends. Measured on the board: the restart came 0.2 s after the first 1 s gap in traffic,
and up to 31 s after the request when no gap occurred.

QuietVendor sends the request, stays silent long enough for the restart to happen, and then polls
slowly enough (every POLL_S, longer than the quiet gap the board needs) that a poll cannot hold the
restart back. Reports, packages, receipts and their checks are exactly vendor_lib's.

Importing this module also makes vendor_lib.wait_for poll no faster than POLL_S for the whole process.
vendor_lib.deploy and the attack scenarios use it to wait for an install's restart, and a fast poll
there holds the restart back in the same way. The vendor_lib file itself is unchanged.
"""

import os
import secrets
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "server", "attest"))

import attest2  # noqa: E402
import vendor_lib as vl  # noqa: E402

QUIET_S = 2.0   # no traffic after a request that makes the board restart
POLL_S = 2.0    # spacing of polls; the board restarted 0.2 s after a gap of 1 s, so 2 s leaves margin


class QuietVendor(vl.Vendor):
    def attest(self, host, port, device_id, wait=60.0):
        """vl.Vendor.attest with a quiet period after the request and slow polling."""
        dev = self.registry.get(device_id)
        nonce = secrets.token_bytes(32)
        c = vl.Client(host, port)
        try:
            c.attest_req(nonce)
        finally:
            c.close()
        time.sleep(QUIET_S)
        end = time.time() + wait
        report = None
        while time.time() < end:
            try:
                c = vl.Client(host, port, timeout=3.0)
                try:
                    obj = c.get_attest()
                finally:
                    c.close()
                candidate = attest2.verify_atr2(obj, bytes.fromhex(dev["dsa_pk"]), self.mldsa)
            except (OSError, ConnectionError, vl.ProtocolError, ValueError):
                time.sleep(POLL_S)
                continue
            if candidate["verifier_nonce"] == nonce:
                report = candidate
                break
            time.sleep(POLL_S)
        if report is None:
            raise vl.AttestationError("no report carrying the verifier's nonce arrived")
        if report["device_id"] != device_id:
            raise vl.AttestationError("report names another device")
        state = attest2.DeviceState()
        state.max_floor = dev["max_floor"]
        state.max_receipt_seq = dev["max_receipt_seq"]
        state.max_journal_seq = dev["max_journal_seq"]
        alerts = state.check(report)
        if not alerts:
            dev["max_floor"] = state.max_floor
            dev["max_receipt_seq"] = state.max_receipt_seq
            dev["max_journal_seq"] = state.max_journal_seq
        dev["history"].append({"t": time.time(), "svn": report["svn"], "floor": report["floor"],
                               "alerts": alerts})
        self.registry.save()
        report["alerts"] = alerts
        return report


if not getattr(vl.wait_for, "slow_poll", False):
    _fast_wait_for = vl.wait_for

    def _slow_wait_for(host, port, pred, timeout=60.0, interval=0.1):
        return _fast_wait_for(host, port, pred, timeout, max(interval, POLL_S))

    _slow_wait_for.slow_poll = True
    vl.wait_for = _slow_wait_for
