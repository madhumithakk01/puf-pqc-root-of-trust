#!/usr/bin/env python3
"""
Attestation server tests. Run: test_attest_server.py <path-to-attest_cli>

Exit criterion: the server accepts a genuine fresh report and rejects a
replayed one. Plus stale/unknown nonce, tampered report, wrong device key, a
cert not signed by the CA, and a device-id mismatch.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attest import (AttestVerifier, Mldsa, build_signed_report, make_cert,
                    serialize_report)

PINNED_REPORT = (
    "415452310100000003000000000000000200000000000000"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

fails = 0


def expect(name, cond):
    global fails
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        fails += 1


def main():
    if len(sys.argv) < 2:
        print("usage: test_attest_server.py <attest_cli>", file=sys.stderr)
        return 2
    m = Mldsa(sys.argv[1])

    ca_pk, ca_sk = m.keygen_det(b"attest-test/ca")
    d1_pk, d1_sk = m.keygen_det(b"attest-test/device-1")
    d2_pk, d2_sk = m.keygen_det(b"attest-test/device-2")
    cert1 = make_cert(1, d1_pk, ca_sk, m)

    v = AttestVerifier(ca_pk, m)

    # 1. genuine fresh report -> accepted
    n1 = v.issue_challenge()
    rep1, sig1 = build_signed_report(1, 3, 2, n1, d1_sk, m)
    ok, why, info = v.verify(cert1, rep1, sig1)
    expect("genuine fresh report accepted",
           ok and why == "accepted" and info["fw_version"] == 3 and info["cnt"] == 2)

    # 2. exact replay of the same bundle -> rejected
    ok, why, _ = v.verify(cert1, rep1, sig1)
    expect("replayed report rejected", (not ok) and why == "replayed nonce")

    # 3. a second genuine report on a fresh challenge -> accepted; its nonce is
    #    then consumed, so re-submitting is a replay
    n2 = v.issue_challenge()
    rep2, sig2 = build_signed_report(1, 4, 2, n2, d1_sk, m)
    ok, why, _ = v.verify(cert1, rep2, sig2)
    expect("second genuine report accepted", ok)
    ok, why, _ = v.verify(cert1, rep2, sig2)
    expect("re-use of a consumed nonce rejected", (not ok) and why == "replayed nonce")

    # 4. nonce the verifier never issued -> rejected
    bogus = bytes(range(32))
    rep_b, sig_b = build_signed_report(1, 3, 2, bogus, d1_sk, m)
    ok, why, _ = v.verify(cert1, rep_b, sig_b)
    expect("unknown / stale nonce rejected",
           (not ok) and why == "unknown or stale nonce")

    # 5. tampered report (fw_version flipped after signing) -> bad signature
    n5 = v.issue_challenge()
    rep5 = bytearray(serialize_report(1, 3, 2, n5))
    sig5 = m.sign(d1_sk, bytes(rep5))
    rep5[8] ^= 0x01
    ok, why, _ = v.verify(cert1, bytes(rep5), sig5)
    expect("tampered report rejected", (not ok) and why == "bad report signature")

    # 6. report signed by the wrong device key -> bad signature
    n6 = v.issue_challenge()
    rep6 = serialize_report(1, 3, 2, n6)
    ok, why, _ = v.verify(cert1, rep6, m.sign(d2_sk, rep6))
    expect("report signed by wrong device key rejected",
           (not ok) and why == "bad report signature")

    # 7. certificate not signed by the CA -> bad chain
    fake_cert = make_cert(1, d1_pk, d2_sk, m)  # device 2 posing as CA
    n7 = v.issue_challenge()
    rep7 = serialize_report(1, 3, 2, n7)
    ok, why, _ = v.verify(fake_cert, rep7, m.sign(d1_sk, rep7))
    expect("cert not signed by the CA rejected", (not ok) and why == "bad cert chain")

    # 8. cert is for device 1 but the report claims device 7
    n8 = v.issue_challenge()
    rep8 = serialize_report(7, 3, 2, n8)
    ok, why, _ = v.verify(cert1, rep8, m.sign(d1_sk, rep8))
    expect("device id mismatch rejected", (not ok) and why == "device id mismatch")

    # 9. serialization matches the bytes the C side pins
    expect("report serialization matches pinned bytes",
           serialize_report(1, 3, 2, bytes(range(32))).hex() == PINNED_REPORT)

    if fails:
        print(f"test_attest_server: FAIL ({fails})")
        return 1
    print("test_attest_server: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
