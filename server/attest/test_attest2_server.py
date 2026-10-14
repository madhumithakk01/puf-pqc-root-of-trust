"""
Verifier-side tests for ATR2 and RCP1. Serialization is checked against the
digests pinned by the C tests (tests/attest/test_attest2.c), so the two
implementations agree byte for byte. ML-DSA is the attest_cli tool.

usage: test_attest2_server.py <path-to-attest_cli>
"""

import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import attest  # noqa: E402
import attest2  # noqa: E402

ATR2_PIN = "21e5dc9f8f3da17098a919d8c8b72f51c23ea654357c152e5717a5374fed105a"
RCP1_PIN = "36752a23e201e2c9c78c34cf8515a03395b8b851b46fdbaa461a2efb0036246d"

failures = 0


def check(name, ok):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        failures += 1


def fill(n, base):
    return bytes((base + i) & 0xFF for i in range(n))


def atr2_fixture():
    return dict(device_id=0xA1B2C3D4, svn=2, floor=2,
                verifier_nonce=fill(32, 0x10), rot_nonce=fill(32, 0x40),
                image_digest=fill(32, 0x70), active_slot=1, trial_state=0,
                reset_cause=1, flags=1, journal_seq=9, last_receipt_seq=4,
                bits_corrected=123, worst_block=4,
                last_receipt_digest=fill(32, 0xA0), version=b"1.1.0")


def rcp_fixture(**kw):
    f = dict(seq=5, device_id=0xA1B2C3D4, outcome=2, reason=20, slot=1,
             from_svn=2, to_svn=3, floor_before=2, floor_after=2,
             image_digest=fill(32, 0x11), package_digest=fill(32, 0x31),
             rot_nonce=fill(32, 0x51), evidence_digest=fill(32, 0x71),
             prev_digest=fill(32, 0x91), journal_seq=12, version=b"1.2.0")
    f.update(kw)
    return f


def digest_hex(b):
    return hashlib.shake_256(b).digest(32).hex()


def sign(mldsa, sk, body):
    return body + (2420).to_bytes(4, "little") + mldsa.sign(sk, body)


def main(cli):
    mldsa = attest.Mldsa(cli)
    pk, sk = mldsa.keygen_det(bytes(range(32)))
    pk2, _ = mldsa.keygen_det(bytes(range(1, 33)))

    body = attest2.serialize_atr2(atr2_fixture())
    check("ATR2 body digest equals the C pin", digest_hex(body) == ATR2_PIN)
    rep = attest2.parse_atr2(body)
    check("ATR2 parse", rep["device_id"] == 0xA1B2C3D4 and rep["floor"] == 2
          and rep["sim_puf"] and not rep["pmp_locked"] and rep["version"] == "1.1.0"
          and rep["bits_corrected"] == 123)
    obj = sign(mldsa, sk, body)
    check("ATR2 verify", attest2.verify_atr2(obj, pk, mldsa)["svn"] == 2)

    def rejects(fn):
        try:
            fn()
        except ValueError:
            return True
        return False

    check("ATR2 wrong key rejected", rejects(lambda: attest2.verify_atr2(obj, pk2, mldsa)))
    t = bytearray(obj); t[16] ^= 1
    check("ATR2 altered floor rejected", rejects(lambda: attest2.verify_atr2(bytes(t), pk, mldsa)))
    check("ATR2 truncated rejected", rejects(lambda: attest2.verify_atr2(obj[:-1], pk, mldsa)))
    t = bytearray(body); t[135] = 1
    check("ATR2 reserved byte rejected", rejects(lambda: attest2.parse_atr2(bytes(t))))

    rbody = attest2.serialize_rcp(rcp_fixture())
    check("RCP1 body digest equals the C pin", digest_hex(rbody) == RCP1_PIN)
    r = attest2.parse_rcp(rbody)
    check("RCP1 parse", r["outcome_name"] == "ROLLED_BACK" and r["reason"] == 20
          and r["reason_text"].startswith("health check failed") and r["to_svn"] == 3)
    robj = sign(mldsa, sk, rbody)
    check("RCP1 verify", attest2.verify_rcp(robj, pk, mldsa)["seq"] == 5)
    t = bytearray(robj); t[13] = 0
    check("RCP1 altered reason rejected", rejects(lambda: attest2.verify_rcp(bytes(t), pk, mldsa)))

    chain, prev = [], b"\0" * 32
    for i in range(1, 5):
        o = sign(mldsa, sk, attest2.serialize_rcp(rcp_fixture(seq=i, prev_digest=prev)))
        chain.append(o)
        prev = attest2.chain_digest(o)
    check("chain of 4 verifies", len(attest2.verify_chain(chain, pk, mldsa)) == 4)
    check("chain suffix verifies with predecessor digest",
          len(attest2.verify_chain(chain[2:], pk, mldsa, attest2.chain_digest(chain[1]))) == 2)
    check("reordered receipts rejected",
          rejects(lambda: attest2.verify_chain([chain[0], chain[2], chain[1], chain[3]], pk, mldsa)))
    check("removed receipt rejected",
          rejects(lambda: attest2.verify_chain([chain[0], chain[2], chain[3]], pk, mldsa)))
    t = bytearray(chain[1]); t[14] ^= 1
    check("altered receipt rejected",
          rejects(lambda: attest2.verify_chain([chain[0], bytes(t), chain[2]], pk, mldsa)))
    check("chain not starting from zero rejected",
          rejects(lambda: attest2.verify_chain(chain[1:], pk, mldsa)))

    st = attest2.DeviceState()
    ok_report = attest2.parse_atr2(body)
    check("first attestation raises no alert", st.check(ok_report) == [])
    older = dict(ok_report, floor=1)
    check("floor decrease raises STATE ROLLBACK", any("floor" in a for a in st.check(older)))
    older = dict(ok_report, last_receipt_seq=2)
    check("receipt sequence decrease raises STATE ROLLBACK",
          any("receipt" in a for a in st.check(older)))
    newer = dict(ok_report, floor=3, last_receipt_seq=6, journal_seq=11)
    check("monotonic increase accepted", st.check(newer) == [])

    print("test_attest2_server:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
