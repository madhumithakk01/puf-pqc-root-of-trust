#!/usr/bin/env python3
"""Round-trip tests for vendor_cli.

Independent checks: signatures are verified with the separate attest_cli
ML-DSA tool, digests with hashlib.

usage: test_vendor_cli.py <vendor_cli> <attest_cli>
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

failures = 0


def check(name, ok):
    global failures
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        failures += 1


def main(cli, attest_cli):
    tmp = tempfile.mkdtemp(prefix="vendor_cli_test_")

    def run(*args, ok=True):
        p = subprocess.run([cli, *args], capture_output=True, cwd=tmp)
        if ok and p.returncode != 0:
            raise RuntimeError(f"{args}: {p.stderr.decode()}")
        return p

    def js(*args):
        return json.loads(run(*args).stdout)

    def read(name):
        return open(os.path.join(tmp, name), "rb").read()

    def mldsa_verify(pk, sig, msg):
        p = subprocess.run([attest_cli, "verify"], capture_output=True,
                           input=(pk.hex() + "\n" + sig.hex() + "\n" + msg.hex() + "\n").encode())
        return p.returncode == 0

    seed_a = "00" * 32
    seed_b = "01" + "00" * 31
    a1 = js("keygen", "va", "--seed", seed_a)
    a2 = js("keygen", "vb", "--seed", seed_a)
    b1 = js("keygen", "vc", "--seed", seed_b)
    check("same seed gives the same key pair", a1["fingerprint"] == a2["fingerprint"] and read("va.pk") == read("vb.pk"))
    check("another seed gives another key", a1["fingerprint"] != b1["fingerprint"])
    check("key sizes are ML-DSA-44", len(read("va.pk")) == 1312 and len(read("va.sk")) == 2560)
    r1 = js("keygen", "r1")
    r2 = js("keygen", "r2")
    check("keys without a seed come from the OS and differ", r1["fingerprint"] != r2["fingerprint"])

    d = js("keygen-device", "dev", "--seed", "07" * 32)
    d2 = js("keygen-device", "dev2", "--seed", "07" * 32)
    check("device identity is a pure function of the UDS", d == dict(d2, name="dev"))
    check("device key sizes", len(read("dev.dsa.pk")) == 1312 and len(read("dev.kem.pk")) == 800)
    expect_id = hashlib.shake_256(b"rot/v1/device-id" + read("dev.dsa.pk")).digest(4)
    check("device id is the first 4 bytes of the identity hash (little-endian)",
          struct.unpack("<I", expect_id)[0] == int(d["device_id"], 16))

    open(os.path.join(tmp, "app.bin"), "wb").write(bytes((i * 3) & 0xFF for i in range(9000)))
    info = js("sign-image", "--app", "app.bin", "--svn", "2", "--version", "1.1.0", "--key", "va.sk",
              "--golden-from", "v11", "--out", "v11.sbi.bin")
    img = read("v11.sbi.bin")
    check("image starts with SBI1 and the fw_version", img[:4] == b"SBI1" and struct.unpack("<Q", img[8:16])[0] == 2)
    body_len = struct.unpack("<Q", img[16:24])[0]
    check("body is the 4072-byte manifest plus the binary", body_len == 4072 + 9000)
    check("the binary starts 4 KB into the image", img[4096:4096 + 9000] == read("app.bin"))
    sig_len = struct.unpack("<I", img[24 + body_len:28 + body_len])[0]
    sig = img[28 + body_len:28 + body_len + sig_len]
    check("the image signature verifies under the vendor key",
          sig_len == 2420 and run("verify-image", "--pk", "va.pk", "v11.sbi.bin", ok=False).returncode == 0)
    check("a different vendor key does not verify",
          run("verify-image", "--pk", "vc.pk", "v11.sbi.bin", ok=False).returncode != 0)
    tampered = bytearray(img)
    tampered[5000] ^= 1
    open(os.path.join(tmp, "tampered.sbi.bin"), "wb").write(bytes(tampered))
    check("a flipped body bit does not verify",
          run("verify-image", "--pk", "va.pk", "tampered.sbi.bin", ok=False).returncode != 0)
    ins = js("inspect", "v11.sbi.bin")
    check("inspect: SBI1 fields", ins["kind"] == "SBI1" and ins["fw_version"] == 2 and ins["apm_status"] == 0
          and ins["binary_offset_in_image"] == 4096 and ins["apm"]["version"] == "1.1.0")
    check("inspect: golden values come from the v1.1 DSP", abs(ins["apm"]["golden_bpm_x10"] - 968) <= 20
          and abs(ins["apm"]["golden_spo2_x10"] - 1000) <= 30 and ins["apm"]["tol_bpm_x10"] == 30)
    check("sign-image reports the same golden values", info["golden_bpm_x10"] == ins["apm"]["golden_bpm_x10"])
    trace_digest = ins["apm"]["golden_digest"]
    check("the manifest records a digest of the golden trace", len(trace_digest) == 64 and trace_digest != "00" * 32)

    v10 = js("sign-image", "--app", "app.bin", "--svn", "1", "--version", "1.0.0", "--key", "va.sk",
             "--golden-from", "v10", "--out", "v10.sbi.bin")
    ins10 = js("inspect", "v10.sbi.bin")
    check("v1.0 manifest has no SpO2 limit", ins10["apm"]["golden_spo2_x10"] == 0xFFFF)

    bad = run("sign-image", "--app", "app.bin", "--svn", "1", "--version", "x" * 17, "--key", "va.sk",
              "--golden-from", "v10", "--out", "bad.bin", ok=False)
    check("an over-long version string is refused", bad.returncode != 0)
    bad = run("sign-image", "--app", "app.bin", "--svn", "1", "--version", "1", "--key", "va.pk",
              "--golden-from", "v10", "--out", "bad.bin", ok=False)
    check("a public key is refused as the signing key", bad.returncode != 0)

    nonce = bytes(range(32)).hex()
    devid = d["device_id"]
    pk_info = js("package", "--image", "v11.sbi.bin", "--device-id", devid, "--kem-pk", "dev.kem.pk",
                 "--nonce", nonce, "--svn", "2", "--version", "1.1.0", "--key", "va.sk", "--out", "pkg.bin")
    pkg = read("pkg.bin")
    check("package size: DLV1 2552 + OTA1 840 + image", len(pkg) == 2552 + 840 + len(img)
          and pk_info["package_len"] == len(pkg))
    ins = js("inspect", "pkg.bin")
    check("inspect: DLV1 fields", ins["kind"] == "DLV1" and ins["svn"] == 2 and ins["rot_nonce"] == nonce
          and ins["ota_magic"] == "OTA1" and ins["image_len"] == len(img) and ins["version"] == "1.1.0")
    check("DLV1 device id is stored little-endian", struct.unpack("<I", pkg[8:12])[0] == int(devid, 16))
    ota = pkg[2552:]
    digest = hashlib.shake_256(b"dlv/v1/ota" + ota).digest(32).hex()
    check("ota_digest equals SHAKE256 of the OTA1 bytes", digest == ins["ota_digest"] == pk_info["ota_digest"])
    dsig_len = struct.unpack("<I", pkg[128:132])[0]
    check("manifest signature verifies independently", dsig_len == 2420 and mldsa_verify(read("va.pk"), pkg[132:2552], pkg[:128]))
    check("OTA1 length field and layout", ota[:4] == b"OTA1" and struct.unpack("<Q", ota[8 + 768 + 24:8 + 768 + 24 + 8])[0] == len(img)
          and len(ota) == 8 + 768 + 24 + 8 + len(img) + 32)
    check("the plaintext image does not appear in the package", img[4096:4096 + 64] not in pkg)

    pkg2 = run("package", "--image", "v11.sbi.bin", "--device-id", devid, "--kem-pk", "dev.kem.pk",
               "--nonce", nonce, "--svn", "2", "--version", "1.1.0", "--key", "va.sk", "--out", "pkg2.bin")
    check("two packages of one image differ (fresh KEM and nonce each time)", read("pkg2.bin") != pkg)

    bad = run("package", "--image", "v11.sbi.bin", "--device-id", devid, "--kem-pk", "va.pk",
              "--nonce", nonce, "--svn", "2", "--version", "1", "--key", "va.sk", "--out", "bad.bin", ok=False)
    check("a signing public key is refused as the KEM key", bad.returncode != 0)
    bad = run("package", "--image", "v11.sbi.bin", "--device-id", devid, "--kem-pk", "dev.kem.pk",
              "--nonce", "00", "--svn", "2", "--version", "1", "--key", "va.sk", "--out", "bad.bin", ok=False)
    check("a short nonce is refused", bad.returncode != 0)

    bad = run("inspect", "app.bin", ok=False)
    check("an unrecognised file is refused", bad.returncode != 0)

    print("test_vendor_cli:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])))
