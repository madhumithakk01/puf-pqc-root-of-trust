# Attestation / fleet loop

Device side: `src/attest/attest.{h,c}` — serialize and sign a report.
Server side: `server/attest/attest.py` — a stdlib-only verifier that delegates
ML-DSA-44 to the `attest_cli` C tool (`tools/attest/`).

> Stretch phase. A one-level certificate chain (CA -> device) and an in-memory
> nonce set; no persistence, no network transport.

## Protocol

1. Server issues a random 32-byte challenge `nonce`.
2. Device serializes `report = {device_id, fw_version, cnt, nonce}` and signs it
   with its attestation key (ML-DSA-44).
3. Device sends `(enrollment_cert, report, sig)`; the cert was provisioned at
   enrollment and binds `device_id` to the device's attestation public key,
   signed by the CA.
4. Server checks, in order:
   - the cert body verifies under the CA public key — else `bad cert chain`;
   - `report.device_id == cert.device_id` — else `device id mismatch`;
   - `sig` verifies over `report` under the cert's device key — else
     `bad report signature`;
   - `report.nonce` was issued and not yet consumed — else `replayed nonce`
     (already used) or `unknown or stale nonce` (never issued);
   - accept, and consume the nonce.

### Report serialization (little-endian, 56 bytes)

| offset | field |
|--|--|
| 0 | magic `"ATR1"` |
| 4 | device_id (uint32) |
| 8 | fw_version (uint64) |
| 16 | cnt (uint64) |
| 24 | nonce (32) |

The C and Python sides pin the same bytes for a fixed input.

### Enrollment certificate (little-endian)

`"ATC1"` ‖ device_id (uint32) ‖ device_pubkey (1312) ‖ sig_len (uint32) ‖
CA signature over the preceding body.

## Tests

- **`make -C tests check-attest`** runs both:
  - `tests/attest/test_attest` (C): serialization matches the pinned bytes;
    sign/verify round-trips; tampered report, tampered signature, and wrong
    public key are rejected.
  - `server/attest/test_attest_server.py` (Python): a **genuine fresh report is
    accepted and an exact replay is rejected**; a consumed nonce re-used is
    rejected; a never-issued nonce is rejected; a report tampered after signing,
    a report signed by the wrong device key, a certificate not signed by the
    CA, and a device-id mismatch are each rejected.

`attest_cli` (`tools/attest/attest_cli.c`) is a thin hex-over-stdio wrapper for
ML-DSA-44 keygen-det / sign / verify; it is a build/test tool, not device
firmware.
