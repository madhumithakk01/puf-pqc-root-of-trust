# Secure boot flow

`src/secure_boot/secure_boot.{h,c}` — the boot-time accept/refuse decision.
`secure_boot_pack.c` builds signed images (server / test side; not device TCB).

## Image container

Little-endian:

| offset | field | |
|--|--|--|
| 0 | magic | `"SBI1"` |
| 4 | hdr_version | `1` |
| 6 | reserved | 0 |
| 8 | fw_version | uint64 — anti-rollback version |
| 16 | body_len | uint64 |
| 24 | body | `body_len` bytes |
| 24+body_len | sig_len | uint32, `<= 2420` |
| 28+body_len | sig | ML-DSA-44 signature |

The signature covers `image[0 : 24+body_len]` — the header fields and the body,
not `sig_len` / `sig`. Layout keeps the signed span contiguous so verification
is zero-copy.

## Decision

`secure_boot_check(otp, image, image_len, rb, rb_key, &result)` runs four gates;
the first failure wins:

1. **Structural** — magic, `hdr_version`, and the size arithmetic
   (`body_len`, `sig_len` bounds). Failure → `SB_REFUSE_MALFORMED`.
2. **Signature** — `PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify` against
   `otp.vendor_pubkey` (the vendor key in simulated OTP). Failure →
   `SB_REFUSE_BAD_SIGNATURE`.
3. **Counter integrity** — `rollback_verify`. A page carrying the magic with a
   bad MAC (tamper, or a torn counter update) or no valid page at all →
   `SB_REFUSE_COUNTER`. This is a *safe* failure: refuse rather than boot
   against an unauthenticated counter. A torn counter update is repaired by the
   install path re-running the update.
4. **Anti-rollback** — `fw_version >= counter`. Failure → `SB_REFUSE_ROLLBACK`.

`SB_BOOT` (0) otherwise. `result` also carries `fw_version`, `counter`, and the
raw `rollback_verify` rc.

## Exit-criteria coverage (`make -C tests check-secure-boot`)

Key material is deterministic (`tests/common/detrand.c`); the vendor public key
is pinned by digest.

| case | decision |
|--|--|
| valid image, `fw_version == counter` | `SB_BOOT` |
| valid image, `fw_version > counter` | `SB_BOOT` |
| `fw_version < counter` | `SB_REFUSE_ROLLBACK` |
| flipped signature byte | `SB_REFUSE_BAD_SIGNATURE` |
| flipped body byte (sig intact) | `SB_REFUSE_BAD_SIGNATURE` |
| `fw_version` bumped in place, not re-signed | `SB_REFUSE_BAD_SIGNATURE` |
| signed with the wrong key | `SB_REFUSE_BAD_SIGNATURE` |
| counter page bit flipped | `SB_REFUSE_COUNTER` |
| both counter pages corrupt | `SB_REFUSE_COUNTER` |
| counter store un-enrolled | `SB_REFUSE_COUNTER` |
| torn counter update | `SB_REFUSE_COUNTER` |
| truncated / bad magic / absurd `sig_len` / absurd `body_len` | `SB_REFUSE_MALFORMED` |
| bad sig **and** low version | `SB_REFUSE_BAD_SIGNATURE` (gate order) |
| valid sig, low version, **and** tampered counter | `SB_REFUSE_COUNTER` (gate order) |
