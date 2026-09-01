# Confidential OTA delivery

`src/ota/ota.{h,c}` — device side. `ota_pack.c` — server side (not device TCB).
`ota_aead.{h,c}` — the SHAKE256 encrypt-then-MAC used inside.

## Flow

**Server** (`ota_pack`): sign the firmware into a Phase-6 secure-boot image,
KEM-encapsulate a fresh 32-byte secret to the device's ML-KEM-512 public key,
then encrypt-then-MAC the signed image under keys derived from that secret.

**Device** (`ota_install`): decapsulate with the device KEM secret key,
recompute the MAC, decrypt into the inactive A/B bank, run `secure_boot_check`
on the recovered image, and — only on `SB_BOOT` — mark that bank pending.
`ota_confirm` promotes it to active; `ota_reject` drops it and keeps the
current bank.

A package encapsulated to a *different* device's key decapsulates to a
different shared secret (ML-KEM implicit rejection), so the derived MAC key is
wrong and the tag check fails — surfaced as `OTA_ERR_AUTH`, nothing staged.

## Package container

Little-endian:

| offset | field |
|--|--|
| 0 | magic `"OTA1"` |
| 4 | version `1` |
| 8 | ML-KEM-512 ciphertext (768) |
| 776 | nonce (24) |
| 800 | payload_len (uint64) |
| 808 | ciphertext of the signed image |
| 808 + payload_len | tag (32) |

## AEAD

Keys from the ML-KEM shared secret via the project KDF:

```
enc_key = KDF(ss, "ota/v1/enc-key")
mac_key = KDF(ss, "ota/v1/mac-key")
ct      = pt XOR SHAKE256(enc_key || nonce)          (streamed)
tag     = SHAKE256(mac_key || nonce || LE64(len) || ct)   (encrypt-then-MAC)
```

Not a standardised AEAD, but a sound PRF/XOF construction consistent with the
KDF and rollback MAC already in the tree; a later swap to AES-GCM / a KMAC AEAD
does not change the package layout.

## Exit-criteria coverage (`make -C tests check-ota`)

Deterministic keys (`tests/common/detrand.c`); the staged image is pinned by
digest.

| case | result |
|--|--|
| correctly packaged update | `OTA_OK`, stages to the inactive bank; `secure_boot_check` on it returns `SB_BOOT`; after `ota_confirm` the active image boots at the new version |
| packaged for another device's KEM key | `OTA_ERR_AUTH`, nothing staged |
| tampered payload / KEM ciphertext / tag | `OTA_ERR_AUTH` |
| inner signature by the wrong key | `OTA_ERR_REJECTED_BY_SECURE_BOOT` (`SB_REFUSE_BAD_SIGNATURE`) |
| `fw_version` below the rollback counter | `OTA_ERR_REJECTED_BY_SECURE_BOOT` (`SB_REFUSE_ROLLBACK`) |
| truncated / bad magic / absurd `payload_len` | `OTA_ERR_MALFORMED` |
| `ota_reject` after a staged install | pending dropped, inactive bank wiped, active image intact |
| failed OTA after a confirm | active bank unchanged, no pending |
