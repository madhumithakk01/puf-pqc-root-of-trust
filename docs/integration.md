# QEMU integration + attack harness

One RV32 image runs the full boot chain: read the (noisy) simulated PUF ->
fuzzy-extractor `Rep` -> KDF -> authenticate the rollback counter ->
verify the firmware signature -> boot / refuse. Regenerate with
`make -C integration attacks`.

- toolchain: riscv64-unknown-elf-gcc (13.2.0-11ubuntu1+12) 13.2.0
- qemu: QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
- target: rv32imac_zicsr / ilp32, QEMU virt, -bios none, -Os

## Scripted attacks

| scenario | provisioned | at boot | decision |
|---|---|---|---|
| good | device 1, counter 3, firmware fw_version 3 | device 1, 2% PUF noise | **BOOT** |
| rollback_replay | counter 3, an *older* validly-signed firmware (fw_version 2) | device 1 | **REFUSE / ROLLBACK** |
| tampered_counter | one flipped bit in the newest counter page | device 1 | **REFUSE / COUNTER** |
| cloned_flash | device 1's helper data + counter pages | device **2** | **REFUSE / COUNTER** |

Every attack is refused. `cloned_flash` shows the anti-cloning property: the
helper data and firmware are inert on different silicon because the
fuzzy-extractor recovers a different key, so the counter MAC no longer verifies.

## Baselines (good-boot image)

| metric | value |
|---|--:|
| flash (`.text` + `.data`) | 17900 B |
| `.text` | 17900 B |
| `.data` | 0 B |
| `.bss` | 32784 B (incl. a 32 KiB Keccak heap arena; see below) |
| heap high-water (Keccak arena) | 224 B |
| boot cost (`rdinstret` delta) | 3860987 instructions retired |

The image reserves a fixed 32 KiB `.bss` arena for PQClean fips202's
`malloc`'d Keccak contexts; only 224 B is actually used on the boot path
(contexts are allocated and freed in sequence, so one is live at a time).
`rdinstret` (instructions retired) is deterministic under QEMU for
deterministic code, so it is a stable regression baseline; it is dominated by
the ML-DSA-44 signature verification. Stack is not re-measured here; see
`docs/pqc-footprint.md` for the ML-DSA-44 verify stack figure.
