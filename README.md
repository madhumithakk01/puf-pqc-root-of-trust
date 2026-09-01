# puf-pqc-root-of-trust

Post-quantum, PUF-anchored secure boot and rollback-protected OTA for RISC-V IoT
devices. A device-unique secret derived from an on-chip PUF seeds a
rollback-authentication key, a signing identity, and a KEM identity, layered
under a post-quantum (ML-DSA) signature verifier anchored in OTP. Development
proceeds in software/QEMU simulation first, FPGA/hardware second.

## Status

Phase 0 — repository scaffold. A clean checkout builds a minimal RV32 image and
boots it under QEMU.

## Requirements

A bare-metal RISC-V toolchain (`riscv64-unknown-elf-*`), `qemu-system-riscv32`,
and `make`. See [docs/toolchain.md](docs/toolchain.md) for exact packages and the
supported host setup (WSL2 / Ubuntu 24.04).

## Build and run

```
make            # build build/hello.elf
make run        # boot it under QEMU (exit with Ctrl-A X)
make boot-test  # boot, assert the banner and a clean QEMU exit
make clean
```

`make boot-test` is the Phase 0 exit check and is what CI runs.

## Layout

```
platform/qemu-virt-rv32/   startup, linker script, and the minimal boot image
docs/                      toolchain setup, design notes, measurement tables
tools/                     build and run helpers
third_party/               vendored dependencies (added from Phase 1)
.github/workflows/         CI
```
