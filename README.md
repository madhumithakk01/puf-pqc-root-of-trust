# puf-pqc-root-of-trust

Post-quantum, PUF-anchored secure boot and rollback-protected OTA for RISC-V IoT
devices. A device-unique secret derived from an on-chip PUF seeds a
rollback-authentication key, a signing identity, and a KEM identity, layered
under a post-quantum (ML-DSA) signature verifier anchored in OTP. Development
proceeds in software/QEMU simulation first, FPGA/hardware second.

## Status

- Minimal RV32 image builds from a clean checkout and boots under QEMU.
- ML-DSA-44, ML-KEM-512, and SHAKE256 wired through vendored PQClean reference
  C; ML-DSA-44 and ML-KEM-512 pass the NIST KAT, both pass functional and
  tamper-rejection tests.
- Domain-separated KDF (`SHAKE256(key || label)`) with known-answer and
  label-independence tests.
- RV32 memory-footprint measurements for both schemes ([docs/pqc-footprint.md](docs/pqc-footprint.md)).
- Simulated PUF (device-unique fingerprint + configurable bit-error noise) for
  pre-hardware development.

## Requirements

A bare-metal RISC-V toolchain (`riscv64-unknown-elf-*`), `qemu-system-riscv32`,
a host C compiler, and `make`. See [docs/toolchain.md](docs/toolchain.md) for
exact packages and the supported host setup (WSL2 / Ubuntu 24.04).

## Build and run

```
make            # build build/hello.elf
make run        # boot it under QEMU (exit with Ctrl-A X)
make boot-test  # boot, assert the banner and a clean QEMU exit
make test       # host tests: PQC NIST KAT + functional, SHAKE256, KDF, PUF sim
make footprint  # regenerate docs/pqc-footprint.md
make clean
```

`make boot-test` and `make test` are what CI runs.

## Layout

```
platform/qemu-virt-rv32/   startup, linker script, and the minimal boot image
src/                       project sources (kdf/, puf/ ...)
third_party/pqclean/       vendored PQClean subset (see PROVENANCE.md)
tests/                     host test drivers and the test Makefile
spikes/                    self-contained investigations (pqc-memory-footprint)
docs/                      toolchain setup, design notes, measurement tables
tools/                     build and run helpers
.github/workflows/         CI
```
