# Toolchain setup

The supported development host is **Ubuntu 24.04** (native or WSL2). All build
and simulation steps run there; CI uses the same packages on an `ubuntu-24.04`
runner. Windows is supported only through WSL2 — the native MSVC/MinGW
toolchains are not used for the cross-compile or QEMU flow.

## Packages

```
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential make \
    gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf \
    qemu-system-misc \
    python3-venv python3-pip
```

| Package | Provides | Used by |
| --- | --- | --- |
| `build-essential`, `make` | host C compiler, `make` | building host-side tests and vendored library KATs (Phase 1+) |
| `gcc-riscv64-unknown-elf` | `riscv64-unknown-elf-{gcc,ld,objcopy,size,...}`, multilib incl. `rv32imac/ilp32` | the RV32 cross build |
| `picolibc-riscv64-unknown-elf` | small embedded libc for the cross target | freestanding test programs that need a libc (Phase 2) |
| `qemu-system-misc` | `qemu-system-riscv32`, `qemu-system-riscv64` | booting images |
| `python3-venv`, `python3-pip` | isolated Python envs | measurement / KAT-comparison scripts (Phase 1+) |

Reference versions (Ubuntu 24.04, at time of writing): GCC 13.2.0 for the
cross target, binutils 2.42, QEMU 8.2.2, GNU Make 4.3.

## Verify

```
riscv64-unknown-elf-gcc --version
qemu-system-riscv32 --version
make --version

git clone <this repo>
cd puf-pqc-root-of-trust
make boot-test        # builds build/hello.elf, boots it, expects "boot-test: PASS"
```

`make boot-test` boots the image on the QEMU `virt` machine with `-bios none`,
checks for the boot banner on the UART, and requires a clean exit through the
SiFive test finisher. This is the Phase 0 exit check.

## RV32 target details

- Machine: QEMU `virt`, single hart, `-bios none` (the image is the reset
  payload, linked to run in place from the RAM base `0x8000_0000`).
- ISA / ABI: `-march=rv32imac -mabi=ilp32`.
- Console: NS16550A UART at `0x1000_0000`.
- Exit: write `0x5555` to the SiFive test finisher at `0x0010_0000` for a
  clean QEMU exit (code 0).

## PQClean (from Phase 1)

The post-quantum primitives come from [PQClean](https://github.com/PQClean/PQClean),
vendored under `third_party/pqclean/` at a pinned commit — not installed system
wide. PQClean has no build system of its own beyond per-scheme makefiles and no
external dependencies; each scheme builds to a static archive with the host or
cross compiler:

```
# host KATs
make -C third_party/pqclean/crypto_sign/ml-dsa-44/clean

# RV32 cross build (Phase 2)
make -C third_party/pqclean/crypto_sign/ml-dsa-44/clean \
    CC=riscv64-unknown-elf-gcc \
    CFLAGS="-march=rv32imac -mabi=ilp32 -Os -ffreestanding"
```

Exact vendoring commit and per-scheme wiring are recorded when Phase 1 lands.
