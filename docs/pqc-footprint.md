# PQC memory footprint on RV32

Cross-compiled ML-DSA-44 and ML-KEM-512 (PQClean portable reference C, "clean"),
measured on RV32 under QEMU. This is the footprint evidence a later hardware
choice cites; regenerate with `spikes/pqc-memory-footprint/measure.sh`.

- toolchain: riscv64-unknown-elf-gcc (13.2.0-11ubuntu1+12) 13.2.0
- qemu: QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
- PQClean pin: see `third_party/pqclean/PROVENANCE.md`

## Method

- **Target**: `riscv64-unknown-elf-gcc -march=rv32imac -mabi=ilp32`, QEMU
  `virt`, `-bios none`, run in place from the RAM base.
- **Code (`.text` / `.rodata` / `.data`)**: `size -A` on an image that calls
  exactly one primitive, built with `-ffunction-sections -fdata-sections
  -Wl,--gc-sections` so only that operation's reachable code is linked. The
  **baseline** image is the harness + runtime + Keccak with no lattice
  operation; **code Δ** is `(.text+.rodata)` above baseline, i.e. the
  scheme-specific code. Full standalone flash for an operation is
  `baseline(.text+.rodata) + code Δ`.
- **`.bss` Δ** is the caller-held key / signature / ciphertext buffers; the
  schemes themselves have no `.data` and ~no `.bss`.
- **Stack HWM (measured)**: the stack is painted with a sentinel before each
  call and scanned afterward for the lowest touched word; the max over 16
  iterations with a varied message. Includes ≲300 B of harness framing beneath
  the measurement point.
- **Stack (static bound)**: `analyze-stack.py` — GCC `-fstack-usage` frame
  sizes over the call graph from `objdump -d`, maximum root-to-leaf path. A
  true worst-case upper bound (the code is non-recursive). The two agree to
  within ~1 %.
- **Heap HWM**: PQClean's reference `fips202` heap-allocates every Keccak
  context (208 B). The harness uses a LIFO arena and reports its peak. A
  production port would make these static/stack; the reference C is left
  unmodified here. ~224 B of the figure is the persistent DRBG context.
- **RNG**: a fixed-seed SHAKE256 stream, so every number is reproducible.

## RFC 7228 mapping

RFC 7228 sizes a device by order of magnitude: Class 0 << 10 KiB RAM /
<< 100 KiB code, Class 1 ~10 KiB / ~100 KiB, Class 2 ~50 KiB / ~250 KiB.

**Code is never the constraint here** — every operation's standalone flash is
~9-15 KiB, inside the Class 0 budget. The label below is therefore driven by
**RAM need = stack HWM (measured) + heap HWM + caller buffers**, bucketed as
`< 8 KiB -> 0`, `< 14 KiB -> 1`, `<= 50 KiB -> 2`, `> 50 KiB -> beyond Class 2`.
Raw KiB is shown so the bound can be re-judged.

`.data` is 0 for every operation (no mutable initialised globals), so it is
omitted from the tables.

## Results (`-Os`, primary)

Baseline flash (`.text+.rodata`, harness + runtime + Keccak): 5840 B.

| operation | code Δ | flash total | stack HWM | stack bound | heap HWM | caller bufs | RAM need | RFC 7228 |
|---|--:|--:|--:|--:|--:|--:|--:|:--:|
| mldsa_keygen | 4876 B | 10.5 KiB | 38292 B | 38352 B | 448 B | 3872 B | **41.6 KiB** | **2** |
| mldsa_sign | 6658 B | 12.2 KiB | 51764 B | 51824 B | 448 B | 5012 B | **55.9 KiB** | **> 2 (over ~50 KiB RAM)** |
| mldsa_verify | 5308 B | 10.9 KiB | 36004 B | 36064 B | 448 B | 3764 B | **39.3 KiB** | **2** |
| mlkem_keygen | 3228 B | 8.9 KiB | 6232 B | 6544 B | 448 B | 2432 B | **8.9 KiB** | **1** |
| mlkem_encaps | 4106 B | 9.7 KiB | 8872 B | 9184 B | 448 B | 1600 B | **10.7 KiB** | **1** |
| mlkem_decaps | 4686 B | 10.3 KiB | 9624 B | 9936 B | 448 B | 2432 B | **12.2 KiB** | **1** |

## Results (`-O2`)

Baseline flash (`.text+.rodata`, harness + runtime + Keccak): 8454 B.

| operation | code Δ | flash total | stack HWM | stack bound | heap HWM | caller bufs | RAM need | RFC 7228 |
|---|--:|--:|--:|--:|--:|--:|--:|:--:|
| mldsa_keygen | 5456 B | 13.6 KiB | 38452 B | 38496 B | 448 B | 3872 B | **41.8 KiB** | **2** |
| mldsa_sign | 7540 B | 15.6 KiB | 51908 B | 51952 B | 448 B | 5012 B | **56.0 KiB** | **> 2 (over ~50 KiB RAM)** |
| mldsa_verify | 5884 B | 14.0 KiB | 36164 B | 36208 B | 448 B | 3764 B | **39.4 KiB** | **2** |
| mlkem_keygen | 3680 B | 11.8 KiB | 6292 B | 6608 B | 448 B | 2432 B | **9.0 KiB** | **1** |
| mlkem_encaps | 4628 B | 12.8 KiB | 8932 B | 9248 B | 448 B | 1600 B | **10.7 KiB** | **1** |
| mlkem_decaps | 5152 B | 13.3 KiB | 9684 B | 10000 B | 448 B | 2432 B | **12.3 KiB** | **1** |

## Reading the numbers

- **ML-DSA-44** — flash is tiny (~11-13 KiB standalone), but stack is
  36-52 KiB. `sign` is the worst at ~52 KiB stack / ~56 KiB RAM need, which is
  **at or just past the Class 2 RAM budget**. `keygen` ~42 KiB and `verify`
  ~39 KiB RAM are solidly Class 2. These are stack-dominated and inherent to
  the scheme's polynomial working set; the reference C is unoptimised but the
  dominant buffers will not shrink far.
- **ML-KEM-512** — flash ~9-11 KiB, stack 6-10 KiB, RAM need ~9-12 KiB:
  **Class 1**, with `encaps` / `decaps` (~11-12 KiB) sitting on the Class 1/2
  border relative to RFC 7228's nominal ~10 KiB Class 1 figure.
- `-O2` costs ~30 % more flash for essentially identical stack; a constrained
  target would ship `-Os`.

## Consequence for the hardware choice

A board that must run **ML-DSA-44 `sign`** on-device needs **~56 KiB of SRAM
free for the crypto working set alone**, on top of a reserved PUF region, the
application, and its own stack/heap. That rules out Class 0/1 parts and the
smallest Class 2 boards (e.g. 32 KiB-SRAM GD32VF103 / Longan Nano). A
~64 KiB-SRAM part is extremely tight (sign alone ≈ 87 % of RAM); a part with
hundreds of KiB (e.g. ESP32-C3, ~400 KiB) clears it with margin. If the device
only ever **verifies** (signing done off-device), the requirement drops to
~39 KiB — still Class 2, still not a sub-32 KiB part.

RAM is the gate, not flash. This is the input to the SRAM-PUF vs RO-PUF and
board decisions.
