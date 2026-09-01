# pqc-memory-footprint

Measures the RV32 memory footprint of ML-DSA-44 and ML-KEM-512 (PQClean
reference C) so the eventual board choice has numbers to cite. Output:
[`docs/pqc-footprint.md`](../../docs/pqc-footprint.md).

## Run

```
spikes/pqc-memory-footprint/measure.sh docs/pqc-footprint.md
```

Needs the RV32 toolchain and `qemu-system-riscv32` (see `docs/toolchain.md`).
Builds into `build/spike/`.

## What it does

For each of `mldsa_{keygen,sign,verify}` and `mlkem_{keygen,encaps,decaps}`:

- **`.text` / `.rodata` / `.data`** from `size -A` on an image linked with
  `--gc-sections` so only that one operation's code is present. A `baseline`
  image (harness + runtime + Keccak, no lattice op) is the common denominator;
  the tables report the delta.
- **Stack high-water mark** two ways that should agree:
  - *measured* — `rt.c` paints the stack, the op runs 16× with a varied
    message, the lowest touched word gives the peak (`harness.c`).
  - *static bound* — `analyze-stack.py` walks the `-fstack-usage` frame sizes
    over the `objdump` call graph for the true worst-case path.
- **Heap high-water mark** — PQClean's reference `fips202` `malloc`s each
  Keccak context; `rt.c`'s arena reports the peak.

`measure.sh` then classifies each operation against RFC 7228.

## Files

| file | role |
| --- | --- |
| `Makefile` | builds one image: `make OP=<op> OPT=<Os\|O2> FIX=<runtime\|static>` |
| `harness.c` | per-op dispatch, stack painting loop, UART report |
| `rt/` | freestanding runtime: `start.S`, `link.ld`, libc shims, UART, arena, SHAKE256 DRBG, `randombytes.h` shim (avoids `<unistd.h>`) |
| `analyze-stack.py` | static worst-case stack from `.su` + disassembly |
| `measure.sh` | build the matrix, run under QEMU, emit `docs/pqc-footprint.md` |

## Caveat

The PQClean reference C is used **unmodified**. Its `fips202` heap-allocates
Keccak state and it is not stack-optimised. A production embedded port would
change both; that is out of scope for a footprint spike. The numbers are a
faithful measurement of the reference implementation as-is on RV32.
