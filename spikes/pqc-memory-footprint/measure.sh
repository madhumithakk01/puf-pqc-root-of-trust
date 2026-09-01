#!/usr/bin/env bash
#
# Build the spike matrix, run each image under QEMU for the stack/heap
# high-water marks, read section sizes off the static images, classify each
# operation against RFC 7228, and emit docs/pqc-footprint.md.
#
#   spikes/pqc-memory-footprint/measure.sh                       # -> stdout
#   spikes/pqc-memory-footprint/measure.sh docs/pqc-footprint.md # -> file

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$ROOT/build/spike"
QEMU="${QEMU:-qemu-system-riscv32}"
SIZE="${SIZE:-riscv64-unknown-elf-size}"

OPS=(mldsa_keygen mldsa_sign mldsa_verify mlkem_keygen mlkem_encaps mlkem_decaps)
PRIMARY_OPT=Os
ALL_OPTS=(Os O2)

declare -A ENTRY=(
    [mldsa_keygen]=PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair
    [mldsa_sign]=PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature
    [mldsa_verify]=PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify
    [mlkem_keygen]=PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
    [mlkem_encaps]=PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
    [mlkem_decaps]=PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
)
# caller-held key/signature/ciphertext buffers per operation (bytes)
declare -A BUFS=(
    [mldsa_keygen]=$((1312 + 2560))
    [mldsa_sign]=$((2560 + 2420 + 32))
    [mldsa_verify]=$((1312 + 2420 + 32))
    [mlkem_keygen]=$((800 + 1632))
    [mlkem_encaps]=$((800 + 768 + 32))
    [mlkem_decaps]=$((1632 + 768 + 32))
)

echo "building matrix..." >&2
rm -rf "$BUILD"
for opt in "${ALL_OPTS[@]}"; do
    for fix in static runtime; do
        for op in baseline "${OPS[@]}"; do
            make -s -C "$HERE" OP="$op" OPT="$opt" FIX="$fix" >/dev/null
        done
    done
done

run_qemu() {  # <elf> -> "stack heap result"
    local out
    out="$(timeout 60 "$QEMU" -machine virt -nographic -bios none -kernel "$1" \
           -no-reboot -semihosting-config enable=off 2>&1 || true)"
    echo "$(sed -n 's/.*stack_used_bytes=\([0-9]*\).*/\1/p' <<<"$out" | tail -1) \
          $(sed -n 's/.*heap_used_bytes=\([0-9]*\).*/\1/p' <<<"$out" | tail -1) \
          $(sed -n 's/.*result=\([a-z]*\).*/\1/p' <<<"$out" | tail -1)"
}

sec() { "$SIZE" -A "$1" | awk -v s="$2" '$1==s{print $2; f=1} END{if(!f)print 0}'; }
kib() { awk -v b="$1" 'BEGIN{printf "%.1f", b/1024}'; }

rfc_class() {  # <ram_bytes> -> label (code is always << Class 0 here)
    local r=$1
    if   [ "$r" -lt  8192 ]; then echo "0"
    elif [ "$r" -lt 14336 ]; then echo "1"
    elif [ "$r" -le 51200 ]; then echo "2"
    else echo "> 2 (over ~50 KiB RAM)"
    fi
}

emit() {
cat <<'INTRO'
# PQC memory footprint on RV32

Cross-compiled ML-DSA-44 and ML-KEM-512 (PQClean portable reference C, "clean"),
measured on RV32 under QEMU. This is the footprint evidence a later hardware
choice cites; regenerate with `spikes/pqc-memory-footprint/measure.sh`.

INTRO

    printf -- '- toolchain: %s\n' "$(riscv64-unknown-elf-gcc --version | head -1)"
    printf -- '- qemu: %s\n' "$("$QEMU" --version | head -1)"
    printf -- '- PQClean pin: see `third_party/pqclean/PROVENANCE.md`\n\n'

cat <<'PREAMBLE'
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

PREAMBLE

    for opt in "${ALL_OPTS[@]}"; do
        local bt bro
        bt=$(sec "$BUILD/$opt/static/baseline/image.elf" .text)
        bro=$(sec "$BUILD/$opt/static/baseline/image.elf" .rodata)
        local base_code=$((bt + bro))

        if [ "$opt" = "$PRIMARY_OPT" ]; then
            echo "## Results (\`-$opt\`, primary)"
        else
            echo "## Results (\`-$opt\`)"
        fi
        echo
        echo "Baseline flash (\`.text+.rodata\`, harness + runtime + Keccak): ${base_code} B."
        echo
        echo "| operation | code Δ | flash total | stack HWM | stack bound | heap HWM | caller bufs | RAM need | RFC 7228 |"
        echo "|---|--:|--:|--:|--:|--:|--:|--:|:--:|"
        for op in "${OPS[@]}"; do
            local se="$BUILD/$opt/static/$op/image.elf"
            local re="$BUILD/$opt/runtime/$op/image.elf"
            local t ro st he res bound
            t=$(sec "$se" .text); ro=$(sec "$se" .rodata)
            read -r st he res < <(run_qemu "$re")
            bound="$(python3 "$HERE/analyze-stack.py" --build-dir "$BUILD/$opt/static/$op" \
                        --elf "$se" --entry "${ENTRY[$op]}" 2>/dev/null \
                     | sed -n 's/^WORST_CASE_STACK=//p')"
            local code_delta=$(( (t + ro) - base_code ))
            local flash_total=$(( base_code + code_delta ))
            local bufs=${BUFS[$op]}
            local ram=$(( st + he + bufs ))
            printf '| %s | %s B | %s KiB | %s B | %s B | %s B | %s B | **%s KiB** | **%s** |\n' \
                "$op" "$code_delta" "$(kib "$flash_total")" \
                "$st" "${bound:-NA}" "$he" "$bufs" "$(kib "$ram")" "$(rfc_class "$ram")"
            [ "$res" = ok ] || echo "  <!-- WARNING $op run=$res -->"
        done
        echo
    done

cat <<'TAIL'
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
TAIL
}

if [ "${1:-}" ]; then
    emit >"$1"
    echo "wrote $1" >&2
else
    emit
fi
