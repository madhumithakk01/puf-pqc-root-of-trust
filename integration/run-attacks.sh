#!/usr/bin/env bash
#
# Boot each integration scenario under QEMU and assert its decision, then
# record the good-boot latency and flash-footprint baselines to
# docs/integration.md.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$ROOT/build/integration"
QEMU="${QEMU:-qemu-system-riscv32}"
SIZE="${SIZE:-riscv64-unknown-elf-size}"

# scenario -> expected RESULT and (for refusals) expected decision=
declare -A EXPECT_RESULT=(
    [good]=BOOT
    [rollback_replay]=REFUSE
    [tampered_counter]=REFUSE
    [cloned_flash]=REFUSE
)
declare -A EXPECT_DECISION=(
    [rollback_replay]=ROLLBACK
    [tampered_counter]=COUNTER
    [cloned_flash]=COUNTER
)

run() { # <elf> -> full UART transcript
    # -icount shift=0 makes rdinstret a true, host-independent instruction count
    timeout 120 "$QEMU" -machine virt -nographic -bios none -kernel "$1" \
        -no-reboot -semihosting-config enable=off -icount shift=0 2>&1 || true
}
field() { sed -n "s/.*$1=\([A-Za-z0-9_]*\).*/\1/p" <<<"$2" | tail -1; }

fail=0
declare -A OUT
for s in good rollback_replay tampered_counter cloned_flash; do
    out="$(run "$BUILD/$s/image.elf")"
    OUT[$s]="$out"
    res="$(field RESULT "$out")"
    dec="$(field decision "$out")"
    want_res="${EXPECT_RESULT[$s]}"
    want_dec="${EXPECT_DECISION[$s]:-}"

    ok=1
    [ "$res" = "$want_res" ] || ok=0
    if [ -n "$want_dec" ] && [ "$dec" != "$want_dec" ]; then ok=0; fi

    if [ "$ok" = 1 ]; then
        printf 'scenario %-18s %-6s (decision=%s) PASS\n' "$s" "$res" "${dec:-BOOT}"
    else
        printf 'scenario %-18s FAIL  got RESULT=%s decision=%s  want RESULT=%s decision=%s\n' \
            "$s" "$res" "$dec" "$want_res" "${want_dec:-BOOT}"
        fail=1
    fi
done

if [ "$fail" != 0 ]; then
    echo "--- transcripts ---"
    for s in "${!OUT[@]}"; do echo "== $s =="; echo "${OUT[$s]}"; done
    exit 1
fi

# --- baselines from the good-boot image ---
good_out="${OUT[good]}"
instret="$(field boot_instret "$good_out")"
heap="$(field heap_hwm "$good_out")"
counter="$(field counter "$good_out")"
fwver="$(field fw_version "$good_out")"
sz="$("$SIZE" "$BUILD/good/image.elf" | awk 'NR==2{print $1, $2, $3, $4}')"
read -r text data bss dec <<<"$sz"
flash=$((text + data))

doc="$ROOT/docs/integration.md"
cat > "$doc" <<EOF
# QEMU integration + attack harness

One RV32 image runs the full boot chain: read the (noisy) simulated PUF ->
fuzzy-extractor \`Rep\` -> KDF -> authenticate the rollback counter ->
verify the firmware signature -> boot / refuse. Regenerate with
\`make -C integration attacks\`.

- toolchain: $(riscv64-unknown-elf-gcc --version | head -1)
- qemu: $("$QEMU" --version | head -1)
- target: rv32imac_zicsr / ilp32, QEMU virt, -bios none, -Os

## Scripted attacks

| scenario | provisioned | at boot | decision |
|---|---|---|---|
| good | device 1, counter $counter, firmware fw_version $fwver | device 1, 2% PUF noise | **BOOT** |
| rollback_replay | counter $counter, an *older* validly-signed firmware (fw_version 2) | device 1 | **REFUSE / ROLLBACK** |
| tampered_counter | one flipped bit in the newest counter page | device 1 | **REFUSE / COUNTER** |
| cloned_flash | device 1's helper data + counter pages | device **2** | **REFUSE / COUNTER** |

Every attack is refused. \`cloned_flash\` shows the anti-cloning property: the
helper data and firmware are inert on different silicon because the
fuzzy-extractor recovers a different key, so the counter MAC no longer verifies.

## Baselines (good-boot image)

| metric | value |
|---|--:|
| flash (\`.text\` + \`.data\`) | ${flash} B |
| \`.text\` | ${text} B |
| \`.data\` | ${data} B |
| \`.bss\` | ${bss} B (incl. a 32 KiB Keccak heap arena; see below) |
| heap high-water (Keccak arena) | ${heap} B |
| boot cost (\`rdinstret\` delta) | ${instret} instructions retired |

The image reserves a fixed 32 KiB \`.bss\` arena for PQClean fips202's
\`malloc\`'d Keccak contexts; only ${heap} B is actually used on the boot path
(contexts are allocated and freed in sequence, so one is live at a time).
\`rdinstret\` (instructions retired) is deterministic under QEMU for
deterministic code, so it is a stable regression baseline; it is dominated by
the ML-DSA-44 signature verification. Stack is not re-measured here; see
\`docs/pqc-footprint.md\` for the ML-DSA-44 verify stack figure.
EOF

echo "wrote $doc"
echo "baseline: flash=${flash}B bss=${bss}B heap=${heap}B boot=${instret} instret"
