#!/usr/bin/env bash
# Special builds for the hardware measurements (Tables 5.3 and 5.9). Run in WSL: bash tools/measure/build_special.sh
# Output goes to data/builds/<name>/, never to data/demo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
source "$HOME/pico/env.sh"
echo "source commit: $(git rev-parse HEAD)  (firmware tree identical to safe-2/safe-1: $(git diff --stat safe-2 HEAD -- firmware src app third_party | wc -l) differing lines)"
OUT="$ROOT/data/builds"
mkdir -p "$OUT/rot-selftest" "$OUT/bench"
echo "== rot with ROT_SELFTEST=1"
nice -n 10 cmake -S firmware -B "$OUT/rot-selftest/cmake" -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-riscv -DROT_SELFTEST=1 >/dev/null
nice -n 10 cmake --build "$OUT/rot-selftest/cmake" --target rot >/dev/null
cp "$OUT/rot-selftest/cmake/rot/rot.uf2" "$OUT/rot-selftest/rot-selftest.uf2"
python3 tools/ci/check_map.py rot "$OUT/rot-selftest/cmake/rot/rot.elf" | tail -2
echo "== bench"
nice -n 10 cmake -S firmware -B "$OUT/bench/cmake" -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-riscv >/dev/null
nice -n 10 cmake --build "$OUT/bench/cmake" --target bench >/dev/null
cp "$OUT/bench/cmake/bench/bench.uf2" "$OUT/bench/bench.uf2"
sha256sum "$OUT/rot-selftest/rot-selftest.uf2" "$OUT/bench/bench.uf2"
ls -l "$OUT/rot-selftest/rot-selftest.uf2" "$OUT/bench/bench.uf2"
echo BUILD_DONE
