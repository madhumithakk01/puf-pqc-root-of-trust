#!/usr/bin/env bash
# Build everything the demo needs, in WSL / Linux, from the repository root:
#
#   bash tools/demo/build_all.sh
#
# Output goes to data/demo: rot.uf2 (the root of trust) and the three signed application
# images v1_0_0 / v1_1_0 / v1_2_0 .sbi.bin. The Wi-Fi name and password come from
# firmware/wifi.cmake (not committed). Needs the toolchain from tools/setup/setup_linux.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
[ -f firmware/wifi.cmake ] || { echo "create firmware/wifi.cmake first (set(WIFI_SSID ...) set(WIFI_PASSWORD ...))"; exit 1; }
# shellcheck disable=SC1090
source "${HOME}/pico/env.sh"

OUT="${ROOT}/data/demo"
mkdir -p "${OUT}" "${ROOT}/data/vendor"

echo "== vendor tools"
make -C tests check-vendor-cli >/dev/null
test -x build/tests/vendor_cli && test -x build/tests/attest_cli

echo "== keys"
python3 tools/demo/demo.py setup

echo "== root of trust (production build)"
cmake -S firmware -B build/fw-rot -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-riscv >/dev/null
cmake --build build/fw-rot --target rot >/dev/null
python3 tools/ci/check_map.py rot build/fw-rot/rot/rot.elf
cp build/fw-rot/rot/rot.uf2 "${OUT}/rot.uf2"

echo "== application images v1.0.0 v1.1.0 v1.2.0 (signed)"
bash tools/vendor/build_images.sh "${ROOT}/data/vendor/vendor.sk" "${OUT}" >/dev/null
ls -l "${OUT}"/rot.uf2 "${OUT}"/v1_?_0.sbi.bin
echo "done"
