#!/usr/bin/env bash
# Build the application for 1.0.0, 1.1.0 and 1.2.0 and sign each as an SBI1 image.
#
#   build_images.sh VENDOR_SK OUT_DIR
#
# Needs the pico toolchain (source ~/pico/env.sh) and a built vendor_cli
# (make -C tests vendor-cli). The golden values in each manifest come from the
# correct v1.0/v1.1 DSP, so the v1.2 image carries v1.1's limits and fails them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SK="${1:?vendor secret key}"
OUT="${2:?output directory}"
CLI="${VENDOR_CLI:-${ROOT}/build/tests/vendor_cli}"
mkdir -p "${OUT}"

build() { # version svn golden
    local ver="$1" svn="$2" golden="$3" dir="${ROOT}/build/fw-app-$1"
    cmake -S "${ROOT}/firmware" -B "${dir}" -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-riscv \
        -DAPP_VERSION="${ver}" -DAPP_SVN="${svn}" >/dev/null
    cmake --build "${dir}" --target app >/dev/null
    "${CLI}" sign-image --app "${dir}/app/app.bin" --svn "${svn}" --version "${ver}" --key "${SK}" \
        --golden-from "${golden}" --build-id "$(git -C "${ROOT}" rev-parse HEAD | cut -c1-40)" \
        --out "${OUT}/v${ver//./_}.sbi.bin"
}

build 1.0.0 1 v10
build 1.1.0 2 v11
build 1.2.0 3 v11
