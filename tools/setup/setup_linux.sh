#!/usr/bin/env bash
# Installs the Pico 2 W firmware toolchain under $PICO_HOME (default ~/pico).
# Idempotent: every step is skipped when its result already exists.
#
#   pico-sdk 2.3.1 (with submodules), RISC-V GCC (riscv-toolchain-16),
#   picotool 2.3.1 (prebuilt), CMake and Ninja in a Python venv.
#
# Nothing here needs root. The host-test dependencies (build-essential,
# riscv64-unknown-elf-gcc, qemu) are listed in docs/toolchain.md.
set -euo pipefail

PICO_HOME="${PICO_HOME:-$HOME/pico}"
SDK_TAG=2.3.1
TOOLS_TAG=v2.3.1-0
TOOLS_URL="https://github.com/raspberrypi/pico-sdk-tools/releases/download/${TOOLS_TAG}"
CMAKE_VER=3.31.6
NINJA_VER=1.13.0

mkdir -p "${PICO_HOME}"
cd "${PICO_HOME}"

if [ ! -d pico-sdk/.git ]; then
    git clone --branch "${SDK_TAG}" --depth 1 https://github.com/raspberrypi/pico-sdk.git
fi
git -C pico-sdk submodule update --init --depth 1

if [ ! -d riscv-toolchain-16/bin ]; then
    curl -fL -o riscv-toolchain-16.tar.gz "${TOOLS_URL}/riscv-toolchain-16-x86_64-lin.tar.gz"
    mkdir -p riscv-toolchain-16
    tar -xf riscv-toolchain-16.tar.gz -C riscv-toolchain-16
    rm -f riscv-toolchain-16.tar.gz
    # Some releases unpack into a single subdirectory.
    if [ ! -d riscv-toolchain-16/bin ]; then
        sub="$(find riscv-toolchain-16 -maxdepth 2 -type d -name bin | head -1)"
        [ -n "${sub}" ] && mv "$(dirname "${sub}")"/* riscv-toolchain-16/ || true
    fi
fi

if [ ! -x picotool/picotool ]; then
    curl -fL -o picotool.tar.gz "${TOOLS_URL}/picotool-2.3.1-x86_64-lin.tar.gz"
    mkdir -p picotool-extract
    tar -xf picotool.tar.gz -C picotool-extract
    rm -f picotool.tar.gz
    found="$(find picotool-extract -type f -name picotool | head -1)"
    mkdir -p picotool
    cp -r "$(dirname "${found}")"/. picotool/
    rm -rf picotool-extract
fi

if [ ! -x venv/bin/cmake ]; then
    python3 -m venv venv
    venv/bin/pip install --quiet "cmake==${CMAKE_VER}" "ninja==${NINJA_VER}" pyserial pytest
fi

cat > env.sh <<EOF
export PICO_HOME="${PICO_HOME}"
export PICO_SDK_PATH="${PICO_HOME}/pico-sdk"
export PICO_TOOLCHAIN_PATH="${PICO_HOME}/riscv-toolchain-16"
export PATH="${PICO_HOME}/venv/bin:${PICO_HOME}/picotool:${PICO_HOME}/riscv-toolchain-16/bin:\$PATH"
EOF

echo "toolchain installed under ${PICO_HOME}; source ${PICO_HOME}/env.sh"
ls riscv-toolchain-16/bin | grep -- '-gcc$' || true
venv/bin/cmake --version | head -1
venv/bin/ninja --version
