#!/usr/bin/env bash
#
# Boot an RV32 ELF on the QEMU 'virt' machine and assert that it printed the
# expected banner and exited cleanly. Used by `make boot-test` and CI as the
# Phase 0 exit check.

set -euo pipefail

ELF="${1:?usage: run-qemu.sh <elf>}"
QEMU="${QEMU:-qemu-system-riscv32}"
EXPECT="${EXPECT:-puf-pqc-root-of-trust: RV32 boot OK}"
TIMEOUT="${TIMEOUT:-20}"

LOG="$(mktemp)"
set +e
timeout "${TIMEOUT}" "${QEMU}" \
    -machine virt -display none -bios none -kernel "${ELF}" \
    -no-reboot -semihosting-config enable=off \
    -chardev file,id=char0,path="${LOG}" \
    -serial chardev:char0 \
    -monitor none
rc=$?
set -e
out="$(cat "${LOG}")"
rm -f "${LOG}"

printf '%s\n' "${out}"
echo "---"
echo "qemu exit: ${rc}"

if [ "${rc}" -eq 124 ]; then
    echo "boot-test: FAIL (timed out after ${TIMEOUT}s; no clean exit)"
    exit 1
fi

if ! printf '%s' "${out}" | grep -qF "${EXPECT}"; then
    echo "boot-test: FAIL (expected banner not found: '${EXPECT}')"
    exit 1
fi

echo "boot-test: PASS"
