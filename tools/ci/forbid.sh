#!/usr/bin/env bash
# Fails if the tree contains anything on the never-do list: OTP writes,
# rollback versions in IMAGE_DEFs, TBYB images, SRAM clearing on load,
# persistent-data sections in RoT/charz, or restricted partition permissions.
# Documentation is not scanned; it has to be able to name these patterns.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

SCAN=()
for d in firmware tools src host app tests .github Makefile; do
    [ -e "$d" ] && SCAN+=("$d")
done

EXCL=(--exclude=forbid.sh --exclude-dir=build --exclude-dir=data
      --exclude-dir=third_party --exclude-dir=.git)

fail=0
hit() { # <description> <extended regex> [path...]
    local desc="$1" re="$2"; shift 2
    local paths=("$@")
    [ ${#paths[@]} -eq 0 ] && paths=("${SCAN[@]}")
    local out
    out="$(grep -rnIE "${EXCL[@]}" -e "${re}" "${paths[@]}" 2>/dev/null)"
    if [ -n "${out}" ]; then
        echo "FORBIDDEN: ${desc}"
        echo "${out}" | sed 's/^/    /'
        fail=1
    fi
}

hit "OTP write via picotool"       'otp[[:space:]]+(set|load|permissions)'
hit "OTP white-labelling"          'white-label'
hit "rollback version in IMAGE_DEF" '(seal[[:space:]]+.*)?--rollback'
hit "SRAM clear on load (seal)"    'seal[[:space:]]+.*--clear'
hit "SRAM clear on load (cmake)"   'pico_load_map_clear_sram'
hit "TBYB image type"              'PICO_CRT0_IMAGE_TYPE_TBYB'
hit "OTP write helper"             'rom_func_otp_access|otp_write|otp_hw->[a-z_]+(\[[^]]*\])?[[:space:]]*(=|\|=|&=)[^=]'

for d in firmware/rot firmware/charz; do
    [ -d "$d" ] && hit "persistent data section in ${d}" '__persistent_data' "$d"
done

# Every bootloader permission in a partition table must be "rw".
for f in $(find firmware -name '*.json' -not -path '*/build/*' 2>/dev/null); do
    bad="$(grep -nE '"bootloader"[[:space:]]*:' "$f" | grep -vE '"bootloader"[[:space:]]*:[[:space:]]*"rw"')"
    if [ -n "${bad}" ]; then
        echo "FORBIDDEN: restricted bootloader permission in ${f}"
        echo "${bad}" | sed 's/^/    /'
        fail=1
    fi
done

if [ "${fail}" -ne 0 ]; then
    exit 1
fi
echo "forbid: clean"
