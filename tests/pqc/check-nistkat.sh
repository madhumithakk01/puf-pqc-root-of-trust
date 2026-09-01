#!/usr/bin/env bash
#
# Run each NIST KAT driver and check that the SHA-256 of its output matches the
# expected value -- the hash of the first NIST-format KAT vector for that
# scheme. Expected values are the nistkat-sha256 fields from the pinned
# PQClean META.yml files (see third_party/pqclean/PROVENANCE.md).

set -euo pipefail

BUILD="${1:?usage: check-nistkat.sh <build-dir>}"

declare -A WANT=(
    [ml-dsa-44]=9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3
    [ml-kem-512]=c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782
)
declare -A BIN=(
    [ml-dsa-44]="$BUILD/nistkat_mldsa"
    [ml-kem-512]="$BUILD/nistkat_mlkem"
)

fail=0
for scheme in ml-dsa-44 ml-kem-512; do
    got="$("${BIN[$scheme]}" | sha256sum | cut -d' ' -f1)"
    if [ "$got" = "${WANT[$scheme]}" ]; then
        printf 'nistkat %-11s PASS  %s\n' "$scheme" "$got"
    else
        printf 'nistkat %-11s FAIL\n  want %s\n  got  %s\n' \
               "$scheme" "${WANT[$scheme]}" "$got"
        fail=1
    fi
done
exit "$fail"
