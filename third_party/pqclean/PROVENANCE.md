# Vendored PQClean subset

Upstream: https://github.com/PQClean/PQClean
Pinned commit: `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (2026-08-04)

Only the files needed to build, test, and later cross-compile ML-DSA-44 and
ML-KEM-512 with the portable reference C ("clean") implementations are vendored.
Nothing here is modified from upstream.

## Contents

| Path | From upstream | Purpose |
| --- | --- | --- |
| `common/fips202.{c,h}` | `common/` | Keccak / SHAKE, used by both schemes and by `src/kdf` |
| `common/aes.{c,h}` | `common/` | AES-256, used only by the NIST KAT DRBG |
| `common/randombytes.{c,h}` | `common/` | OS RNG, used by the functional tests |
| `common/compat.h` | `common/` | compiler-compat shim included by ML-KEM sources |
| `crypto_sign/ml-dsa-44/clean/` | same | ML-DSA-44 reference C (FIPS 204) |
| `crypto_kem/ml-kem-512/clean/` | same | ML-KEM-512 reference C (FIPS 203) |
| `crypto_{sign,kem}/*/META.yml` | same | records upstream source commits and the KAT hashes |
| `test/common/nistkatrng.c` | `test/common/` | AES-256-CTR-DRBG, the NIST KAT RNG |
| `test/crypto_sign/{nistkat,functest}.c` | `test/crypto_sign/` | KAT + functional test drivers |
| `test/crypto_kem/{nistkat,functest}.c` | `test/crypto_kem/` | KAT + functional test drivers |

Deliberately not vendored: AVX2 / aarch64 implementations, other schemes,
`sha2` / `sp800-185` / `nistseedexpander` (unused by these two clean
implementations), and the Python test framework.

## Licensing

PQClean is public domain (CC0); Keccak and AES carry the permissive notices in
their file headers. Each scheme directory keeps its upstream `LICENSE`.

## NIST KAT hashes

`test/test_nistkat.py` upstream checks the SHA-256 of the first NIST-format KAT
vector (the `nistkat` driver's stdout) against the scheme `META.yml`:

| Scheme | `nistkat-sha256` |
| --- | --- |
| ML-DSA-44 | `9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3` |
| ML-KEM-512 | `c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782` |

`tests/pqc/check-nistkat.sh` reproduces that check. Keep the two copies in sync
with `META.yml` on any pin bump.

## Updating the pin

1. Check out the new PQClean commit in a scratch clone.
2. Re-copy the paths in the table above.
3. Update the commit hash here and the `nistkat-sha256` values in
   `tests/pqc/check-nistkat.sh` from the new `META.yml`.
4. `make -C tests check` must pass.
