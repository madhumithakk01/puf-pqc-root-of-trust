# PQC core

Post-quantum primitives wired through the vendored PQClean reference C, plus the
domain-separated KDF, all exercised by host tests.

## Primitives

| Primitive | Source | Sizes (bytes) |
| --- | --- | --- |
| ML-DSA-44 (FIPS 204) | `third_party/pqclean/crypto_sign/ml-dsa-44/clean` | pk 1312, sk 2560, sig 2420 |
| ML-KEM-512 (FIPS 203) | `third_party/pqclean/crypto_kem/ml-kem-512/clean` | pk 800, sk 1632, ct 768, ss 32 |
| SHAKE256 (FIPS 202) | `third_party/pqclean/common/fips202.c` | XOF |

Parameter sets match Phase 2's footprint spike. See
`third_party/pqclean/PROVENANCE.md` for the pin and vendoring scope.

## KDF

`src/kdf/kdf.{h,c}` -- one function:

```
out = SHAKE256(key || label), squeezed to out_len bytes
```

`label` selects an independent sub-key from one master `key`. It is used to
split the PUF-derived master key into the rollback-authentication key, the
signing identity, and the KEM identity, and later the OTA and attestation keys.

Properties (all in `tests/kdf/test_kdf.c`):

- **Reproducible** -- a given `(key, label)` always yields the same bytes.
- **XOF stream** -- a short request is a prefix of a longer one.
- **Label independence** -- distinct labels give outputs that are byte-distinct,
  share no 8-byte prefix, and differ in ~50% of bits (checked pairwise over five
  labels).
- **Key sensitivity** -- one flipped key bit changes the whole output.

**Encoding caveat.** `key || label` is not injective for a variable-length
`key`: `derive("AB", "C")` and `derive("A", "BC")` collide. Callers must fix one
side. The intended use fixes the key (a constant-length PUF-derived master),
leaving labels free-form. If a future caller needs variable-length keys, switch
to a length-prefixed encoding and re-pin the KDF known answers.

## Tests

```
make test               # from repo root
make -C tests check      # equivalent
make -C tests check-nistkat check-functest check-shake check-kdf   # individually
```

- **`check-nistkat`** -- builds the PQClean `nistkat` driver for each scheme
  (deterministic AES-256-CTR-DRBG per NIST's KAT procedure) and checks the
  SHA-256 of its output against the published `nistkat-sha256` in the scheme
  `META.yml`. This is the "passes official NIST KAT" check for ML-DSA-44 and
  ML-KEM-512. Expected hashes live in `tests/pqc/check-nistkat.sh`.
- **`check-functest`** -- PQClean's functional driver, 10 iterations: keygen /
  sign / verify (attached and detached) and keygen / encaps / decaps
  round-trips, plus wrong-key, invalid-secret-key, and invalid-ciphertext
  rejection and memory-canary checks.
- **`check-shake`** -- SHAKE256 against the FIPS 202 empty-message example, a
  multi-block squeeze of it, and the 200-byte `0xA3` Keccak test pattern.
- **`check-kdf`** -- the KDF properties above; known answers were produced
  independently with CPython's `hashlib.shake_256`.

All test C is built with PQClean's own strict flag set
(`-Wall -Wextra -Wpedantic -Wvla -Werror -Wshadow -Wcast-align ...`).
