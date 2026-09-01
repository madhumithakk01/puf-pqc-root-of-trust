#ifndef ROT_KDF_H
#define ROT_KDF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Domain-separated key derivation.
 *
 *   out = SHAKE256(key || label), squeezed to out_len bytes.
 *
 * `label` selects an independent sub-key from a single master `key`: a given
 * (key, label) pair always yields the same bytes, and distinct labels yield
 * outputs with no exploitable relation to one another. The output is an XOF
 * stream, so a short request is a prefix of a longer one for the same input.
 *
 * Encoding caveat: `key || label` is not injective when `key` is
 * variable-length -- rot_kdf_derive(k="AB", l="C") and
 * rot_kdf_derive(k="A", l="BC") collide. Callers MUST fix one side. The
 * intended use fixes the key: a PUF-derived master key of constant length,
 * with arbitrary distinct label strings.
 */
void rot_kdf_derive(const uint8_t *key, size_t key_len,
                    const uint8_t *label, size_t label_len,
                    uint8_t *out, size_t out_len);

#endif /* ROT_KDF_H */
