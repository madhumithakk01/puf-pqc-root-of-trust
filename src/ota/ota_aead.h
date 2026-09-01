#ifndef ROT_OTA_AEAD_H
#define ROT_OTA_AEAD_H

/*
 * Internal: the SHAKE256 encrypt-then-MAC used by the OTA package.
 * Keys are derived from the ML-KEM shared secret with the project KDF.
 *
 *   enc_key = KDF(ss, "ota/v1/enc-key")
 *   mac_key = KDF(ss, "ota/v1/mac-key")
 *   ct      = pt XOR SHAKE256(enc_key || nonce)
 *   tag     = SHAKE256(mac_key || nonce || LE64(ct_len) || ct)
 */

#include <stddef.h>
#include <stdint.h>

#define OTA_AEAD_KEY_BYTES 32
#define OTA_AEAD_NONCE_BYTES 24
#define OTA_AEAD_TAG_BYTES 32

void ota_aead_derive_keys(const uint8_t *ss, size_t ss_len,
                          uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                          uint8_t mac_key[OTA_AEAD_KEY_BYTES]);

/* XOR `len` keystream bytes into `buf` in place (encrypt == decrypt). */
void ota_aead_xor(const uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  uint8_t *buf, size_t len);

void ota_aead_mac(const uint8_t mac_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  const uint8_t *ct, size_t ct_len,
                  uint8_t tag[OTA_AEAD_TAG_BYTES]);

/* constant-time; 1 if equal */
int ota_aead_tag_equal(const uint8_t a[OTA_AEAD_TAG_BYTES],
                       const uint8_t b[OTA_AEAD_TAG_BYTES]);

#endif /* ROT_OTA_AEAD_H */
