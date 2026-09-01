#include "ota/ota_aead.h"

#include "kdf/kdf.h"
#include "fips202.h"

void ota_aead_derive_keys(const uint8_t *ss, size_t ss_len,
                          uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                          uint8_t mac_key[OTA_AEAD_KEY_BYTES])
{
    rot_kdf_derive(ss, ss_len, (const uint8_t *)"ota/v1/enc-key", 14,
                   enc_key, OTA_AEAD_KEY_BYTES);
    rot_kdf_derive(ss, ss_len, (const uint8_t *)"ota/v1/mac-key", 14,
                   mac_key, OTA_AEAD_KEY_BYTES);
}

void ota_aead_xor(const uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  uint8_t *buf, size_t len)
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, enc_key, OTA_AEAD_KEY_BYTES);
    shake256_inc_absorb(&st, nonce, OTA_AEAD_NONCE_BYTES);
    shake256_inc_finalize(&st);

    uint8_t ks[136];
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > sizeof ks) {
            n = sizeof ks;
        }
        shake256_inc_squeeze(ks, n, &st);
        for (size_t i = 0; i < n; i++) {
            buf[off + i] ^= ks[i];
        }
        off += n;
    }
    shake256_inc_ctx_release(&st);
}

void ota_aead_mac(const uint8_t mac_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  const uint8_t *ct, size_t ct_len,
                  uint8_t tag[OTA_AEAD_TAG_BYTES])
{
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) {
        lenbuf[i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
    }
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, mac_key, OTA_AEAD_KEY_BYTES);
    shake256_inc_absorb(&st, nonce, OTA_AEAD_NONCE_BYTES);
    shake256_inc_absorb(&st, lenbuf, sizeof lenbuf);
    shake256_inc_absorb(&st, ct, ct_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(tag, OTA_AEAD_TAG_BYTES, &st);
    shake256_inc_ctx_release(&st);
}

int ota_aead_tag_equal(const uint8_t a[OTA_AEAD_TAG_BYTES],
                       const uint8_t b[OTA_AEAD_TAG_BYTES])
{
    uint8_t d = 0;
    for (unsigned i = 0; i < OTA_AEAD_TAG_BYTES; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d == 0;
}
