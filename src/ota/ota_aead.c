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

void ota_aead_stream_init(ota_aead_stream *s,
                          const uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                          const uint8_t nonce[OTA_AEAD_NONCE_BYTES])
{
    shake256_inc_init(&s->st);
    shake256_inc_absorb(&s->st, enc_key, OTA_AEAD_KEY_BYTES);
    shake256_inc_absorb(&s->st, nonce, OTA_AEAD_NONCE_BYTES);
    shake256_inc_finalize(&s->st);
}

void ota_aead_stream_xor(ota_aead_stream *s, uint8_t *buf, size_t len)
{
    uint8_t ks[136];
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > sizeof ks) {
            n = sizeof ks;
        }
        shake256_inc_squeeze(ks, n, &s->st);
        for (size_t i = 0; i < n; i++) {
            buf[off + i] ^= ks[i];
        }
        off += n;
    }
}

void ota_aead_stream_release(ota_aead_stream *s)
{
    shake256_inc_ctx_release(&s->st);
}

void ota_aead_xor(const uint8_t enc_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  uint8_t *buf, size_t len)
{
    ota_aead_stream s;
    ota_aead_stream_init(&s, enc_key, nonce);
    ota_aead_stream_xor(&s, buf, len);
    ota_aead_stream_release(&s);
}

void ota_aead_mac_init(ota_aead_mac_ctx *m,
                       const uint8_t mac_key[OTA_AEAD_KEY_BYTES],
                       const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                       uint64_t ct_len)
{
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) {
        lenbuf[i] = (uint8_t)(ct_len >> (8 * i));
    }
    shake256_inc_init(&m->st);
    shake256_inc_absorb(&m->st, mac_key, OTA_AEAD_KEY_BYTES);
    shake256_inc_absorb(&m->st, nonce, OTA_AEAD_NONCE_BYTES);
    shake256_inc_absorb(&m->st, lenbuf, sizeof lenbuf);
}

void ota_aead_mac_update(ota_aead_mac_ctx *m, const uint8_t *ct, size_t len)
{
    shake256_inc_absorb(&m->st, ct, len);
}

void ota_aead_mac_final(ota_aead_mac_ctx *m, uint8_t tag[OTA_AEAD_TAG_BYTES])
{
    shake256_inc_finalize(&m->st);
    shake256_inc_squeeze(tag, OTA_AEAD_TAG_BYTES, &m->st);
    shake256_inc_ctx_release(&m->st);
}

void ota_aead_mac(const uint8_t mac_key[OTA_AEAD_KEY_BYTES],
                  const uint8_t nonce[OTA_AEAD_NONCE_BYTES],
                  const uint8_t *ct, size_t ct_len,
                  uint8_t tag[OTA_AEAD_TAG_BYTES])
{
    ota_aead_mac_ctx m;
    ota_aead_mac_init(&m, mac_key, nonce, ct_len);
    ota_aead_mac_update(&m, ct, ct_len);
    ota_aead_mac_final(&m, tag);
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
