#include "attest/attest2.h"

#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

void atr2_serialize(uint8_t out[ATR2_BODY_BYTES], const atr2_t *r)
{
    memset(out, 0, ATR2_BODY_BYTES);
    memcpy(out, "ATR2", 4);
    put32(out + 4, r->device_id);
    put64(out + 8, r->svn);
    put64(out + 16, r->floor);
    memcpy(out + 24, r->verifier_nonce, 32);
    memcpy(out + 56, r->rot_nonce, 32);
    memcpy(out + 88, r->image_digest, 32);
    out[120] = r->active_slot;
    out[121] = r->trial_state;
    out[122] = r->reset_cause;
    out[123] = r->flags;
    put32(out + 124, r->journal_seq);
    put32(out + 128, r->last_receipt_seq);
    put16(out + 132, r->bits_corrected);
    out[134] = r->worst_block;
    memcpy(out + 136, r->last_receipt_digest, 32);
    memcpy(out + 168, r->version, 16);
}

int atr2_parse(const uint8_t b[ATR2_BODY_BYTES], atr2_t *r)
{
    if (memcmp(b, "ATR2", 4) != 0 || b[135] != 0) return -1;
    for (int i = 184; i < 192; i++) {
        if (b[i] != 0) return -1;
    }
    r->device_id = get32(b + 4);
    r->svn = get64(b + 8);
    r->floor = get64(b + 16);
    memcpy(r->verifier_nonce, b + 24, 32);
    memcpy(r->rot_nonce, b + 56, 32);
    memcpy(r->image_digest, b + 88, 32);
    r->active_slot = b[120];
    r->trial_state = b[121];
    r->reset_cause = b[122];
    r->flags = b[123];
    r->journal_seq = get32(b + 124);
    r->last_receipt_seq = get32(b + 128);
    r->bits_corrected = get16(b + 132);
    r->worst_block = b[134];
    memcpy(r->last_receipt_digest, b + 136, 32);
    memcpy(r->version, b + 168, 16);
    return 0;
}

int atr2_sign(const uint8_t body[ATR2_BODY_BYTES],
              const uint8_t sk[ATR2_SECKEY_BYTES],
              uint8_t out[ATR2_TOTAL_BYTES])
{
    size_t sig_len = 0;
    if (out != body) memmove(out, body, ATR2_BODY_BYTES);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(out + ATR2_BODY_BYTES + 4, &sig_len,
                                                    out, ATR2_BODY_BYTES, sk) != 0
        || sig_len != ATR2_SIG_BYTES)
        return -1;
    put32(out + ATR2_BODY_BYTES, (uint32_t)sig_len);
    return 0;
}

int atr2_verify(const uint8_t *obj, size_t len, const uint8_t pk[ATR2_PUBKEY_BYTES])
{
    if (len != ATR2_TOTAL_BYTES || get32(obj + ATR2_BODY_BYTES) != ATR2_SIG_BYTES) return -1;
    if (memcmp(obj, "ATR2", 4) != 0) return -1;
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(obj + ATR2_BODY_BYTES + 4, ATR2_SIG_BYTES,
                                                    obj, ATR2_BODY_BYTES, pk) == 0 ? 0 : -1;
}
