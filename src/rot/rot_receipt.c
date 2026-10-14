#include "rot/rot_receipt.h"

#include "fips202.h"
#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

void rcp_serialize(uint8_t out[RCP_BODY_BYTES], const rcp_t *r)
{
    memset(out, 0, RCP_BODY_BYTES);
    memcpy(out, "RCP1", 4);
    put32(out + 4, r->seq);
    put32(out + 8, r->device_id);
    out[12] = r->outcome;
    out[13] = r->reason;
    out[14] = r->slot;
    put64(out + 16, r->from_svn);
    put64(out + 24, r->to_svn);
    put64(out + 32, r->floor_before);
    put64(out + 40, r->floor_after);
    memcpy(out + 48, r->image_digest, 32);
    memcpy(out + 80, r->package_digest, 32);
    memcpy(out + 112, r->rot_nonce, 32);
    memcpy(out + 144, r->evidence_digest, 32);
    memcpy(out + 176, r->prev_digest, 32);
    put32(out + 208, r->journal_seq);
    memcpy(out + 212, r->version, 16);
}

int rcp_parse(const uint8_t b[RCP_BODY_BYTES], rcp_t *r)
{
    if (memcmp(b, "RCP1", 4) != 0 || b[15] != 0) return -1;
    for (int i = 228; i < 256; i++) {
        if (b[i] != 0) return -1;
    }
    r->seq = get32(b + 4);
    r->device_id = get32(b + 8);
    r->outcome = b[12];
    r->reason = b[13];
    r->slot = b[14];
    r->from_svn = get64(b + 16);
    r->to_svn = get64(b + 24);
    r->floor_before = get64(b + 32);
    r->floor_after = get64(b + 40);
    memcpy(r->image_digest, b + 48, 32);
    memcpy(r->package_digest, b + 80, 32);
    memcpy(r->rot_nonce, b + 112, 32);
    memcpy(r->evidence_digest, b + 144, 32);
    memcpy(r->prev_digest, b + 176, 32);
    r->journal_seq = get32(b + 208);
    memcpy(r->version, b + 212, 16);
    return 0;
}

int rcp_sign(const uint8_t body[RCP_BODY_BYTES],
             const uint8_t sk[RCP_SECKEY_BYTES],
             uint8_t out[RCP_TOTAL_BYTES])
{
    size_t sig_len = 0;
    if (out != body) memmove(out, body, RCP_BODY_BYTES);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(out + RCP_BODY_BYTES + 4, &sig_len,
                                                    out, RCP_BODY_BYTES, sk) != 0
        || sig_len != RCP_SIG_BYTES)
        return -1;
    put32(out + RCP_BODY_BYTES, (uint32_t)sig_len);
    return 0;
}

int rcp_verify(const uint8_t *obj, size_t len, const uint8_t pk[RCP_PUBKEY_BYTES])
{
    if (len != RCP_TOTAL_BYTES || get32(obj + RCP_BODY_BYTES) != RCP_SIG_BYTES) return -1;
    if (memcmp(obj, "RCP1", 4) != 0) return -1;
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(obj + RCP_BODY_BYTES + 4, RCP_SIG_BYTES,
                                                    obj, RCP_BODY_BYTES, pk) == 0 ? 0 : -1;
}

void rcp_chain_digest(const uint8_t obj[RCP_TOTAL_BYTES], uint8_t out[32])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)"rcp/v1/chain", 12);
    shake256_inc_absorb(&st, obj, RCP_TOTAL_BYTES);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, 32, &st);
    shake256_inc_ctx_release(&st);
}

int rcp_verify_chain(const uint8_t *objs, size_t n,
                     const uint8_t pk[RCP_PUBKEY_BYTES],
                     const uint8_t first_prev[32])
{
    uint8_t expect_prev[32];
    uint32_t prev_seq = 0;
    memcpy(expect_prev, first_prev, 32);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *o = objs + i * RCP_TOTAL_BYTES;
        rcp_t r;
        if (rcp_verify(o, RCP_TOTAL_BYTES, pk) != 0 || rcp_parse(o, &r) != 0)
            return (int)i + 1;
        if (memcmp(r.prev_digest, expect_prev, 32) != 0) return (int)i + 1;
        if (i > 0 && r.seq != prev_seq + 1) return (int)i + 1;
        prev_seq = r.seq;
        rcp_chain_digest(o, expect_prev);
    }
    return 0;
}
