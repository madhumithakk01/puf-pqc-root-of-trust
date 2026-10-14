#include "dlv/dlv.h"

#include "fips202.h"
#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

#define DIGEST_LABEL "dlv/v1/ota"
#define CHUNK 512u

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

void dlv_ota_digest(const uint8_t *ota, size_t ota_len, uint8_t out[DLV_DIGEST_BYTES])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)DIGEST_LABEL, sizeof DIGEST_LABEL - 1);
    shake256_inc_absorb(&st, ota, ota_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, DLV_DIGEST_BYTES, &st);
    shake256_inc_ctx_release(&st);
}

static void serialize(uint8_t out[DLV_SIGNED_BYTES], const dlv_t *m)
{
    memset(out, 0, DLV_SIGNED_BYTES);
    memcpy(out, "DLV1", 4);
    put16(out + 4, 1);
    put32(out + 8, m->device_id);
    memcpy(out + 16, m->rot_nonce, DLV_NONCE_BYTES);
    put64(out + 48, m->svn);
    memcpy(out + 56, m->version, DLV_VERSION_LEN);
    put64(out + 72, m->ota_len);
    memcpy(out + 80, m->ota_digest, DLV_DIGEST_BYTES);
    put64(out + 112, m->issued_unix);
}

int dlv_pack(const dlv_t *m, const uint8_t sk[SB_SECKEY_BYTES],
             const uint8_t *ota, size_t ota_len,
             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!m || !sk || !ota || !out || !out_len || ota_len < DLV_MIN_OTA_BYTES) return -1;
    if (out_cap < DLV_PREFIX_BYTES + ota_len) return -2;

    dlv_t f = *m;
    f.ota_len = ota_len;
    dlv_ota_digest(ota, ota_len, f.ota_digest);
    serialize(out, &f);

    size_t sig_len = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(out + DLV_SIGNED_BYTES + 4, &sig_len,
                                                    out, DLV_SIGNED_BYTES, sk) != 0)
        return -3;
    if (sig_len != DLV_SIG_BYTES) return -3;
    put32(out + DLV_SIGNED_BYTES, (uint32_t)sig_len);
    memcpy(out + DLV_PREFIX_BYTES, ota, ota_len);
    *out_len = DLV_PREFIX_BYTES + ota_len;
    return 0;
}

dlv_status dlv_check(const uint8_t *p, size_t pkg_len,
                     const uint8_t vendor_pk[SB_PUBKEY_BYTES],
                     uint32_t my_device_id,
                     const uint8_t *outstanding_nonce,
                     uint64_t floor,
                     dlv_read_fn read, void *read_ctx,
                     dlv_t *out)
{
    /* structure and sizes */
    if (!p || !vendor_pk || !read || pkg_len < DLV_PREFIX_BYTES + DLV_MIN_OTA_BYTES)
        return DLV_E_MALFORMED;
    if (memcmp(p, "DLV1", 4) != 0 || get16(p + 4) != 1 || get16(p + 6) != 0
        || !all_zero(p + 12, 4) || !all_zero(p + 120, 8))
        return DLV_E_MALFORMED;
    if (get32(p + DLV_SIGNED_BYTES) != DLV_SIG_BYTES) return DLV_E_MALFORMED;
    uint64_t ota_len = get64(p + 72);
    if (ota_len < DLV_MIN_OTA_BYTES || ota_len != (uint64_t)pkg_len - DLV_PREFIX_BYTES)
        return DLV_E_MALFORMED;

    /* signature against the sealed vendor key */
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(p + DLV_SIGNED_BYTES + 4, DLV_SIG_BYTES,
                                                 p, DLV_SIGNED_BYTES, vendor_pk) != 0)
        return DLV_E_UNKNOWN_SIGNER;

    dlv_t m;
    m.device_id = get32(p + 8);
    memcpy(m.rot_nonce, p + 16, DLV_NONCE_BYTES);
    m.svn = get64(p + 48);
    memcpy(m.version, p + 56, DLV_VERSION_LEN);
    m.ota_len = ota_len;
    memcpy(m.ota_digest, p + 80, DLV_DIGEST_BYTES);
    m.issued_unix = get64(p + 112);
    if (out) *out = m;

    if (m.device_id != my_device_id) return DLV_E_WRONG_DEVICE;
    if (!outstanding_nonce || !ct_equal(m.rot_nonce, outstanding_nonce, DLV_NONCE_BYTES))
        return DLV_E_STALE_NONCE;
    if (m.svn < floor) return DLV_E_BELOW_FLOOR;

    /* digest of the OTA1 bytes, streamed */
    shake256incctx st;
    uint8_t buf[CHUNK], got[DLV_DIGEST_BYTES];
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)DIGEST_LABEL, sizeof DIGEST_LABEL - 1);
    for (uint64_t off = 0; off < ota_len;) {
        size_t n = ota_len - off < CHUNK ? (size_t)(ota_len - off) : CHUNK;
        if (read(read_ctx, off, buf, n) != 0) {
            shake256_inc_ctx_release(&st);
            return DLV_E_AUTH_FAILED;
        }
        shake256_inc_absorb(&st, buf, n);
        off += n;
    }
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(got, sizeof got, &st);
    shake256_inc_ctx_release(&st);
    return ct_equal(got, m.ota_digest, DLV_DIGEST_BYTES) ? DLV_OK : DLV_E_AUTH_FAILED;
}
