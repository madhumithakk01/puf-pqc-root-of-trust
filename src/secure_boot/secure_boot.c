#include "secure_boot/secure_boot.h"

#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

static uint64_t rd_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static sb_decision finish(sb_result *out, sb_decision d,
                          uint64_t fw, uint64_t cnt, int rb_rc)
{
    if (out) {
        out->decision = d;
        out->fw_version = fw;
        out->counter = cnt;
        out->rollback_rc = rb_rc;
    }
    return d;
}

sb_decision secure_boot_check(const secure_boot_otp *otp,
                              const uint8_t *image, size_t image_len,
                              const rollback_store *rb,
                              const uint8_t rb_key[ROLLBACK_KEY_BYTES],
                              sb_result *out)
{
    if (!otp || !image || !rb || !rb_key) {
        return finish(out, SB_REFUSE_MALFORMED, 0, 0, 0);
    }

    /* 1. structural parse */
    if (image_len < SB_MIN_IMAGE_BYTES) {
        return finish(out, SB_REFUSE_MALFORMED, 0, 0, 0);
    }
    if (image[0] != SB_MAGIC0 || image[1] != SB_MAGIC1 ||
        image[2] != SB_MAGIC2 || image[3] != SB_MAGIC3) {
        return finish(out, SB_REFUSE_MALFORMED, 0, 0, 0);
    }
    uint32_t hdr_version = (uint32_t)image[4] | ((uint32_t)image[5] << 8);
    if (hdr_version != 1u) {
        return finish(out, SB_REFUSE_MALFORMED, 0, 0, 0);
    }
    uint64_t fw_version = rd_le64(image + 8);
    uint64_t body_len   = rd_le64(image + 16);

    /* guard the arithmetic before using body_len */
    if (body_len > image_len ||
        image_len < (uint64_t)SB_AUTH_HDR_BYTES + body_len + 4u) {
        return finish(out, SB_REFUSE_MALFORMED, fw_version, 0, 0);
    }
    size_t auth_len = SB_AUTH_HDR_BYTES + (size_t)body_len;
    uint32_t sig_len = rd_le32(image + auth_len);
    if (sig_len == 0u || sig_len > SB_SIG_MAX_BYTES ||
        image_len < auth_len + 4u + sig_len) {
        return finish(out, SB_REFUSE_MALFORMED, fw_version, 0, 0);
    }
    const uint8_t *sig = image + auth_len + 4u;

    /* 2. signature over image[0 : 24 + body_len] */
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, image, auth_len,
                                                 otp->vendor_pubkey) != 0) {
        return finish(out, SB_REFUSE_BAD_SIGNATURE, fw_version, 0, 0);
    }

    /* 3. rollback-counter integrity */
    uint64_t counter = 0;
    unsigned tampered = 0;
    int rb_rc = rollback_verify(rb, rb_key, &counter, &tampered);
    if (rb_rc != ROLLBACK_OK) {
        return finish(out, SB_REFUSE_COUNTER, fw_version, counter, rb_rc);
    }

    /* 4. anti-rollback */
    if (fw_version < counter) {
        return finish(out, SB_REFUSE_ROLLBACK, fw_version, counter, rb_rc);
    }

    return finish(out, SB_BOOT, fw_version, counter, rb_rc);
}
