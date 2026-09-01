/* Server / test side: build a signed image. Not part of the device TCB. */

#include "secure_boot/secure_boot.h"

#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr_le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void wr_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

int secure_boot_pack(uint64_t fw_version,
                     const uint8_t *body, size_t body_len,
                     const uint8_t sk[SB_SECKEY_BYTES],
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!body || !sk || !out || !out_len) {
        return -1;
    }
    size_t auth_len = SB_AUTH_HDR_BYTES + body_len;
    if (out_cap < auth_len + 4u + SB_SIG_MAX_BYTES) {
        return -2;
    }

    memset(out, 0, SB_AUTH_HDR_BYTES);
    out[0] = SB_MAGIC0;
    out[1] = SB_MAGIC1;
    out[2] = SB_MAGIC2;
    out[3] = SB_MAGIC3;
    wr_le16(out + 4, 1u);
    wr_le64(out + 8, fw_version);
    wr_le64(out + 16, body_len);
    memcpy(out + SB_AUTH_HDR_BYTES, body, body_len);

    size_t sig_len = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(out + auth_len + 4u, &sig_len,
                                                    out, auth_len, sk) != 0) {
        return -3;
    }
    wr_le32(out + auth_len, (uint32_t)sig_len);
    *out_len = auth_len + 4u + sig_len;
    return 0;
}
