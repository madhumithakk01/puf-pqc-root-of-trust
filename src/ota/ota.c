#include "ota/ota.h"
#include "ota/ota_aead.h"

#include "api.h" /* PQCLEAN_MLKEM512_CLEAN_* */

#include <string.h>

static uint64_t rd_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

void ota_flash_init(ota_flash *f, const uint8_t *initial_image, size_t len)
{
    memset(f, 0, sizeof *f);
    f->active = 0;
    f->pending = OTA_BANK_NONE;
    if (initial_image && len > 0 && len <= OTA_BANK_BYTES) {
        memcpy(f->bank[0], initial_image, len);
        f->bank_len[0] = (uint32_t)len;
    }
}

static ota_status finish(ota_result *out, ota_status s)
{
    if (out) {
        out->status = s;
    }
    return s;
}

ota_status ota_install(ota_flash *f,
                       const uint8_t *pkg, size_t pkg_len,
                       const uint8_t kem_sk[OTA_KEM_SK_BYTES],
                       const secure_boot_otp *otp,
                       const rollback_store *rb,
                       const uint8_t rb_key[ROLLBACK_KEY_BYTES],
                       ota_result *out)
{
    if (out) {
        memset(out, 0, sizeof *out);
    }
    if (!f || !pkg || !kem_sk || !otp || !rb || !rb_key) {
        return finish(out, OTA_ERR_ARG);
    }

    if (pkg_len < OTA_OVERHEAD_BYTES) {
        return finish(out, OTA_ERR_MALFORMED);
    }
    if (pkg[0] != 'O' || pkg[1] != 'T' || pkg[2] != 'A' || pkg[3] != '1') {
        return finish(out, OTA_ERR_MALFORMED);
    }
    uint32_t version = (uint32_t)pkg[4] | ((uint32_t)pkg[5] << 8);
    if (version != 1u) {
        return finish(out, OTA_ERR_MALFORMED);
    }

    const uint8_t *kem_ct = pkg + OTA_HDR_BYTES;
    const uint8_t *nonce  = kem_ct + OTA_KEM_CT_BYTES;
    uint64_t payload_len  = rd_le64(nonce + OTA_NONCE_BYTES);

    if (payload_len > OTA_BANK_BYTES ||
        pkg_len != OTA_PREFIX_BYTES + payload_len + OTA_TAG_BYTES) {
        return finish(out, OTA_ERR_MALFORMED);
    }
    const uint8_t *ct  = pkg + OTA_PREFIX_BYTES;
    const uint8_t *tag = ct + payload_len;

    /* decapsulate: a package for another device yields a different ss */
    uint8_t ss[OTA_KEM_SS_BYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, kem_ct, kem_sk) != 0) {
        return finish(out, OTA_ERR_AUTH);
    }

    uint8_t enc_key[OTA_AEAD_KEY_BYTES], mac_key[OTA_AEAD_KEY_BYTES];
    ota_aead_derive_keys(ss, sizeof ss, enc_key, mac_key);

    uint8_t want_tag[OTA_AEAD_TAG_BYTES];
    ota_aead_mac(mac_key, nonce, ct, (size_t)payload_len, want_tag);
    if (!ota_aead_tag_equal(want_tag, tag)) {
        return finish(out, OTA_ERR_AUTH);
    }

    /* authenticated: decrypt straight into the inactive bank */
    uint32_t target = 1u - f->active;
    memcpy(f->bank[target], ct, (size_t)payload_len);
    ota_aead_xor(enc_key, nonce, f->bank[target], (size_t)payload_len);

    sb_result sbr;
    sb_decision d = secure_boot_check(otp, f->bank[target], (size_t)payload_len,
                                      rb, rb_key, &sbr);
    if (d != SB_BOOT) {
        memset(f->bank[target], 0, OTA_BANK_BYTES);
        f->bank_len[target] = 0;
        if (out) {
            out->status = OTA_ERR_REJECTED_BY_SECURE_BOOT;
            out->sb_decision = d;
            out->sb = sbr;
        }
        return OTA_ERR_REJECTED_BY_SECURE_BOOT;
    }

    f->bank_len[target] = (uint32_t)payload_len;
    f->pending = target;
    if (out) {
        out->status = OTA_OK;
        out->installed_bank = target;
        out->sb_decision = d;
        out->sb = sbr;
    }
    return OTA_OK;
}

void ota_confirm(ota_flash *f)
{
    if (f && f->pending != OTA_BANK_NONE) {
        f->active = f->pending;
        f->pending = OTA_BANK_NONE;
    }
}

void ota_reject(ota_flash *f)
{
    if (f && f->pending != OTA_BANK_NONE) {
        memset(f->bank[f->pending], 0, OTA_BANK_BYTES);
        f->bank_len[f->pending] = 0;
        f->pending = OTA_BANK_NONE;
    }
}

const uint8_t *ota_active_image(const ota_flash *f, size_t *len)
{
    if (!f) {
        if (len) *len = 0;
        return NULL;
    }
    if (len) {
        *len = f->bank_len[f->active];
    }
    return f->bank[f->active];
}
