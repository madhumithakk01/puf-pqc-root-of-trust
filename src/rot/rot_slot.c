#include "rot/rot_slot.h"

#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include "secure_boot/secure_boot.h"
#include "fips202.h"

#include <string.h>

int rot_slot_header_svn(const rot_platform *p, int slot, uint64_t *svn)
{
    const uint8_t *img = p->flash_xip(p->ctx, ROT_SLOT_OFF(slot));
    if (!img || memcmp(img, "SBI1", 4) != 0) {
        return -1;
    }
    *svn = rot_get64(img + 8);
    return 0;
}

int rot_slot_verify(const rot_ctx *c, int slot, rot_slot_info *info)
{
    const rot_platform *p = c->p;
    const uint8_t *img = p->flash_xip(p->ctx, ROT_SLOT_OFF(slot));
    secure_boot_otp otp;
    sb_result r;
    sb_decision d;
    apm_t apm;
    uint64_t body_len;
    shake256incctx st;

    if (!img) {
        return ROT_SLOT_IO;
    }
    memcpy(otp.vendor_pubkey, c->vendor_pk, SB_PUBKEY_BYTES);
    d = secure_boot_check(&otp, img, ROT_REGION_APP_A_SIZE, &c->rb, c->k->rb_key, &r);
    switch (d) {
    case SB_BOOT:                break;
    case SB_REFUSE_MALFORMED:    return RCP_REASON_IMG_MALFORMED;
    case SB_REFUSE_BAD_SIGNATURE: return RCP_REASON_IMG_BAD_SIGNATURE;
    case SB_REFUSE_COUNTER:      return ROT_SLOT_COUNTER;
    case SB_REFUSE_ROLLBACK:     return RCP_REASON_IMG_BELOW_FLOOR;
    default:                     return RCP_REASON_IMG_MALFORMED;
    }

    body_len = rot_get64(img + 16);
    switch (apm_parse(img + SB_AUTH_HDR_BYTES, (size_t)body_len, r.fw_version, &apm)) {
    case APM_OK:      break;
    case APM_E_SVN:   return RCP_REASON_IMG_SVN_MISMATCH;
    default:          return RCP_REASON_IMG_APM_INVALID;
    }

    if (info) {
        info->svn = r.fw_version;
        info->body_len = (uint32_t)body_len;
        info->apm = apm;
        shake256_inc_init(&st);
        shake256_inc_absorb(&st, (const uint8_t *)ROT_SBI_DIGEST_LABEL, sizeof ROT_SBI_DIGEST_LABEL - 1);
        shake256_inc_absorb(&st, img, SB_AUTH_HDR_BYTES + (size_t)body_len);
        shake256_inc_finalize(&st);
        shake256_inc_squeeze(info->digest, 32, &st);
        shake256_inc_ctx_release(&st);
    }
    return 0;
}
