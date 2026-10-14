#include "rot/rot_anchor.h"

#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include "fips202.h"

#include <string.h>

#define OFF ROT_DATA_SECTOR_OFF(ROT_SECTOR_ANC1)

static void tag_of(const uint8_t key[32], const uint8_t *rec, uint8_t tag[32])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, key, 32);
    shake256_inc_absorb(&st, (const uint8_t *)"anchor/v1/tag", 13);
    shake256_inc_absorb(&st, rec, ROT_ANCHOR_TAG_OFF);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(tag, 32, &st);
    shake256_inc_ctx_release(&st);
}

int rot_anchor_seal(const rot_platform *p, const uint8_t anchor_key[32],
                    const uint8_t vendor_pk[ROT_ANCHOR_PK_BYTES])
{
    uint8_t rec[ROT_ANCHOR_BYTES];

    memset(rec, 0, sizeof rec);
    memcpy(rec, "ANC1", 4);
    rot_put16(rec + 4, 1);
    memcpy(rec + 8, vendor_pk, ROT_ANCHOR_PK_BYTES);
    tag_of(anchor_key, rec, rec + ROT_ANCHOR_TAG_OFF);
    return rot_flash_put(p, OFF, rec, sizeof rec);
}

int rot_anchor_open(const rot_platform *p, const uint8_t anchor_key[32],
                    uint8_t vendor_pk[ROT_ANCHOR_PK_BYTES])
{
    uint8_t rec[ROT_ANCHOR_BYTES], tag[32];

    if (rot_flash_read(p, OFF, rec, sizeof rec) != 0) {
        return ROT_ANCHOR_BAD;
    }
    if (rot_all_byte(rec, sizeof rec, 0xFF)) {
        return ROT_ANCHOR_ABSENT;
    }
    if (memcmp(rec, "ANC1", 4) != 0 || rot_get16(rec + 4) != 1 || rot_get16(rec + 6) != 0) {
        return ROT_ANCHOR_BAD;
    }
    tag_of(anchor_key, rec, tag);
    if (!rot_ct_equal(tag, rec + ROT_ANCHOR_TAG_OFF, 32)) {
        return ROT_ANCHOR_BAD;
    }
    memcpy(vendor_pk, rec + 8, ROT_ANCHOR_PK_BYTES);
    return ROT_ANCHOR_OK;
}
