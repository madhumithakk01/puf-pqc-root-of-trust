#include "rot/rot_helper.h"

#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include "puf/vn_debias.h"

#include <string.h>

#define OFF ROT_DATA_SECTOR_OFF(ROT_SECTOR_HLP1)

int rot_hlp_write(const rot_platform *p, const rot_hlp_t *h)
{
    uint8_t rec[ROT_HLP_BYTES];

    memset(rec, 0, sizeof rec);
    memcpy(rec, "HLP1", 4);
    rot_put16(rec + 4, 1);
    rot_put16(rec + 6, h->flags);
    rot_put32(rec + 8, h->window_addr);
    rot_put32(rec + 12, ROT_HLP_WINDOW_BYTES);
    rot_put16(rec + 16, ROT_HLP_BLOCKS);
    rot_put16(rec + 18, ROT_HLP_REP);
    rot_put16(rec + 20, ROT_HLP_PAIRS);
    rot_put16(rec + 22, h->pairs_available);
    rot_put32(rec + 24, h->device_id);
    rot_put32(rec + 28, h->t_off_ms);
    memcpy(rec + 32, h->fpr_dsa, 32);
    memcpy(rec + 64, h->fpr_kem, 32);
    memcpy(rec + 128, h->bitmap, ROT_HLP_BITMAP_BYTES);
    memcpy(rec + 2176, h->helper, ROT_HLP_W_BYTES);
    rot_put32(rec + 2656, rot_crc32(0, rec, 2656));
    return rot_flash_put(p, OFF, rec, sizeof rec) == 0 ? ROT_HLP_OK : ROT_HLP_IO;
}

int rot_hlp_read(const rot_platform *p, rot_hlp_t *h)
{
    uint8_t rec[ROT_HLP_BYTES];

    if (rot_flash_read(p, OFF, rec, sizeof rec) != 0) {
        return ROT_HLP_IO;
    }
    if (rot_all_byte(rec, sizeof rec, 0xFF)) {
        return ROT_HLP_ABSENT;
    }
    if (memcmp(rec, "HLP1", 4) != 0 || rot_get16(rec + 4) != 1
        || rot_get32(rec + 12) != ROT_HLP_WINDOW_BYTES || rot_get16(rec + 16) != ROT_HLP_BLOCKS
        || rot_get16(rec + 18) != ROT_HLP_REP || rot_get16(rec + 20) != ROT_HLP_PAIRS
        || rot_crc32(0, rec, 2656) != rot_get32(rec + 2656)) {
        return ROT_HLP_BAD;
    }
    h->flags = rot_get16(rec + 6);
    h->window_addr = rot_get32(rec + 8);
    h->pairs_available = rot_get16(rec + 22);
    h->device_id = rot_get32(rec + 24);
    h->t_off_ms = rot_get32(rec + 28);
    memcpy(h->fpr_dsa, rec + 32, 32);
    memcpy(h->fpr_kem, rec + 64, 32);
    memcpy(h->bitmap, rec + 128, ROT_HLP_BITMAP_BYTES);
    memcpy(h->helper, rec + 2176, ROT_HLP_W_BYTES);
    return ROT_HLP_OK;
}

int rot_puf_reconstruct(const uint8_t window[ROT_HLP_WINDOW_BYTES], const rot_hlp_t *h,
                        uint8_t uds[ROT_UDS_BYTES], rot_puf_stats *st)
{
    uint8_t w[ROT_HLP_W_BYTES];
    fuzzy_params fp = { ROT_HLP_BLOCKS, ROT_HLP_REP };
    fuzzy_stats fs;
    int rc;

    if (vn_extract(window, ROT_HLP_WINDOW_BYTES, h->bitmap, ROT_HLP_PAIRS, w) != 0) {
        return -1;
    }
    rc = fuzzy_rep_stats(fp, w, sizeof w, h->helper, sizeof h->helper, uds, ROT_UDS_BYTES, &fs);
    rot_wipe(w, sizeof w);
    if (rc != 0) {
        return -2;
    }
    if (st) {
        st->bits_corrected = fs.bits_corrected;
        st->worst_block = fs.worst_block;
    }
    return 0;
}
