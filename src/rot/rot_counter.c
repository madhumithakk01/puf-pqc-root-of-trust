#include "rot/rot_counter.h"

#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include <string.h>

static uint32_t sector_off(int page)
{
    return ROT_DATA_SECTOR_OFF(page ? ROT_SECTOR_RBC1_B : ROT_SECTOR_RBC1_A);
}

int rot_counter_load(const rot_platform *p, rollback_store *rb)
{
    memset(rb, 0, sizeof *rb);
    for (int i = 0; i < 2; i++) {
        uint8_t *pg = rb->page[i];
        if (rot_flash_read(p, sector_off(i), pg, ROLLBACK_PAGE_BYTES) != 0) {
            return ROT_CTR_IO;
        }
        /* interrupted program: magic present, final byte still erased */
        if (pg[ROLLBACK_PAGE_BYTES - 1] == 0xFF) {
            memset(pg, 0xFF, ROLLBACK_PAGE_BYTES);
        }
    }
    return ROT_CTR_OK;
}

int rot_counter_enroll(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                       uint64_t floor)
{
    rollback_store rb;
    int rc;

    if (rollback_enroll(&rb, key, floor) != ROLLBACK_OK) {
        return ROT_CTR_IO;
    }
    rc = rot_flash_put(p, sector_off(0), rb.page[0], ROLLBACK_PAGE_BYTES);
    if (rc == 0) {
        rc = rot_flash_erase(p, sector_off(1), ROT_FLASH_SECTOR);
    }
    return rc == 0 ? ROT_CTR_OK : ROT_CTR_IO;
}

int rot_counter_read(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                     uint64_t *floor)
{
    rollback_store rb;
    unsigned tampered = 0;
    int rc;

    if (rot_counter_load(p, &rb) != ROT_CTR_OK) {
        return ROT_CTR_IO;
    }
    rc = rollback_verify(&rb, key, floor, &tampered);
    if (rc == ROLLBACK_OK) {
        return ROT_CTR_OK;
    }
    return rc == ROLLBACK_ERR_TAMPER ? ROT_CTR_TAMPER : ROT_CTR_NONE;
}

int rot_counter_update(const rot_platform *p, const uint8_t key[ROLLBACK_KEY_BYTES],
                       uint64_t new_floor)
{
    rollback_store before, after;
    uint64_t cur;
    int rc, idx;

    rc = rot_counter_read(p, key, &cur);
    if (rc != ROT_CTR_OK) {
        return rc;
    }
    if (rot_counter_load(p, &before) != ROT_CTR_OK) {
        return ROT_CTR_IO;
    }
    after = before;
    rc = rollback_update(&after, key, new_floor, 0);
    if (rc == ROLLBACK_ERR_MONOTONIC) {
        return ROT_CTR_MONOTONIC;
    }
    if (rc != ROLLBACK_OK) {
        return ROT_CTR_IO;
    }
    idx = memcmp(before.page[0], after.page[0], ROLLBACK_PAGE_BYTES) != 0 ? 0 : 1;
    rc = rot_flash_put(p, sector_off(idx), after.page[idx], ROLLBACK_PAGE_BYTES);
    return rc == 0 ? ROT_CTR_OK : ROT_CTR_IO;
}
