#include "rot/rot_journal.h"

#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include "fips202.h"

#include <string.h>

static uint32_t sector_off(int page)
{
    return ROT_DATA_SECTOR_OFF(page ? ROT_SECTOR_JNL1_B : ROT_SECTOR_JNL1_A);
}

static void tag_of(const uint8_t key[32], const uint8_t *rec, uint8_t tag[32])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, key, 32);
    shake256_inc_absorb(&st, (const uint8_t *)"journal/v1/tag", 14);
    shake256_inc_absorb(&st, rec, 96);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(tag, 32, &st);
    shake256_inc_ctx_release(&st);
}

void rot_journal_serialize(uint8_t out[ROT_JNL_BYTES], const rot_journal_t *j, const uint8_t key[32])
{
    memset(out, 0, ROT_JNL_BYTES);
    memcpy(out, "JNL1", 4);
    rot_put32(out + 4, j->seq);
    out[8] = j->active;
    out[9] = j->status[0];
    out[10] = j->status[1];
    out[11] = j->trial_state;
    out[12] = j->trial_slot;
    out[13] = j->nonce_state;
    rot_put64(out + 16, j->trial_svn);
    memcpy(out + 24, j->nonce, 32);
    rot_put32(out + 56, j->receipt_seq);
    memcpy(out + 64, j->last_receipt_digest, 32);
    tag_of(key, out, out + 96);
}

static int page_valid(const uint8_t key[32], const uint8_t *rec, rot_journal_t *j)
{
    uint8_t tag[32];

    if (memcmp(rec, "JNL1", 4) != 0) {
        return 0;
    }
    tag_of(key, rec, tag);
    if (!rot_ct_equal(tag, rec + 96, 32)) {
        return 0;
    }
    j->seq = rot_get32(rec + 4);
    j->active = rec[8];
    j->status[0] = rec[9];
    j->status[1] = rec[10];
    j->trial_state = rec[11];
    j->trial_slot = rec[12];
    j->nonce_state = rec[13];
    j->trial_svn = rot_get64(rec + 16);
    memcpy(j->nonce, rec + 24, 32);
    j->receipt_seq = rot_get32(rec + 56);
    memcpy(j->last_receipt_digest, rec + 64, 32);
    return 1;
}

static int fields_ok(const rot_journal_t *j)
{
    return j->active <= 1 && j->status[0] <= SLOT_REJECTED && j->status[1] <= SLOT_REJECTED
           && j->trial_state <= TRIAL_RUNNING && j->trial_slot <= 1
           && j->nonce_state <= NONCE_OUTSTANDING;
}

int rot_journal_enroll(const rot_platform *p, const uint8_t key[32], const rot_journal_t *init)
{
    uint8_t rec[ROT_JNL_BYTES];
    rot_journal_t j = *init;

    j.seq = 1;
    rot_journal_serialize(rec, &j, key);
    if (rot_flash_put(p, sector_off(0), rec, sizeof rec) != 0
        || rot_flash_erase(p, sector_off(1), ROT_FLASH_SECTOR) != 0) {
        return ROT_JNL_IO;
    }
    return ROT_JNL_OK;
}

int rot_journal_load(const rot_platform *p, const uint8_t key[32], rot_journal_t *j)
{
    int best = -1;
    rot_journal_t cand[2];

    for (int i = 0; i < 2; i++) {
        uint8_t rec[ROT_JNL_BYTES];
        if (rot_flash_read(p, sector_off(i), rec, sizeof rec) != 0) {
            return ROT_JNL_IO;
        }
        if (page_valid(key, rec, &cand[i]) && (best < 0 || cand[i].seq > cand[best].seq)) {
            best = i;
        }
    }
    if (best < 0) {
        return ROT_JNL_NONE;
    }
    *j = cand[best];
    j->page = best;
    return fields_ok(j) ? ROT_JNL_OK : ROT_JNL_BAD_FIELD;
}

int rot_journal_commit(const rot_platform *p, const uint8_t key[32], rot_journal_t *j)
{
    uint8_t rec[ROT_JNL_BYTES];
    int target = j->page ? 0 : 1;

    j->seq += 1;
    rot_journal_serialize(rec, j, key);
    if (rot_flash_put(p, sector_off(target), rec, sizeof rec) != 0) {
        j->seq -= 1;
        return ROT_JNL_IO;
    }
    j->page = target;
    return ROT_JNL_OK;
}
