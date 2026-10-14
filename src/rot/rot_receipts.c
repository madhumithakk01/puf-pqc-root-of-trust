#include "rot/rot_receipts.h"

#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include <string.h>

static uint32_t sector_of(uint32_t seq)
{
    return ROT_DATA_SECTOR_OFF(ROT_SECTOR_RCP1_FIRST + (seq % ROT_RCP1_RING));
}

int rot_receipts_issue(const rot_platform *p, const rot_keys *k, rot_journal_t *j, rcp_t *r)
{
    uint8_t body[RCP_BODY_BYTES], obj[RCP_TOTAL_BYTES], digest[32];

    r->seq = j->receipt_seq + 1;
    r->device_id = k->device_id;
    memcpy(r->prev_digest, j->last_receipt_digest, 32);
    r->journal_seq = j->seq + 1;
    rcp_serialize(body, r);
    if (rcp_sign(body, k->sk_dsa, obj) != 0) {
        return ROT_RCPS_SIGN;
    }
    if (rot_flash_put(p, sector_of(r->seq), obj, sizeof obj) != 0) {
        return ROT_RCPS_IO;
    }
    rcp_chain_digest(obj, digest);
    j->receipt_seq = r->seq;
    memcpy(j->last_receipt_digest, digest, 32);
    return ROT_RCPS_OK;
}

int rot_receipts_read(const rot_platform *p, uint32_t seq, uint8_t obj[RCP_TOTAL_BYTES])
{
    if (seq == 0 || rot_flash_read(p, sector_of(seq), obj, RCP_TOTAL_BYTES) != 0) {
        return ROT_RCPS_IO;
    }
    if (memcmp(obj, "RCP1", 4) != 0 || rot_get32(obj + 4) != seq) {
        return ROT_RCPS_NONE;
    }
    return ROT_RCPS_OK;
}
