#include "rot/rot_mailbox.h"

#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_util.h"

#include <string.h>

#define OFF ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1)

static int len_ok(uint8_t type, uint16_t len)
{
    switch (type) {
    case MBX_ATTEST_REQ:    return len == 32;
    case MBX_INSTALL_REQ:   return len == 8;
    case MBX_HEALTH_REPORT: return len == 32;
    default:                return 0;
    }
}

int rot_mailbox_read(const rot_platform *p, rot_mbx_t *m)
{
    uint8_t rec[ROT_MBX_HDR + ROT_MBX_MAX_PAYLOAD + 4];
    uint16_t len;

    if (rot_flash_read(p, OFF, rec, sizeof rec) != 0) {
        return ROT_MBX_IO;
    }
    if (rot_all_byte(rec, sizeof rec, 0xFF)) {
        return ROT_MBX_EMPTY;
    }
    if (memcmp(rec, "MBX1", 4) != 0 || rec[9] != 0) {
        return ROT_MBX_BAD;
    }
    len = rot_get16(rec + 10);
    if (len > ROT_MBX_MAX_PAYLOAD || !len_ok(rec[8], len)) {
        return ROT_MBX_BAD;
    }
    if (rot_crc32(0, rec, ROT_MBX_HDR + len) != rot_get32(rec + ROT_MBX_HDR + len)) {
        return ROT_MBX_BAD;
    }
    m->seq = rot_get32(rec + 4);
    m->type = rec[8];
    m->len = len;
    memset(m->payload, 0, sizeof m->payload);
    memcpy(m->payload, rec + ROT_MBX_HDR, len);
    return ROT_MBX_OK;
}

int rot_mailbox_erase(const rot_platform *p)
{
    return rot_flash_erase(p, OFF, ROT_FLASH_SECTOR) == 0 ? ROT_MBX_OK : ROT_MBX_IO;
}
