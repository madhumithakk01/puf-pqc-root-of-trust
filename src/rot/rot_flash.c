#include "rot/rot_flash.h"

#include "rot/rot_util.h"

#include <string.h>

int rot_flash_read(const rot_platform *p, uint32_t off, uint8_t *buf, size_t n)
{
    if ((uint64_t)off + n > ROT_FLASH_TOTAL) {
        return ROT_E_RANGE;
    }
    return p->flash_read(p->ctx, off, buf, n);
}

int rot_flash_erase(const rot_platform *p, uint32_t off, size_t len)
{
    if ((off % ROT_FLASH_SECTOR) != 0 || (len % ROT_FLASH_SECTOR) != 0
        || (uint64_t)off + len > ROT_FLASH_TOTAL) {
        return ROT_E_RANGE;
    }
    return p->flash_erase(p->ctx, off, len);
}

int rot_flash_program(const rot_platform *p, uint32_t off, const uint8_t *data, size_t len)
{
    if ((uint64_t)off + len > ROT_FLASH_TOTAL) {
        return ROT_E_RANGE;
    }
    return p->flash_write(p->ctx, off, data, len);
}

int rot_flash_put(const rot_platform *p, uint32_t off, const uint8_t *data, size_t len)
{
    uint8_t page[ROT_FLASH_PAGE];
    int rc;

    if ((off % ROT_FLASH_SECTOR) != 0 || len > ROT_FLASH_SECTOR) {
        return ROT_E_RANGE;
    }
    rc = rot_flash_erase(p, off, ROT_FLASH_SECTOR);
    if (rc != 0) {
        return rc;
    }
    for (size_t done = 0; done < len; done += ROT_FLASH_PAGE) {
        size_t n = len - done < ROT_FLASH_PAGE ? len - done : ROT_FLASH_PAGE;
        memset(page, 0xFF, sizeof page);
        memcpy(page, data + done, n);
        rc = rot_flash_program(p, off + (uint32_t)done, page, ROT_FLASH_PAGE);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int rot_flash_sector_blank(const rot_platform *p, uint32_t off)
{
    uint8_t buf[256];
    for (uint32_t o = 0; o < ROT_FLASH_SECTOR; o += sizeof buf) {
        if (rot_flash_read(p, off + o, buf, sizeof buf) != 0 || !rot_all_byte(buf, sizeof buf, 0xFF)) {
            return 0;
        }
    }
    return 1;
}
