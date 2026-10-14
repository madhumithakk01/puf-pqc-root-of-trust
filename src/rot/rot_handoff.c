#include "rot/rot_handoff.h"

#include "rot/rot_crc32.h"

#include <stddef.h>

void rot_handoff_seal(rot_handoff_t *h)
{
    h->magic = HND_MAGIC;
    h->version = HND_VERSION;
    h->size = (uint16_t)sizeof *h;
    h->crc = rot_crc32(0, (const uint8_t *)h, offsetof(rot_handoff_t, crc));
}

int rot_handoff_valid(const rot_handoff_t *h)
{
    return h->magic == HND_MAGIC && h->version == HND_VERSION && h->size == sizeof *h
           && h->crc == rot_crc32(0, (const uint8_t *)h, offsetof(rot_handoff_t, crc));
}
