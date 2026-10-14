/* Mailbox record builder: shared by the RoT tests and the application. No platform dependencies. */

#include "rot/rot_mailbox.h"

#include "rot/rot_crc32.h"
#include "rot/rot_util.h"

#include <string.h>

size_t rot_mailbox_build(uint8_t *out, uint32_t seq, uint8_t type,
                         const uint8_t *payload, uint16_t len)
{
    memcpy(out, "MBX1", 4);
    rot_put32(out + 4, seq);
    out[8] = type;
    out[9] = 0;
    rot_put16(out + 10, len);
    memcpy(out + ROT_MBX_HDR, payload, len);
    rot_put32(out + ROT_MBX_HDR + len, rot_crc32(0, out, ROT_MBX_HDR + len));
    return ROT_MBX_HDR + len + 4u;
}
