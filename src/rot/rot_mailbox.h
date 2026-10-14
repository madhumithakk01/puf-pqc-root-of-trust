#ifndef ROT_MAILBOX_H
#define ROT_MAILBOX_H

#include "rot/rot_platform.h"

/*
 * Mailbox (MBX1) in rot_data sector 6. The application writes one request;
 * the RoT reads it on the next boot and erases it last. The content is
 * untrusted: the CRC only catches transport and flash errors.
 *
 *   0   4  "MBX1"
 *   4   4  seq
 *   8   1  type: 1 ATTEST_REQ, 2 INSTALL_REQ, 3 HEALTH_REPORT
 *   9   1  reserved (0)
 *  10   2  payload_len
 *  12   n  payload
 * 12+n  4  CRC32 over bytes [0 : 12+n)
 *
 * Payloads: ATTEST_REQ 32-byte verifier nonce; INSTALL_REQ u32 package
 * length + u32 package CRC32; HEALTH_REPORT the 32-byte HEV1.
 */

enum { MBX_NONE_TYPE = 0, MBX_ATTEST_REQ = 1, MBX_INSTALL_REQ = 2, MBX_HEALTH_REPORT = 3 };

#define ROT_MBX_MAX_PAYLOAD 64u
#define ROT_MBX_HDR 12u

typedef struct {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
    uint8_t  payload[ROT_MBX_MAX_PAYLOAD];
} rot_mbx_t;

enum {
    ROT_MBX_OK = 0,
    ROT_MBX_EMPTY = -1,  /* sector blank */
    ROT_MBX_BAD = -2,    /* CRC, length, type or magic wrong */
    ROT_MBX_IO = -3,
};

int rot_mailbox_read(const rot_platform *p, rot_mbx_t *m);
int rot_mailbox_erase(const rot_platform *p);

/* Serialize a request (application and test side). Returns the length written. */
size_t rot_mailbox_build(uint8_t *out, uint32_t seq, uint8_t type,
                         const uint8_t *payload, uint16_t len);

#endif
