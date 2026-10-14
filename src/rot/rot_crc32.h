#ifndef ROT_CRC32_H
#define ROT_CRC32_H

#include <stddef.h>
#include <stdint.h>

/* CRC-32/IEEE 802.3 (zlib). Transport and mailbox integrity only; never a security check. */
uint32_t rot_crc32(uint32_t crc, const uint8_t *data, size_t len);

#endif
