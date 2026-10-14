#ifndef ROT_UTIL_H
#define ROT_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Little-endian accessors and small helpers shared by the RoT modules. */

static inline void rot_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void rot_put32(uint8_t *p, uint32_t v)
{
    rot_put16(p, (uint16_t)v);
    rot_put16(p + 2, (uint16_t)(v >> 16));
}

static inline void rot_put64(uint8_t *p, uint64_t v)
{
    rot_put32(p, (uint32_t)v);
    rot_put32(p + 4, (uint32_t)(v >> 32));
}

static inline uint16_t rot_get16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t rot_get32(const uint8_t *p)
{
    return (uint32_t)rot_get16(p) | ((uint32_t)rot_get16(p + 2) << 16);
}

static inline uint64_t rot_get64(const uint8_t *p)
{
    return (uint64_t)rot_get32(p) | ((uint64_t)rot_get32(p + 4) << 32);
}

/* Constant-time equality; 1 if equal. */
static inline int rot_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d == 0;
}

/* Zeroize in a way the compiler may not drop. */
static inline void rot_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

static inline int rot_all_byte(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] != v) {
            return 0;
        }
    }
    return 1;
}

#endif
