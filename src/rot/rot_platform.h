#ifndef ROT_PLATFORM_H
#define ROT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Everything the portable RoT core needs from the board.
 *
 * Flash offsets are relative to the start of flash. Erase works on whole
 * 4 KB sectors and leaves 0xFF; program clears bits only (a write can turn 1
 * into 0, never the reverse) and takes any length here, the RP2350
 * implementation pads to 256-byte pages. Every flash call returns 0 on
 * success and a negative value on failure, including a power cut in the
 * host model.
 */

#define ROT_E_FLASH   (-100)
#define ROT_E_RANGE   (-101)

typedef struct rot_platform {
    void *ctx;

    int (*flash_read)(void *ctx, uint32_t off, uint8_t *buf, size_t n);
    int (*flash_erase)(void *ctx, uint32_t off, size_t len);
    int (*flash_write)(void *ctx, uint32_t off, const uint8_t *buf, size_t n);

    /* Raw TRNG output, no conditioning. */
    void (*trng_raw)(void *ctx, uint8_t *buf, size_t n);

    /* Free-running cycle counter; may return 0 if unavailable. */
    uint64_t (*cycles)(void *ctx);

    /* Feed the watchdog; no-op when none is armed. */
    void (*wdt_feed)(void *ctx);
} rot_platform;

#endif
