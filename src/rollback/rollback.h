#ifndef ROT_ROLLBACK_H
#define ROT_ROLLBACK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Rollback counter in simulated flash.
 *
 * A monotonic counter authenticated with a MAC keyed by a device secret (in
 * the full system, KDF(puf_key, "rollback-auth-key")). Stored twice, in A/B
 * pages, so a power loss during an update always leaves at least one complete,
 * authentic record to boot from.
 *
 * Page layout (ROLLBACK_PAGE_BYTES):
 *   [0:4]   magic "RBC1"
 *   [4:8]   seq   uint32 little-endian   (write order; newest valid page wins)
 *   [8:16]  cnt   uint64 little-endian   (the counter)
 *   [16:48] tag   = SHAKE256(key || "rollback/v1/tag" || magic||seq||cnt)
 *   [48:..] zero padding
 */

#define ROLLBACK_KEY_BYTES  32
#define ROLLBACK_TAG_BYTES  32
#define ROLLBACK_PAGE_BYTES 64

typedef struct {
    uint8_t page[2][ROLLBACK_PAGE_BYTES];
} rollback_store;

enum {
    ROLLBACK_OK                    = 0,
    ROLLBACK_ERR_ARG              = -1,
    ROLLBACK_ERR_NO_VALID_PAGE    = -2, /* neither page authenticates */
    ROLLBACK_ERR_TAMPER          = -3, /* a page carries the magic but a bad tag */
    ROLLBACK_ERR_MONOTONIC        = -4, /* update refused: counter not increasing */
    ROLLBACK_ERR_WRITE_INTERRUPTED = -5, /* simulated power loss during the write */
};

/*
 * Enrolment. Zeroes the store and writes page 0 with (seq=1, cnt). Not
 * power-loss safe by design -- there is no prior state to fall back to -- and
 * is expected to run once in a controlled setting.
 */
int rollback_enroll(rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES], uint64_t cnt);

/*
 * Boot path: return the authenticated counter from the newest MAC-valid page.
 * ROLLBACK_ERR_NO_VALID_PAGE if neither page authenticates.
 */
int rollback_read(const rollback_store *s,
                  const uint8_t key[ROLLBACK_KEY_BYTES], uint64_t *cnt);

/*
 * Like rollback_read, but returns ROLLBACK_ERR_TAMPER (still setting *cnt from
 * a good page if one exists) when a page carries the magic yet fails its MAC,
 * i.e. a record was modified in place. *tampered_pages, if non-NULL, gets a
 * bitmask of which page indices were tampered.
 */
int rollback_verify(const rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES],
                    uint64_t *cnt, unsigned *tampered_pages);

/*
 * Update the counter to new_cnt (must be strictly greater than the current
 * value). Writes the non-current page and bumps seq, so the current page stays
 * intact until the new one is fully written.
 *
 * fault_after_bytes == 0 performs a normal write. A value in [1, PAGE_BYTES)
 * simulates a power loss: only that many bytes are written, the rest of the
 * page is left erased (0xFF), and ROLLBACK_ERR_WRITE_INTERRUPTED is returned --
 * after which rollback_read still returns the pre-update counter.
 */
int rollback_update(rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES],
                    uint64_t new_cnt, size_t fault_after_bytes);

#endif /* ROT_ROLLBACK_H */
