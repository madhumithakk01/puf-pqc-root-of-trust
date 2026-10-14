#ifndef ROT_HELPER_H
#define ROT_HELPER_H

#include "rot/rot_platform.h"
#include "rot/rot_keys.h"
#include "fuzzy/fuzzy_extractor.h"

/*
 * Public helper data (HLP1), rot_data sector 0.
 *
 *    0     4  "HLP1"
 *    4     2  version = 1
 *    6     2  flags (bit 0 STABLE_PAIRS, bit 1 SIM_PUF)
 *    8     4  window address
 *   12     4  window length (4096)
 *   16     2  blocks (256)
 *   18     2  rep (15)
 *   20     2  pairs selected (3840)
 *   22     2  pairs available at enrollment
 *   24     4  device_id
 *   28     4  T_off ms
 *   32    32  fingerprint of pk_dsa
 *   64    32  fingerprint of pk_kem
 *   96    32  reserved (0)
 *  128  2048  pair bitmap (bit i = pair i selected, LSB-first)
 * 2176   480  fuzzy helper P
 * 2656     4  CRC32 of [0:2656)
 *
 * Nothing here is secret. Tampering that changes the reconstructed key is
 * caught by the fingerprint comparison; the CRC only catches flash errors.
 */

#define ROT_HLP_WINDOW_BYTES 4096u
#define ROT_HLP_BITMAP_BYTES 2048u
#define ROT_HLP_PAIRS        3840u
#define ROT_HLP_W_BYTES      480u      /* 3840 bits */
#define ROT_HLP_BLOCKS       256u
#define ROT_HLP_REP          15u
#define ROT_HLP_BYTES        2660u

#define ROT_HLP_F_STABLE 0x0001u
#define ROT_HLP_F_SIM    0x0002u

typedef struct {
    uint16_t flags;
    uint32_t window_addr;
    uint16_t pairs_available;
    uint32_t device_id;
    uint32_t t_off_ms;
    uint8_t  fpr_dsa[32];
    uint8_t  fpr_kem[32];
    uint8_t  bitmap[ROT_HLP_BITMAP_BYTES];
    uint8_t  helper[ROT_HLP_W_BYTES];
} rot_hlp_t;

enum {
    ROT_HLP_OK = 0,
    ROT_HLP_ABSENT = -1,
    ROT_HLP_BAD = -2,
    ROT_HLP_IO = -3,
};

int rot_hlp_write(const rot_platform *p, const rot_hlp_t *h);
int rot_hlp_read(const rot_platform *p, rot_hlp_t *h);

typedef struct {
    unsigned bits_corrected;
    unsigned worst_block;
} rot_puf_stats;

/*
 * Reconstruct the 32-byte UDS from a fresh read of the key window.
 * Returns 0, or negative on a malformed record.
 */
int rot_puf_reconstruct(const uint8_t window[ROT_HLP_WINDOW_BYTES], const rot_hlp_t *h,
                        uint8_t uds[ROT_UDS_BYTES], rot_puf_stats *st);

#endif
