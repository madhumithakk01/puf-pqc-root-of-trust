#ifndef ROT_APM_H
#define ROT_APM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Signed application manifest (APM1).
 *
 * The first APM_BYTES of an SBI1 body. The application binary follows at
 * body offset APM_BYTES, which places it 4 KB after the start of the slot
 * (24-byte SBI1 header + 4072). The manifest is covered by the SBI1
 * signature; this module only checks its internal consistency.
 *
 * Layout (little-endian):
 *    0  4  "APM1"
 *    4  2  apm_version = 1
 *    6  2  flags (bit 0 HAS_SPO2)
 *    8 16  version string, NUL padded
 *   24  8  svn (equals the SBI1 fw_version)
 *   32  4  app_bin_offset = APM_BYTES
 *   36  4  app_bin_len
 *   40  2  golden_bpm_x10
 *   42  2  tol_bpm_x10
 *   44  2  golden_spo2_x10 (0xFFFF if none)
 *   46  2  tol_spo2_x10
 *   48  2  min_live_samples
 *   50  2  trial_deadline_ms (<= APM_MAX_DEADLINE_MS)
 *   52  4  reserved (0)
 *   56 32  golden trace digest
 *   88 20  build id
 *  108 3964 zero
 */

#define APM_BYTES            4072u
#define APM_VERSION          1u
#define APM_FLAG_HAS_SPO2    0x0001u
#define APM_SPO2_NONE        0xFFFFu
#define APM_VERSION_STR_LEN  16u
#define APM_MAX_DEADLINE_MS  15000u

typedef struct {
    uint16_t flags;
    char     version[APM_VERSION_STR_LEN]; /* NUL padded, not necessarily terminated */
    uint64_t svn;
    uint32_t app_bin_len;
    uint16_t golden_bpm_x10;
    uint16_t tol_bpm_x10;
    uint16_t golden_spo2_x10;
    uint16_t tol_spo2_x10;
    uint16_t min_live_samples;
    uint16_t trial_deadline_ms;
    uint8_t  golden_digest[32];
    uint8_t  build_id[20];
} apm_t;

typedef enum {
    APM_OK = 0,
    APM_E_SHORT,    /* body shorter than the manifest */
    APM_E_MAGIC,
    APM_E_VERSION,
    APM_E_OFFSET,   /* app_bin_offset != APM_BYTES */
    APM_E_LENGTH,   /* app_bin_len != body_len - APM_BYTES, or zero */
    APM_E_SVN,      /* svn != SBI1 fw_version */
    APM_E_FIELDS,   /* reserved/padding nonzero, deadline out of range, SpO2 flag inconsistent */
} apm_status;

/* Serialize into exactly APM_BYTES. Does not validate. */
void apm_build(uint8_t out[APM_BYTES], const apm_t *m);

/*
 * Parse and validate the manifest at the start of an SBI1 body.
 * `body_len` is the SBI1 body length, `sbi_fw_version` its header version.
 * The first failing check wins, in the order of apm_status.
 */
apm_status apm_parse(const uint8_t *body, size_t body_len,
                     uint64_t sbi_fw_version, apm_t *out);

#endif
