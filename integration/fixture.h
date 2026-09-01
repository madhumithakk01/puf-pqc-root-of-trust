#ifndef ROT_INTEGRATION_FIXTURE_H
#define ROT_INTEGRATION_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Provisioned data the boot image works against, emitted by gen_fixture as a
 * C array and linked in. Serialized layout (little-endian):
 *
 *   [0:4]    magic "ITG1"
 *   [4:8]    device_id
 *   [8:12]   ber_ppm         (PUF bit-error rate for this power-up)
 *   [12:16]  fuzzy_blocks
 *   [16:20]  fuzzy_rep
 *   [20:24]  helper_len
 *   [24:28]  fw_len
 *   [28:28+helper_len]        helper data
 *   [.. : ..+64]              rollback page 0
 *   [.. : ..+64]              rollback page 1
 *   [.. : ..+1312]            secure-boot OTP vendor public key
 *   [.. : ..+fw_len]          firmware image (SBI1 container)
 */

#define FIXTURE_RB_PAGE_BYTES 64u
#define FIXTURE_OTP_BYTES     1312u

extern const unsigned char fixture_blob[];
extern const unsigned int  fixture_blob_len;

uint32_t       fixture_device_id(void);
uint32_t       fixture_ber_ppm(void);
uint32_t       fixture_fuzzy_blocks(void);
uint32_t       fixture_fuzzy_rep(void);
size_t         fixture_helper_len(void);
const uint8_t *fixture_helper(void);
const uint8_t *fixture_rb_page0(void);
const uint8_t *fixture_rb_page1(void);
const uint8_t *fixture_otp(void);
size_t         fixture_fw_len(void);
const uint8_t *fixture_fw(void);

#endif /* ROT_INTEGRATION_FIXTURE_H */
