#ifndef ROT_OTA_H
#define ROT_OTA_H

#include <stddef.h>
#include <stdint.h>

#include "secure_boot/secure_boot.h"
#include "rollback/rollback.h"

/*
 * Confidential OTA delivery.
 *
 * Server: sign the firmware (Phase 6 image), KEM-encapsulate a fresh secret to
 * the device's ML-KEM-512 public key, encrypt-then-MAC the signed image under
 * keys derived from that secret.
 *
 * Device: decapsulate, authenticate, decrypt, run secure_boot_check on the
 * recovered signed image, and stage it into the inactive A/B bank. A package
 * encrypted to a different device's key yields the wrong shared secret and
 * fails the MAC.
 *
 * Package container (little-endian):
 *   [0:4]                     magic "OTA1"
 *   [4:6]                     version = 1
 *   [6:8]                     reserved
 *   [8 : 8+768]               ML-KEM-512 ciphertext
 *   [.. : ..+24]              nonce
 *   [.. : ..+8]               payload_len (uint64)
 *   [.. : ..+payload_len]     ciphertext of the signed image
 *   [.. : ..+32]              tag
 */

#define OTA_KEM_PK_BYTES 800u
#define OTA_KEM_SK_BYTES 1632u
#define OTA_KEM_CT_BYTES 768u
#define OTA_KEM_SS_BYTES 32u

#define OTA_NONCE_BYTES 24u
#define OTA_TAG_BYTES   32u
#define OTA_HDR_BYTES   8u
#define OTA_PREFIX_BYTES (OTA_HDR_BYTES + OTA_KEM_CT_BYTES + OTA_NONCE_BYTES + 8u)
#define OTA_OVERHEAD_BYTES (OTA_PREFIX_BYTES + OTA_TAG_BYTES)

#define OTA_BANK_BYTES 8192u
#define OTA_BANK_NONE  0xffffffffu

typedef struct {
    uint8_t  bank[2][OTA_BANK_BYTES];
    uint32_t bank_len[2];
    uint32_t active;
    uint32_t pending; /* OTA_BANK_NONE when none staged */
} ota_flash;

typedef enum {
    OTA_OK                          = 0,
    OTA_ERR_ARG                     = -1,
    OTA_ERR_MALFORMED               = -2,
    OTA_ERR_AUTH                    = -3, /* wrong device key, or tampered package */
    OTA_ERR_REJECTED_BY_SECURE_BOOT = -4,
} ota_status;

typedef struct {
    ota_status  status;
    uint32_t    installed_bank;  /* set on OTA_OK */
    sb_decision sb_decision;     /* set on OTA_ERR_REJECTED_BY_SECURE_BOOT */
    sb_result   sb;
} ota_result;

/* Initialise the flash with an initial signed image in bank 0, active = 0. */
void ota_flash_init(ota_flash *f, const uint8_t *initial_image, size_t len);

/*
 * Process a package: decapsulate with kem_sk, authenticate, decrypt, run
 * secure_boot_check(otp, ., rb, rb_key), and on SB_BOOT stage the image into
 * the inactive bank (pending = that bank). Nothing is staged on any error.
 */
ota_status ota_install(ota_flash *f,
                       const uint8_t *pkg, size_t pkg_len,
                       const uint8_t kem_sk[OTA_KEM_SK_BYTES],
                       const secure_boot_otp *otp,
                       const rollback_store *rb,
                       const uint8_t rb_key[ROLLBACK_KEY_BYTES],
                       ota_result *out);

void ota_confirm(ota_flash *f); /* promote pending -> active */
void ota_reject(ota_flash *f);  /* drop pending, keep active */

const uint8_t *ota_active_image(const ota_flash *f, size_t *len);

/*
 * Server side: build a package into `out` (needs
 * OTA_OVERHEAD_BYTES + 28 + body_len + SB_SIG_MAX_BYTES). Returns 0 and
 * *out_len, or negative on a size error.
 */
int ota_pack(uint64_t fw_version,
             const uint8_t *body, size_t body_len,
             const uint8_t sign_sk[SB_SECKEY_BYTES],
             const uint8_t kem_pk[OTA_KEM_PK_BYTES],
             uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* ROT_OTA_H */
