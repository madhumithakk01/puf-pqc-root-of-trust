#ifndef ROT_DLV_H
#define ROT_DLV_H

#include <stddef.h>
#include <stdint.h>

#include "secure_boot/secure_boot.h"

/*
 * Delivery package (DLV1): a vendor-signed manifest in front of an OTA1
 * package. The device checks the manifest, in order, before it decapsulates
 * or decrypts anything.
 *
 * Layout (little-endian):
 *    0   4  "DLV1"
 *    4   2  version = 1
 *    6   2  flags = 0
 *    8   4  device_id
 *   12   4  reserved (0)
 *   16  32  rot_nonce
 *   48   8  svn
 *   56  16  version string
 *   72   8  ota_len
 *   80  32  ota_digest = SHAKE256("dlv/v1/ota" || OTA1 bytes)[0:32]
 *  112   8  issued_unix (informational)
 *  120   8  reserved (0)
 *  128   4  sig_len (= DLV_SIG_BYTES)
 *  132 2420 ML-DSA-44 signature over bytes [0:128)
 * 2552  ota_len  OTA1 package
 */

#define DLV_SIGNED_BYTES   128u
#define DLV_SIG_BYTES      SB_SIG_MAX_BYTES
#define DLV_PREFIX_BYTES   (DLV_SIGNED_BYTES + 4u + DLV_SIG_BYTES) /* 2552 */
#define DLV_NONCE_BYTES    32u
#define DLV_VERSION_LEN    16u
#define DLV_DIGEST_BYTES   32u
#define DLV_MIN_OTA_BYTES  1u

typedef struct {
    uint32_t device_id;
    uint8_t  rot_nonce[DLV_NONCE_BYTES];
    uint64_t svn;
    char     version[DLV_VERSION_LEN];
    uint64_t ota_len;
    uint8_t  ota_digest[DLV_DIGEST_BYTES];
    uint64_t issued_unix;
} dlv_t;

/* Values match the RCP1 reason codes. */
typedef enum {
    DLV_OK = 0,
    DLV_E_MALFORMED = 1,       /* PKG_MALFORMED */
    DLV_E_UNKNOWN_SIGNER = 2,  /* PKG_UNKNOWN_SIGNER */
    DLV_E_WRONG_DEVICE = 3,    /* PKG_WRONG_DEVICE */
    DLV_E_STALE_NONCE = 4,     /* PKG_STALE_NONCE */
    DLV_E_BELOW_FLOOR = 5,     /* PKG_BELOW_FLOOR */
    DLV_E_AUTH_FAILED = 6,     /* PKG_AUTH_FAILED (digest) */
} dlv_status;

/* H("dlv/v1/ota" || ota) */
void dlv_ota_digest(const uint8_t *ota, size_t ota_len,
                    uint8_t out[DLV_DIGEST_BYTES]);

/*
 * Vendor side: sign a manifest and append `ota`. The digest and ota_len
 * fields of `m` are computed here. Returns 0 and *out_len, or negative.
 */
int dlv_pack(const dlv_t *m, const uint8_t sk[SB_SECKEY_BYTES],
             const uint8_t *ota, size_t ota_len,
             uint8_t *out, size_t out_cap, size_t *out_len);

/* Reads `n` bytes of the OTA1 object starting at `off`. Returns 0 on success. */
typedef int (*dlv_read_fn)(void *ctx, uint64_t off, uint8_t *buf, size_t n);

/*
 * Device side. `prefix` holds the first DLV_PREFIX_BYTES of the package and
 * `pkg_len` is the full package length. `outstanding_nonce` is NULL when
 * the journal holds none. The first failing check wins, in this order:
 *   structure and sizes, signature against `vendor_pk`, device id, nonce,
 *   svn >= floor, digest of the OTA1 bytes read through `read`.
 * `out` is filled once the signature has verified.
 */
dlv_status dlv_check(const uint8_t *prefix, size_t pkg_len,
                     const uint8_t vendor_pk[SB_PUBKEY_BYTES],
                     uint32_t my_device_id,
                     const uint8_t *outstanding_nonce,
                     uint64_t floor,
                     dlv_read_fn read, void *read_ctx,
                     dlv_t *out);

#endif
