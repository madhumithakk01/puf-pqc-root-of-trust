/* Server side: build a confidential OTA package. Not part of the device TCB. */

#include "ota/ota.h"
#include "ota/ota_aead.h"

#include "randombytes.h"
#include "api.h" /* PQCLEAN_MLKEM512_CLEAN_* */

#include <string.h>

int ota_pack(uint64_t fw_version,
             const uint8_t *body, size_t body_len,
             const uint8_t sign_sk[SB_SECKEY_BYTES],
             const uint8_t kem_pk[OTA_KEM_PK_BYTES],
             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!body || !sign_sk || !kem_pk || !out || !out_len) {
        return -1;
    }
    size_t signed_cap = 28u + body_len + SB_SIG_MAX_BYTES;
    if (signed_cap > OTA_BANK_BYTES) {
        return -2;
    }
    if (out_cap < OTA_OVERHEAD_BYTES + signed_cap) {
        return -2;
    }

    /* sign the firmware (Phase 6 container) directly into the package's
     * ciphertext slot, then encrypt it in place */
    uint8_t *ct = out + OTA_PREFIX_BYTES;
    size_t signed_len = 0;
    int rc = secure_boot_pack(fw_version, body, body_len, sign_sk,
                              ct, out_cap - OTA_PREFIX_BYTES, &signed_len);
    if (rc != 0) {
        return -3;
    }

    /* header */
    memset(out, 0, OTA_HDR_BYTES);
    out[0] = 'O';
    out[1] = 'T';
    out[2] = 'A';
    out[3] = '1';
    out[4] = 1;

    /* encapsulate to the device KEM key */
    uint8_t *kem_ct = out + OTA_HDR_BYTES;
    uint8_t ss[OTA_KEM_SS_BYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(kem_ct, ss, kem_pk) != 0) {
        return -4;
    }

    uint8_t *nonce = kem_ct + OTA_KEM_CT_BYTES;
    randombytes(nonce, OTA_NONCE_BYTES);

    uint8_t *lenp = nonce + OTA_NONCE_BYTES;
    for (int i = 0; i < 8; i++) {
        lenp[i] = (uint8_t)((uint64_t)signed_len >> (8 * i));
    }

    uint8_t enc_key[OTA_AEAD_KEY_BYTES], mac_key[OTA_AEAD_KEY_BYTES];
    ota_aead_derive_keys(ss, sizeof ss, enc_key, mac_key);

    ota_aead_xor(enc_key, nonce, ct, signed_len);
    ota_aead_mac(mac_key, nonce, ct, signed_len, ct + signed_len);

    *out_len = OTA_PREFIX_BYTES + signed_len + OTA_TAG_BYTES;
    return 0;
}
