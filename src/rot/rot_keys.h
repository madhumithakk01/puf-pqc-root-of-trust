#ifndef ROT_KEYS_H
#define ROT_KEYS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Key hierarchy derived from the 32-byte device secret (UDS).
 *
 *   signing-identity   32 B  ML-DSA-44 seed (FIPS 204 xi)
 *   kem-identity       64 B  ML-KEM-512 d || z (FIPS 203)
 *   rollback-auth-key  32 B  RBC1 MAC key
 *   anchor-seal-key    32 B  ANC1 tag key
 *   journal-auth-key   32 B  JNL1 tag key
 *
 * All labels go through rot_kdf_derive(uds, 32, label). Nothing derived here
 * is ever stored; the caller wipes the structure when done.
 */

#define ROT_UDS_BYTES   32u
#define ROT_DSA_PK      1312u
#define ROT_DSA_SK      2560u
#define ROT_DSA_SIG     2420u
#define ROT_KEM_PK      800u
#define ROT_KEM_SK      1632u
#define ROT_KEM_CT      768u
#define ROT_KEM_SS      32u
#define ROT_FPR_BYTES   32u

typedef struct {
    uint8_t  pk_dsa[ROT_DSA_PK];
    uint8_t  sk_dsa[ROT_DSA_SK];
    uint8_t  pk_kem[ROT_KEM_PK];
    uint8_t  sk_kem[ROT_KEM_SK];
    uint8_t  rb_key[32];
    uint8_t  anchor_key[32];
    uint8_t  journal_key[32];
    uint8_t  fpr_dsa[ROT_FPR_BYTES];
    uint8_t  fpr_kem[ROT_FPR_BYTES];
    uint32_t device_id;
} rot_keys;

/* Derive every key. Returns 0, or negative if key generation failed. */
int rot_keys_derive(const uint8_t uds[ROT_UDS_BYTES], rot_keys *k);

/* device_id = LE32(SHAKE256("rot/v1/device-id" || pk_dsa)[0:4]) */
uint32_t rot_device_id(const uint8_t pk_dsa[ROT_DSA_PK]);

/* SHAKE256("rot/v1/fpr" || pk)[0:32] */
void rot_fingerprint(const uint8_t *pk, size_t pk_len, uint8_t out[ROT_FPR_BYTES]);

void rot_keys_wipe(rot_keys *k);

#endif
