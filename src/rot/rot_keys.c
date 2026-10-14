#include "rot/rot_keys.h"

#include "rot/rot_rng.h"
#include "rot/rot_util.h"

#include "kdf/kdf.h"
#include "fips202.h"

/* Both schemes ship an api.h, so the entry points are declared here. */
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
                                                     const uint8_t *coins);

#define LABEL(s) (const uint8_t *)(s), sizeof(s) - 1

uint32_t rot_device_id(const uint8_t pk_dsa[ROT_DSA_PK])
{
    uint8_t d[4];
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, LABEL("rot/v1/device-id"));
    shake256_inc_absorb(&st, pk_dsa, ROT_DSA_PK);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(d, sizeof d, &st);
    shake256_inc_ctx_release(&st);
    return rot_get32(d);
}

void rot_fingerprint(const uint8_t *pk, size_t pk_len, uint8_t out[ROT_FPR_BYTES])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, LABEL("rot/v1/fpr"));
    shake256_inc_absorb(&st, pk, pk_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, ROT_FPR_BYTES, &st);
    shake256_inc_ctx_release(&st);
}

int rot_keys_derive(const uint8_t uds[ROT_UDS_BYTES], rot_keys *k)
{
    uint8_t xi[32], coins[64];
    int rc = 0;

    rot_kdf_derive(uds, ROT_UDS_BYTES, LABEL("signing-identity"), xi, sizeof xi);
    rot_rng_seed_once(xi, sizeof xi);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(k->pk_dsa, k->sk_dsa) != 0
        || rot_rng_seed_pending() || rot_rng_seed_error()) {
        rc = -1; /* the seed must be consumed whole, in one call */
    }
    rot_rng_reset();

    rot_kdf_derive(uds, ROT_UDS_BYTES, LABEL("kem-identity"), coins, sizeof coins);
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(k->pk_kem, k->sk_kem, coins) != 0) {
        rc = -2;
    }

    rot_kdf_derive(uds, ROT_UDS_BYTES, LABEL("rollback-auth-key"), k->rb_key, sizeof k->rb_key);
    rot_kdf_derive(uds, ROT_UDS_BYTES, LABEL("anchor-seal-key"), k->anchor_key, sizeof k->anchor_key);
    rot_kdf_derive(uds, ROT_UDS_BYTES, LABEL("journal-auth-key"), k->journal_key, sizeof k->journal_key);

    k->device_id = rot_device_id(k->pk_dsa);
    rot_fingerprint(k->pk_dsa, ROT_DSA_PK, k->fpr_dsa);
    rot_fingerprint(k->pk_kem, ROT_KEM_PK, k->fpr_kem);

    rot_wipe(xi, sizeof xi);
    rot_wipe(coins, sizeof coins);
    return rc;
}

void rot_keys_wipe(rot_keys *k)
{
    rot_wipe(k, sizeof *k);
}
