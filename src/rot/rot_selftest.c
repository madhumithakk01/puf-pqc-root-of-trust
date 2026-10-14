#include "rot/rot_selftest.h"

#include "rot/rot_keys.h"
#include "rot/rot_selftest_vectors.h"
#include "rot/rot_util.h"

#include "fips202.h"

#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

uint32_t rot_selftest_run(uint64_t (*counter)(void), uint64_t cycles[5])
{
    static rot_keys k;
    static uint8_t sig[ROT_DSA_SIG];
    uint8_t d[32], ss[32];
    uint32_t bad = 0;
    uint64_t t = counter ? counter() : 0, t1;

#define LAP(i)                                \
    do {                                      \
        if (counter) {                        \
            t1 = counter();                   \
            if (cycles) cycles[i] = t1 - t;   \
            t = t1;                           \
        }                                     \
    } while (0)

    shake256(d, 32, (const uint8_t *)"abc", 3);
    if (!rot_ct_equal(d, st_shake_abc, 32)) bad |= ROT_ST_SHAKE;
    LAP(0);

    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(st_sig, sizeof st_sig, st_msg, ST_MSG_LEN, st_pk_dsa) != 0)
        bad |= ROT_ST_VERIFY;
    LAP(1);

    memcpy(sig, st_sig, sizeof sig);
    sig[100] ^= 1;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sizeof sig, st_msg, ST_MSG_LEN, st_pk_dsa) == 0)
        bad |= ROT_ST_REJECT;
    LAP(2);

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, st_ct, st_sk_kem);
    if (!rot_ct_equal(ss, st_ss, 32)) bad |= ROT_ST_DECAPS;
    LAP(3);

    if (rot_keys_derive(st_uds, &k) != 0 || !rot_ct_equal(k.fpr_dsa, st_fpr_dsa, 32)
        || !rot_ct_equal(k.fpr_kem, st_fpr_kem, 32))
        bad |= ROT_ST_KEYGEN;
    rot_keys_wipe(&k);
    LAP(4);
#undef LAP
    return bad;
}
