/*
 * Tests for rot_keys / rot_rng.
 *
 * The seeded key generation is checked against NIST ACVP-Server vectors
 * (ML-DSA-44 keyGen tcId 1, ML-KEM-512 keyGen tcId 1): the expected public
 * and secret keys are pinned by SHAKE256 digest, computed from the published
 * JSON with an independent tool. Plus determinism, label separation, the
 * exactly-32-bytes rule of the one-shot RNG, and TRNG conditioning.
 */

#include "rot/rot_keys.h"
#include "rot/rot_rng.h"

#include "fips202.h"
#include "randombytes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
                                                     const uint8_t *coins);

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int digest_is(const uint8_t *data, size_t len, const char *want_hex)
{
    uint8_t d[32], w[32];
    shake256(d, 32, data, len);
    unhex(want_hex, w, 32);
    return memcmp(d, w, 32) == 0;
}

static unsigned raw_calls;
static void raw_src(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx;
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(raw_calls * 31 + i * 7 + 1);
    raw_calls++;
}

static void test_acvp(void)
{
    uint8_t seed[32], pk[ROT_DSA_PK], sk[ROT_DSA_SK];
    unhex("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161", seed, 32);
    rot_rng_seed_once(seed, 32);
    check("ML-DSA-44 keygen consumes the 32-byte seed",
          PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0
          && !rot_rng_seed_pending() && !rot_rng_seed_error());
    check("ML-DSA-44 pk equals ACVP tcId 1",
          digest_is(pk, sizeof pk, "0db3223594a1fce8db48c8f1793611a17fcc0006ffea26cf7094d8325037288f"));
    check("ML-DSA-44 sk equals ACVP tcId 1",
          digest_is(sk, sizeof sk, "b2fce5a6c1c6a365206edc65522041459dbdcd23de698d5b8ba961043c1f1362"));
    rot_rng_reset();

    uint8_t coins[64], kpk[ROT_KEM_PK], ksk[ROT_KEM_SK];
    unhex("47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a", coins, 32);      /* d */
    unhex("1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9", coins + 32, 32); /* z */
    check("ML-KEM-512 keygen_derand(d||z)",
          PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(kpk, ksk, coins) == 0);
    check("ML-KEM-512 ek equals ACVP tcId 1",
          digest_is(kpk, sizeof kpk, "3bb95e3b62de52e36b7e277d3066aa2272a8f4f803aff95251bbf05dd3e7399c"));
    check("ML-KEM-512 dk equals ACVP tcId 1",
          digest_is(ksk, sizeof ksk, "fab7b5af01921972763bdc911d5cf5e1dffa946c92765198d9a9f78cdbdc3502"));
}

static void test_rng_rules(void)
{
    uint8_t seed[32], buf[64], pk[ROT_DSA_PK], sk[ROT_DSA_SK];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;

    rot_rng_seed_once(seed, 32);
    check("a request larger than the remaining seed fails and latches",
          randombytes(buf, 33) != 0 && rot_rng_seed_error());
    rot_rng_reset();

    rot_rng_seed_once(seed, 32);
    check("split requests consume the seed in order",
          randombytes(buf, 16) == 0 && rot_rng_seed_pending()
          && randombytes(buf + 16, 16) == 0 && !rot_rng_seed_pending()
          && memcmp(buf, seed, 32) == 0);
    rot_rng_reset();

    rot_rng_seed_once(seed, 16);
    check("keygen with a 16-byte seed is reported as an error",
          (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk), rot_rng_seed_error()));
    rot_rng_reset();

    uint8_t a[100], b[100];
    raw_calls = 0;
    check("conditioned bytes", rot_rng_bytes(a, sizeof a) == 0);
    check("each output block absorbs fresh raw bytes", raw_calls == 1);
    check("second call differs from the first", (rot_rng_bytes(b, sizeof b), memcmp(a, b, 100) != 0));
    raw_calls = 0;
    rot_rng_bytes(a, 300);
    check("300 bytes take three blocks (3 x 64 raw bytes)", raw_calls == 3);
    check("zero-length request is a no-op", rot_rng_bytes(a, 0) == 0);
}

static void test_derive(void)
{
    static rot_keys k1, k2, k3;
    uint8_t uds[32], uds2[32];
    for (int i = 0; i < 32; i++) { uds[i] = (uint8_t)(i * 3 + 1); uds2[i] = uds[i]; }
    uds2[31] ^= 1;

    check("derive succeeds", rot_keys_derive(uds, &k1) == 0);
    check("derive is deterministic", rot_keys_derive(uds, &k2) == 0 && memcmp(&k1, &k2, sizeof k1) == 0);
    check("another UDS gives different keys",
          rot_keys_derive(uds2, &k3) == 0 && memcmp(k1.pk_dsa, k3.pk_dsa, ROT_DSA_PK) != 0
          && memcmp(k1.pk_kem, k3.pk_kem, ROT_KEM_PK) != 0 && k1.device_id != k3.device_id);
    check("derivation does not depend on the TRNG state", (raw_calls = 99, rot_keys_derive(uds, &k3) == 0)
          && memcmp(&k1, &k3, sizeof k1) == 0);

    check("MAC keys are pairwise different",
          memcmp(k1.rb_key, k1.anchor_key, 32) != 0 && memcmp(k1.rb_key, k1.journal_key, 32) != 0
          && memcmp(k1.anchor_key, k1.journal_key, 32) != 0);
    check("no key equals the UDS", memcmp(k1.rb_key, uds, 32) != 0 && memcmp(k1.anchor_key, uds, 32) != 0);
    check("device_id is the first 4 bytes of the identity hash", k1.device_id == rot_device_id(k1.pk_dsa));
    {
        uint8_t f[32];
        rot_fingerprint(k1.pk_dsa, ROT_DSA_PK, f);
        check("fingerprints match", memcmp(f, k1.fpr_dsa, 32) == 0);
        rot_fingerprint(k1.pk_kem, ROT_KEM_PK, f);
        check("kem fingerprint matches", memcmp(f, k1.fpr_kem, 32) == 0);
        check("dsa and kem fingerprints differ", memcmp(k1.fpr_dsa, k1.fpr_kem, 32) != 0);
    }
    rot_keys_wipe(&k1);
    check("wipe zeroes the structure", k1.sk_dsa[0] == 0 && k1.sk_kem[100] == 0 && k1.rb_key[0] == 0);
}

int main(void)
{
    rot_rng_init(raw_src, NULL);
    test_acvp();
    test_rng_rules();
    test_derive();
    if (failures) {
        printf("test_keys: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_keys: PASS\n");
    return 0;
}
