/*
 * Deterministic randombytes for tests that need reproducible key material:
 * a fixed-seed SHAKE256 stream. Link this instead of PQClean's
 * common/randombytes.c.
 */

#include "randombytes.h"

#include "fips202.h"

static shake256incctx drbg;
static int ready = 0;

int randombytes(uint8_t *output, size_t n)
{
    if (!ready) {
        static const uint8_t seed[] = "detrand-v1/secure-boot-and-friends";
        shake256_inc_init(&drbg);
        shake256_inc_absorb(&drbg, seed, sizeof seed - 1);
        shake256_inc_finalize(&drbg);
        ready = 1;
    }
    shake256_inc_squeeze(output, n, &drbg);
    return 0;
}
