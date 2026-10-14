#include "rot/rot_rng.h"

#include "rot/rot_util.h"

#include "fips202.h"
#include "randombytes.h" /* declares randombytes (renamed by PQClean's macro) */

#include <string.h>

#define SEED_MAX 64u

static rot_rng_raw_fn raw_fn;
static void *raw_ctx;
static uint64_t counter;

static uint8_t seed[SEED_MAX];
static size_t seed_len;
static size_t seed_off;
static int seed_err;

void rot_rng_init(rot_rng_raw_fn raw, void *ctx)
{
    raw_fn = raw;
    raw_ctx = ctx;
    counter = 0;
}

int rot_rng_bytes(uint8_t *out, size_t n)
{
    if (!raw_fn) {
        return -1;
    }
    size_t off = 0;
    while (off < n) {
        uint8_t raw[ROT_RNG_RAW_ABSORB_BYTES], ctr[8], block[136];
        shake256incctx st;

        raw_fn(raw_ctx, raw, sizeof raw);
        rot_put64(ctr, counter++);
        shake256_inc_init(&st);
        shake256_inc_absorb(&st, (const uint8_t *)"rot/v1/trng", 11);
        shake256_inc_absorb(&st, ctr, sizeof ctr);
        shake256_inc_absorb(&st, raw, sizeof raw);
        shake256_inc_finalize(&st);
        shake256_inc_squeeze(block, sizeof block, &st);
        shake256_inc_ctx_release(&st);
        rot_wipe(raw, sizeof raw);

        size_t take = n - off < sizeof block ? n - off : sizeof block;
        memcpy(out + off, block, take);
        rot_wipe(block, sizeof block);
        off += take;
    }
    return 0;
}

void rot_rng_seed_once(const uint8_t *s, size_t n)
{
    rot_rng_reset();
    if (n > SEED_MAX) {
        seed_err = 1;
        return;
    }
    memcpy(seed, s, n);
    seed_len = n;
    seed_off = 0;
}

int rot_rng_seed_pending(void)
{
    return seed_off < seed_len;
}

int rot_rng_seed_error(void)
{
    return seed_err;
}

void rot_rng_reset(void)
{
    rot_wipe(seed, sizeof seed);
    seed_len = 0;
    seed_off = 0;
    seed_err = 0;
}

int randombytes(uint8_t *out, size_t n)
{
    if (rot_rng_seed_pending()) {
        if (n > seed_len - seed_off) {
            seed_err = 1;
            memset(out, 0, n);
            return -1;
        }
        memcpy(out, seed + seed_off, n);
        rot_wipe(seed + seed_off, n);
        seed_off += n;
        return 0;
    }
    return rot_rng_bytes(out, n);
}
