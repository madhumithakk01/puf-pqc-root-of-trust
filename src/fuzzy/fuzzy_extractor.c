#include "fuzzy/fuzzy_extractor.h"

#include "fips202.h"

#define EXTRACT_DOMAIN "fuzzy/v1/extract"

static unsigned bit_get(const uint8_t *buf, size_t i)
{
    return (buf[i >> 3] >> (i & 7u)) & 1u;
}

static void bit_set(uint8_t *buf, size_t i, unsigned v)
{
    uint8_t mask = (uint8_t)(1u << (i & 7u));
    if (v) {
        buf[i >> 3] |= mask;
    } else {
        buf[i >> 3] &= (uint8_t)~mask;
    }
}

static int params_ok(fuzzy_params p, size_t *n_bytes)
{
    if (p.rep == 0u || (p.rep & 1u) == 0u || p.blocks == 0u) {
        return 0;
    }
    uint64_t n = (uint64_t)p.blocks * p.rep;
    if ((n & 7u) != 0u || n / 8u > FUZZY_MAX_RESPONSE_BYTES) {
        return 0;
    }
    *n_bytes = (size_t)(n / 8u);
    return 1;
}

size_t fuzzy_response_bytes(fuzzy_params p)
{
    size_t n;
    return params_ok(p, &n) ? n : 0u;
}

static void extract(const uint8_t *w, size_t w_len, uint8_t *key, size_t key_len)
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)EXTRACT_DOMAIN,
                        sizeof EXTRACT_DOMAIN - 1);
    shake256_inc_absorb(&st, w, w_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(key, key_len, &st);
    shake256_inc_ctx_release(&st);
}

int fuzzy_gen(fuzzy_params p,
              const uint8_t *w, size_t w_len,
              const uint8_t *rnd, size_t rnd_len,
              uint8_t *helper, size_t helper_len,
              uint8_t *key, size_t key_len)
{
    size_t n_bytes;
    if (!params_ok(p, &n_bytes) || w_len != n_bytes || helper_len != n_bytes) {
        return -1;
    }
    if (rnd_len * 8u < p.blocks || key_len == 0u) {
        return -2;
    }

    for (unsigned b = 0; b < p.blocks; b++) {
        unsigned m = bit_get(rnd, b);
        for (unsigned j = 0; j < p.rep; j++) {
            size_t i = (size_t)b * p.rep + j;
            bit_set(helper, i, bit_get(w, i) ^ m); /* helper = w XOR codeword */
        }
    }

    extract(w, w_len, key, key_len);
    return 0;
}

int fuzzy_rep(fuzzy_params p,
              const uint8_t *w_noisy, size_t w_len,
              const uint8_t *helper, size_t helper_len,
              uint8_t *key, size_t key_len)
{
    size_t n_bytes;
    if (!params_ok(p, &n_bytes) || w_len != n_bytes || helper_len != n_bytes) {
        return -1;
    }
    if (key_len == 0u) {
        return -2;
    }

    uint8_t w_hat[FUZZY_MAX_RESPONSE_BYTES];
    for (size_t i = 0; i < n_bytes; i++) {
        w_hat[i] = 0;
    }

    for (unsigned b = 0; b < p.blocks; b++) {
        unsigned ones = 0;
        for (unsigned j = 0; j < p.rep; j++) {
            size_t i = (size_t)b * p.rep + j;
            ones += bit_get(w_noisy, i) ^ bit_get(helper, i); /* c' = w' XOR P */
        }
        unsigned m = (2u * ones > p.rep) ? 1u : 0u;           /* majority vote */
        for (unsigned j = 0; j < p.rep; j++) {
            size_t i = (size_t)b * p.rep + j;
            bit_set(w_hat, i, m ^ bit_get(helper, i));        /* w_hat = c_hat XOR P */
        }
    }

    extract(w_hat, n_bytes, key, key_len);
    return 0;
}
