/*
 * Tests for the simulated PUF.
 *
 * Known answers were produced independently with CPython's hashlib.shake_256
 * over the same domain-separated encoding.
 */

#include "puf/puf_sim.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void to_hex(char *dst, const uint8_t *b, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = digits[b[i] >> 4];
        dst[2 * i + 1] = digits[b[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

static void expect_hex(const char *name, const uint8_t *got, size_t n,
                       const char *want)
{
    char buf[2 * 128 + 1];
    to_hex(buf, got, n);
    if (strcmp(buf, want) != 0) {
        printf("  FAIL %s\n    want %s\n    got  %s\n", name, want, buf);
        failures++;
    } else {
        printf("  ok   %s\n", name);
    }
}

static void check(const char *name, int ok)
{
    if (ok) {
        printf("  ok   %s\n", name);
    } else {
        printf("  FAIL %s\n", name);
        failures++;
    }
}

int main(void)
{
    uint8_t a[64], b[64];

    /* 1. Clean response known answers. */
    puf_sim_response(0, a, 32);
    expect_hex("clean id=0 / 32", a, 32,
               "8ff838578677c714ecbd347cdb061a0ab4f1599c632d8956c68c863297f54a28");
    puf_sim_response(1, a, 32);
    expect_hex("clean id=1 / 32", a, 32,
               "e55c4eabaa144ad1f114c5ee04d9603ffddde5cd9bec468717fb68e10ee0deeb");
    puf_sim_response(42, a, 32);
    expect_hex("clean id=42 / 32", a, 32,
               "8a2572ebb545892e2c9fcb815260abdef9d19413b1eda2b3d36b0f3a0743f019");
    puf_sim_response(0, a, 64);
    expect_hex("clean id=0 / 64 (XOF prefix)", a, 64,
               "8ff838578677c714ecbd347cdb061a0ab4f1599c632d8956c68c863297f54a288d164bf80463ecc50382ba606262bf7381a494498353959d7a0df74b1f212d3d");

    /* 2. Deterministic: same id -> same bytes. */
    puf_sim_response(7, a, 64);
    puf_sim_response(7, b, 64);
    check("clean response is deterministic", memcmp(a, b, 64) == 0);

    /* 3. Inter-device uniqueness: distinct ids ~50 % apart. */
    {
        uint8_t r[16][64];
        for (uint32_t i = 0; i < 16; i++) {
            puf_sim_response(i, r[i], 64);
        }
        int ok = 1;
        size_t lo = 512, hi = 0;
        for (int i = 0; i < 16; i++) {
            for (int j = i + 1; j < 16; j++) {
                size_t d = puf_sim_hamming(r[i], r[j], 64); /* of 512 bits */
                if (d < lo) lo = d;
                if (d > hi) hi = d;
                if (d < 205 || d > 307) ok = 0;
            }
        }
        printf("       inter-device Hamming range: %zu..%zu / 512\n", lo, hi);
        check("all 120 id pairs within 40-60% Hamming", ok);
    }

    /* 4. Noise known answer + flip count. */
    {
        uint8_t clean[64], noisy[64];
        puf_sim_response(7, clean, 64);
        puf_sim_response_noisy(7, 100000u, (const uint8_t *)"seed-A", 6, noisy, 64);
        expect_hex("noisy id=7 ber=100000ppm seed=seed-A / 64", noisy, 64,
                   "08fe577e9232d62bf7158c6991c06471d750fd93bd62d0792bb36245b38959d441b86342b5f465ea5a64febe488995171ae4cd92369453031b35a776080d2801");
        check("that sample flipped 49 of 512 bits",
              puf_sim_hamming(clean, noisy, 64) == 49);
    }

    /* 5. ber_ppm == 0 returns the clean response. */
    {
        uint8_t clean[64], noisy[64];
        puf_sim_response(7, clean, 64);
        puf_sim_response_noisy(7, 0u, (const uint8_t *)"seed-A", 6, noisy, 64);
        check("ber_ppm=0 -> clean response", memcmp(clean, noisy, 64) == 0);
    }

    /* 6. Noise is reproducible and seed-dependent. */
    {
        uint8_t x[64], y[64], z[64];
        puf_sim_response_noisy(3, 50000u, (const uint8_t *)"A", 1, x, 64);
        puf_sim_response_noisy(3, 50000u, (const uint8_t *)"A", 1, y, 64);
        puf_sim_response_noisy(3, 50000u, (const uint8_t *)"B", 1, z, 64);
        check("same (id,ber,noise) -> identical", memcmp(x, y, 64) == 0);
        check("different noise seed -> different flips", memcmp(x, z, 64) != 0);
    }

    /* 7. Configurable BER is measurable: observed flip rate tracks the set
     *    rate over 128 power-ups x 512 bits = 65536 trials per point. */
    {
        static const uint32_t points[] = { 0u, 10000u, 50000u, 100000u, 200000u };
        const int M = 128;
        const size_t LEN = 64;
        int ok = 1;
        for (size_t p = 0; p < sizeof points / sizeof points[0]; p++) {
            uint8_t clean[64], noisy[64];
            puf_sim_response(9, clean, LEN);
            size_t flips = 0;
            for (int k = 0; k < M; k++) {
                uint8_t seed[4];
                seed[0] = (uint8_t)k; seed[1] = (uint8_t)(k >> 8);
                seed[2] = 0; seed[3] = 0;
                puf_sim_response_noisy(9, points[p], seed, sizeof seed, noisy, LEN);
                flips += puf_sim_hamming(clean, noisy, LEN);
            }
            double trials   = (double)M * (double)LEN * 8.0;
            double measured = (double)flips / trials;
            double target   = (double)points[p] / 1000000.0;
            double err      = measured - target;
            if (err < 0) err = -err;
            printf("       ber set=%.3f  measured=%.4f  (%zu/%.0f flips)\n",
                   target, measured, flips, trials);
            if (points[p] == 0u) {
                if (flips != 0) ok = 0;
            } else if (err > 0.006) {
                ok = 0;
            }
        }
        check("measured BER tracks configured BER (+/- 0.006)", ok);
    }

    if (failures) {
        printf("test_puf_sim: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_puf_sim: PASS\n");
    return 0;
}
