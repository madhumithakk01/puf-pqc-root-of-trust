/*
 * Tests for the repetition-code fuzzy extractor.
 *
 * The known-answer helper/key were produced independently in Python over the
 * same construction. The success-rate sweep drives the extractor with the
 * simulated PUF across the noise range and checks the empirical reproduction
 * rate against the analytic (1 - P_block)^blocks.
 */

#include "fuzzy/fuzzy_extractor.h"
#include "puf/puf_sim.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void to_hex(char *dst, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = d[b[i] >> 4];
        dst[2 * i + 1] = d[b[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

static void expect_hex(const char *name, const uint8_t *got, size_t n,
                       const char *want)
{
    char buf[2 * FUZZY_MAX_RESPONSE_BYTES + 1];
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

/* P(>= ceil(k/2) of k iid bits in error), per-bit error probability p */
static double p_block_fail(double p, unsigned k)
{
    /* binomial tail via a simple recurrence for C(k,j) */
    double q = 1.0 - p;
    double term = 1.0;
    for (unsigned i = 0; i < k; i++) {
        term *= q; /* C(k,0) p^0 q^k */
    }
    double cum = 0.0;
    unsigned t = (k + 1u) / 2u;
    for (unsigned j = 0; j <= k; j++) {
        if (j >= t) {
            cum += term;
        }
        /* term(j) -> term(j+1): * (k-j)/(j+1) * p/q */
        if (j < k) {
            term *= (double)(k - j) / (double)(j + 1u);
            term *= p / q;
        }
    }
    return cum;
}

int main(void)
{
    const fuzzy_params P15 = { .blocks = 128, .rep = 15 };
    const size_t N15 = fuzzy_response_bytes(P15); /* 240 */

    uint8_t w[FUZZY_MAX_RESPONSE_BYTES];
    uint8_t helper[FUZZY_MAX_RESPONSE_BYTES];
    uint8_t key[32], key2[32];
    uint8_t rnd[16];
    for (int i = 0; i < 16; i++) {
        rnd[i] = (uint8_t)i;
    }

    check("fuzzy_response_bytes({128,15}) == 240", N15 == 240);

    /* 1. Known answer: w from the simulated PUF, fixed rnd. */
    puf_sim_response(0, w, N15);
    check("fuzzy_gen ok", fuzzy_gen(P15, w, N15, rnd, sizeof rnd,
                                    helper, N15, key, sizeof key) == 0);
    expect_hex("helper KAT", helper, N15,
               "8ff838578677c714ecbd347cdb061af5cbf1599c632d8956c68c863297f54aa872294bf80463ecc50382ba60629d408cbea494498353959d7a0df74b1f212dfd7af3da3ce382d9271efb06ccb31452894e453f50d4bd413bb99b2d852d933b5583273fa14d080bc454b4c35bda6701cca3bbf16f213b0dc0e29d71e129ed102fa8319142a8941b04a62cfee8c8d7c088759857c18c389c83a551f0ab8bced7cd486e01ebc5c384ecde07da5e9f78d42a0369bd4ef5bb2da7333129c542dc5241217bd57bfae907982334866dd42c687e51a22f5221316d4a5272e3d9b2c8778e6bc3c146535be592af52503c46ce6a85");
    expect_hex("key KAT", key, sizeof key,
               "9288dde9fcd74de7b298f34c985716fb6f2c670b98dc9b46cedbfee7da3163df");

    /* 2. Reproduction with no noise. */
    check("fuzzy_rep ok",
          fuzzy_rep(P15, w, N15, helper, N15, key2, sizeof key2) == 0);
    check("Rep(w, P) == Gen key (no noise)", memcmp(key, key2, 32) == 0);

    /* 3. Correction capacity: rep=15 corrects 7 errors per block, not 8. */
    {
        uint8_t wn[FUZZY_MAX_RESPONSE_BYTES];
        memcpy(wn, w, N15);
        for (unsigned i = 0; i < 7; i++) {
            wn[i >> 3] ^= (uint8_t)(1u << (i & 7u)); /* 7 flips in block 0 */
        }
        fuzzy_rep(P15, wn, N15, helper, N15, key2, sizeof key2);
        check("7 errors in a block still reproduce the key",
              memcmp(key, key2, 32) == 0);

        wn[0] ^= (uint8_t)(1u << 7); /* an 8th flip in block 0 */
        fuzzy_rep(P15, wn, N15, helper, N15, key2, sizeof key2);
        check("8 errors in a block break that block (key differs)",
              memcmp(key, key2, 32) != 0);
    }

    /* 4. Parameter errors. */
    {
        fuzzy_params bad = { .blocks = 128, .rep = 8 }; /* even */
        check("even rep rejected", fuzzy_response_bytes(bad) == 0);
        check("wrong w_len rejected",
              fuzzy_gen(P15, w, N15 - 1, rnd, sizeof rnd,
                        helper, N15, key, sizeof key) < 0);
    }

    /* 5. Success rate across the noise range, vs the analytic model. */
    static const unsigned rep_set[] = { 5, 9, 15 };
    static const unsigned ber_pct[] = { 0, 1, 2, 5, 8, 10, 12, 15, 20, 25 };
    const int TRIALS = 200;

    for (size_t ri = 0; ri < sizeof rep_set / sizeof rep_set[0]; ri++) {
        fuzzy_params pr = { .blocks = 128, .rep = rep_set[ri] };
        size_t nb = fuzzy_response_bytes(pr);
        uint8_t cw[FUZZY_MAX_RESPONSE_BYTES];
        uint8_t ch[FUZZY_MAX_RESPONSE_BYTES];
        uint8_t ck[32], rk[32];

        puf_sim_response(5, cw, nb);
        fuzzy_gen(pr, cw, nb, rnd, sizeof rnd, ch, nb, ck, sizeof ck);

        printf("  rep=%2u (%zu B PUF)\n", pr.rep, nb);
        for (size_t bi = 0; bi < sizeof ber_pct / sizeof ber_pct[0]; bi++) {
            uint32_t ppm = ber_pct[bi] * 10000u;
            int ok = 0;
            uint8_t noisy[FUZZY_MAX_RESPONSE_BYTES];
            for (int t = 0; t < TRIALS; t++) {
                uint8_t seed[4] = { (uint8_t)t, (uint8_t)(t >> 8), 0, 0 };
                puf_sim_response_noisy(5, ppm, seed, sizeof seed, noisy, nb);
                fuzzy_rep(pr, noisy, nb, ch, nb, rk, sizeof rk);
                if (memcmp(ck, rk, 32) == 0) {
                    ok++;
                }
            }
            double emp = (double)ok / (double)TRIALS;
            double ana = 1.0;
            {
                double pblk = p_block_fail((double)ber_pct[bi] / 100.0, pr.rep);
                for (unsigned b = 0; b < pr.blocks; b++) {
                    ana *= (1.0 - pblk);
                }
            }
            double diff = emp - ana;
            if (diff < 0) {
                diff = -diff;
            }
            printf("     BER=%2u%%  empirical=%.3f  analytic=%.3f\n",
                   ber_pct[bi], emp, ana);
            if (diff > 0.08) {
                printf("       FAIL empirical vs analytic diff %.3f\n", diff);
                failures++;
            }
            if (pr.rep == 15) {
                if (ber_pct[bi] <= 8 && emp < 0.99) {
                    printf("       FAIL rep=15 BER<=8%% expected >=0.99\n");
                    failures++;
                }
                if (ber_pct[bi] <= 12 && emp < 0.90) {
                    printf("       FAIL rep=15 BER<=12%% expected >=0.90\n");
                    failures++;
                }
                if (ber_pct[bi] == 25 && emp > 0.30) {
                    printf("       FAIL rep=15 BER=25%% expected <=0.30\n");
                    failures++;
                }
            }
        }
    }

    if (failures) {
        printf("test_fuzzy: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_fuzzy: PASS\n");
    return 0;
}
