/*
 * Tests for the von Neumann debiasing module and the fuzzy decoder's
 * correction statistics: packing known answer, exact selection count, yield
 * on strongly biased simulated data, stable-pair restriction, and
 * bits-corrected equal to the number of injected errors within capacity.
 */

#include "puf/vn_debias.h"
#include "puf/puf_sim.h"
#include "fuzzy/fuzzy_extractor.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

#define WIN 4096u
#define WANT 3840u

static uint8_t ref[WIN], bitmap[WIN / 2], packed[WANT / 8];

static void test_kat(void)
{
    /* bits of 0x36 = 0b00110110: b0=0 b1=1 | b2=1 b3=0 | b4=1 b5=1 | b6=0 b7=0
     * pairs: (0,1) diff, (1,0) diff, (1,1) same, (0,0) same
     * 0xA5 = 0b10100101: b0=1 b1=0 | b2=1 b3=0 | b4=0 b5=1 | b6=0 b7=1
     * pairs: (1,0) diff, (1,0) diff, (0,1) diff, (0,1) diff */
    const uint8_t r[2] = {0x36, 0xA5};
    uint8_t bm[1] = {0xFF}, out[1];
    unsigned avail = 0;

    check("KAT: select 6 of 8 pairs",
          vn_select_pairs(r, 2, NULL, 6, bm, &avail) == 0 && avail == 6);
    /* usable pairs: 0, 1, 4, 5, 6, 7 -> bitmap 0b11110011 = 0xF3 */
    check("KAT: bitmap is 0xF3", bm[0] == 0xF3);
    /* first bits of those pairs: 0,1,1,1,0,0 -> LSB-first 0b001110 = 0x0E */
    check("KAT: extraction packs LSB-first (0x0E)",
          vn_extract(r, 2, bm, 6, out) == 0 && out[0] == 0x0E);
    check("select first 4 only",
          vn_select_pairs(r, 2, NULL, 4, bm, &avail) == 0 && avail == 6 && bm[0] == 0x33);
    check("extract rejects a bitmap with a different count",
          vn_extract(r, 2, bm, 5, out) == -1);
    check("too few pairs fails and reports availability",
          vn_select_pairs(r, 2, NULL, 7, bm, &avail) == -1 && avail == 6);

    const uint8_t a[1] = {0xE9}, b[1] = {0x6B}, c[1] = {0xFA};
    const uint8_t *reads[3] = {a, b, c};
    uint8_t maj[1], mask[1];
    /* per-bit majority of 0xE9,0x6B,0xFA: bit0 1,1,0->1; bit1 0,1,1->1; bit2 0,0,0->0;
       bit3 1,1,1->1; bit4 0,0,1->0; bit5 1,1,1->1; bit6 1,1,1->1; bit7 1,0,1->1 => 0xEB */
    check("majority of three reads (0xEB)", vn_majority(reads, 3, 1, maj) == 0 && maj[0] == 0xEB);
    /* stable where all agree: bits 2,3,5,6 */
    check("stable mask (0x6C)", vn_stable_mask(reads, 3, 1, mask) == 0 && mask[0] == 0x6C);
    check("even read count refused", vn_majority(reads, 2, 1, maj) == -1);
}

/* Strongly biased data: AND of two uniform streams has P(1) = 0.25. */
static void biased(uint32_t id, uint8_t *out)
{
    uint8_t x[WIN], y[WIN];
    puf_sim_response(id, x, WIN);
    puf_sim_response(id + 1000, y, WIN);
    for (unsigned i = 0; i < WIN; i++) out[i] = x[i] & y[i];
}

static void test_yield(void)
{
    unsigned avail = 0, ones = 0;
    biased(7, ref);
    for (unsigned i = 0; i < WIN; i++) ones += (unsigned)__builtin_popcount(ref[i]);
    check("biased data is biased (ones fraction < 30 %)", ones * 100u / (WIN * 8u) < 30u);
    check("select exactly 3840 pairs from biased data",
          vn_select_pairs(ref, WIN, NULL, WANT, bitmap, &avail) == 0);
    unsigned marked = 0;
    for (unsigned i = 0; i < WIN / 2; i++) marked += (unsigned)__builtin_popcount(bitmap[i]);
    check("bitmap marks exactly 3840", marked == WANT);
    check("yield above 3840 (available > 5000)", avail > 5000u);

    check("extract reproduces the reference's debiased bits",
          vn_extract(ref, WIN, bitmap, WANT, packed) == 0);
    /* every selected pair differs, so first bit XOR second bit == 1 */
    unsigned diffs = 0, j = 0;
    for (unsigned i = 0; i < WIN * 4u; i++) {
        if (!((bitmap[i >> 3] >> (i & 7)) & 1)) continue;
        unsigned b0 = (ref[(2 * i) >> 3] >> ((2 * i) & 7)) & 1;
        unsigned b1 = (ref[(2 * i + 1) >> 3] >> ((2 * i + 1) & 7)) & 1;
        unsigned o = (packed[j >> 3] >> (j & 7)) & 1;
        diffs += (b0 != b1) && (o == b0);
        j++;
    }
    check("every selected pair differs and the output is its first bit", diffs == WANT);

    /* debiased output is near-balanced even though the source is not */
    unsigned out_ones = 0;
    for (unsigned i = 0; i < WANT / 8; i++) out_ones += (unsigned)__builtin_popcount(packed[i]);
    check("debiased bits are roughly balanced (45-55 %)",
          out_ones * 100u / WANT >= 45u && out_ones * 100u / WANT <= 55u);
}

static void test_stable(void)
{
    uint8_t r1[WIN], r2[WIN], r3[WIN], mask[WIN], maj[WIN];
    const uint8_t *reads[3] = {r1, r2, r3};
    unsigned avail_all = 0, avail_stable = 0;

    biased(9, r1);
    memcpy(r2, r1, WIN);
    memcpy(r3, r1, WIN);
    for (unsigned i = 0; i < 40; i++) { r2[i * 50] ^= 0x01; r3[i * 50 + 7] ^= 0x10; }

    vn_majority(reads, 3, WIN, maj);
    vn_stable_mask(reads, 3, WIN, mask);
    vn_select_pairs(maj, WIN, NULL, 1, bitmap, &avail_all);
    vn_select_pairs(maj, WIN, mask, 1, bitmap, &avail_stable);
    check("majority removes single-read flips", memcmp(maj, r1, WIN) == 0);
    check("stable restriction removes pairs touching unstable bits",
          avail_stable < avail_all && avail_all - avail_stable <= 80u);
}

static void test_stats(void)
{
    fuzzy_params p = {256, 15};
    size_t n = fuzzy_response_bytes(p);
    uint8_t w[512], noisy[512], helper[512], rnd[32], k0[32], k1[32];
    fuzzy_stats st;

    puf_sim_response(3, w, n);
    for (unsigned i = 0; i < 32; i++) rnd[i] = (uint8_t)(i * 11 + 5);
    fuzzy_gen(p, w, n, rnd, 32, helper, n, k0, 32);

    /* inject e errors in block b: e <= 7 is within capacity */
    memcpy(noisy, w, n);
    check("no noise: zero corrected",
          fuzzy_rep_stats(p, noisy, n, helper, n, k1, 32, &st) == 0
          && st.bits_corrected == 0 && st.worst_block == 0 && memcmp(k0, k1, 32) == 0);

    memcpy(noisy, w, n);
    unsigned injected = 0;
    for (unsigned b = 0; b < 256; b += 3) {
        unsigned e = 1 + (b % 7); /* 1..7 */
        for (unsigned j = 0; j < e; j++) {
            size_t bit = (size_t)b * 15 + j * 2;
            noisy[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
        }
        injected += e;
    }
    check("bits corrected equals injected errors within capacity",
          fuzzy_rep_stats(p, noisy, n, helper, n, k1, 32, &st) == 0
          && st.bits_corrected == injected && memcmp(k0, k1, 32) == 0);
    check("worst block is the largest per-block count (7)", st.worst_block == 7);

    uint8_t k2[32];
    check("fuzzy_rep and fuzzy_rep_stats give the same key",
          fuzzy_rep(p, noisy, n, helper, n, k2, 32) == 0 && memcmp(k1, k2, 32) == 0);
    check("stats pointer may be NULL",
          fuzzy_rep_stats(p, noisy, n, helper, n, k2, 32, NULL) == 0);

    /* beyond capacity: 8 errors in one block flips the vote and the key */
    memcpy(noisy, w, n);
    for (unsigned j = 0; j < 8; j++) noisy[j / 8] ^= (uint8_t)(1u << (j & 7));
    fuzzy_rep_stats(p, noisy, n, helper, n, k2, 32, &st);
    check("8 errors in a block is beyond capacity (key differs)", memcmp(k0, k2, 32) != 0);
}

int main(void)
{
    test_kat();
    test_yield();
    test_stable();
    test_stats();
    if (failures) {
        printf("test_vn: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_vn: PASS\n");
    return 0;
}
