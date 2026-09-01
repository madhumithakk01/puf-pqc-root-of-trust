/*
 * SHAKE256 known-answer test -- the XOF the KDF is built on.
 *
 * Vectors:
 *  - empty message, 512-bit output: the value published in NIST's FIPS 202
 *    SHAKE256 example.
 *  - empty message, 1088-bit output: exercises a multi-block squeeze;
 *    cross-checked against CPython's hashlib.shake_256.
 *  - 200 bytes of 0xA3, 512-bit output: the long-standing Keccak/FIPS 202
 *    test pattern.
 */

#include "fips202.h"

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

static void check(const char *name, const uint8_t *in, size_t inlen,
                  size_t outlen, const char *want)
{
    uint8_t out[200];
    char hex[2 * sizeof out + 1];

    shake256(out, outlen, in, inlen);
    to_hex(hex, out, outlen);
    if (strcmp(hex, want) != 0) {
        printf("  FAIL %s\n    want %s\n    got  %s\n", name, want, hex);
        failures++;
    } else {
        printf("  ok   %s\n", name);
    }
}

int main(void)
{
    uint8_t a3_200[200];
    uint8_t empty[1] = { 0 };
    memset(a3_200, 0xA3, sizeof a3_200);

    check("SHAKE256(\"\") / 64  (FIPS 202 example)", empty, 0, 64,
          "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

    check("SHAKE256(\"\") / 136 (multi-block squeeze)", empty, 0, 136,
          "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd");

    check("SHAKE256(200x 0xA3) / 64 (Keccak test pattern)", a3_200, sizeof a3_200,
          64,
          "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b");

    if (failures) {
        printf("shake256_kat: FAIL (%d)\n", failures);
        return 1;
    }
    printf("shake256_kat: PASS\n");
    return 0;
}
