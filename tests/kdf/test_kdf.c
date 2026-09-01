/*
 * Tests for the domain-separated KDF.
 *
 * Known answers were produced independently with CPython's
 * hashlib.shake_256(key + label).hexdigest(n) -- a different SHAKE256
 * implementation from the one under test.
 */

#include "kdf/kdf.h"

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
    char buf[2 * 256 + 1];
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

static size_t hamming(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t bits = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t x = (uint8_t)(a[i] ^ b[i]);
        while (x) {
            bits += x & 1u;
            x = (uint8_t)(x >> 1);
        }
    }
    return bits;
}

int main(void)
{
    uint8_t K[32];
    for (int i = 0; i < 32; i++) {
        K[i] = (uint8_t)i;
    }

    uint8_t out[256];

    /* 1. Known answers vs. an independent SHAKE256. */
    rot_kdf_derive(K, sizeof K, (const uint8_t *)"rollback-auth-key", 17, out, 32);
    expect_hex("KAT rollback-auth-key / 32", out, 32,
               "47e18a271a132609ec729382734c5a76c5c85dfa81634b4b4740a4905467e52c");

    rot_kdf_derive(K, sizeof K, (const uint8_t *)"signing-identity", 16, out, 32);
    expect_hex("KAT signing-identity / 32", out, 32,
               "5cfeb1e62dcb573f805f73588fd586e489006f032dc5c60059116e0d298cbdc8");

    rot_kdf_derive(K, sizeof K, (const uint8_t *)"kem-identity", 12, out, 32);
    expect_hex("KAT kem-identity / 32", out, 32,
               "3f7f495b4d9f325e6354803462127e847a01c9149c105fb4d724b2980e359f51");

    rot_kdf_derive(K, sizeof K, (const uint8_t *)"", 0, out, 32);
    expect_hex("KAT empty label / 32", out, 32,
               "69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd3");

    rot_kdf_derive(K, sizeof K, (const uint8_t *)"signing-identity", 16, out, 64);
    expect_hex("KAT signing-identity / 64", out, 64,
               "5cfeb1e62dcb573f805f73588fd586e489006f032dc5c60059116e0d298cbdc869e177f9f1072b94f0f37f7b3989057312b6d5817625d1e3650da9bc9c144d7f");

    /* 2. XOF prefix property: a short output is a prefix of a longer one. */
    rot_kdf_derive(K, sizeof K, (const uint8_t *)"rollback-auth-key", 17, out, 200);
    expect_hex("KAT rollback-auth-key / 200 (multi-block)", out, 200,
               "47e18a271a132609ec729382734c5a76c5c85dfa81634b4b4740a4905467e52c232be88562cf23e93af1b0c29a35c4d83909a1b7278ffdfa551911ab3290ddde4359404038881816b934c3c0cea27a4a89b15c39a668890adeadb416224ec6058ff2f7dfa238f97548779ab9adbeb5a6953258770d5f3ead55b5d1199cefcb3f0a2395c09819f88c217fb2d4b9e994fb65bdd3c62facbf656845b7dea519c88b1fa77acd0283c71e61b84225a28fd38bedb103ba93d5e63a9dc8f52f4c20973ecd820de615a54d4f");

    /* 3. Reproducible: same (key, label) -> same bytes. */
    uint8_t a[64], b[64];
    rot_kdf_derive(K, sizeof K, (const uint8_t *)"signing-identity", 16, a, 64);
    rot_kdf_derive(K, sizeof K, (const uint8_t *)"signing-identity", 16, b, 64);
    check("reproducible across calls", memcmp(a, b, 64) == 0);

    /* 4. Label independence: distinct labels -> independent-looking outputs. */
    static const char *const labels[] = {
        "rollback-auth-key", "signing-identity", "kem-identity",
        "ota-delivery-key", "attestation-key",
    };
    enum { NLAB = (int)(sizeof labels / sizeof labels[0]) };
    uint8_t sub[NLAB][64];
    for (int i = 0; i < NLAB; i++) {
        rot_kdf_derive(K, sizeof K, (const uint8_t *)labels[i],
                       strlen(labels[i]), sub[i], 64);
    }
    for (int i = 0; i < NLAB; i++) {
        for (int j = i + 1; j < NLAB; j++) {
            char name[96];
            snprintf(name, sizeof name, "labels [%s] vs [%s] independent",
                     labels[i], labels[j]);
            int distinct  = memcmp(sub[i], sub[j], 64) != 0;
            int no_prefix = memcmp(sub[i], sub[j], 8) != 0;
            size_t d      = hamming(sub[i], sub[j], 64); /* of 512 bits */
            int balanced  = d >= 205 && d <= 307;        /* ~50% +/- 10% */
            check(name, distinct && no_prefix && balanced);
            if (!(distinct && no_prefix && balanced)) {
                printf("       (distinct=%d no_prefix=%d hamming=%zu/512)\n",
                       distinct, no_prefix, d);
            }
        }
    }

    /* 5. Key sensitivity: one flipped key bit changes the whole output. */
    uint8_t K2[32];
    memcpy(K2, K, 32);
    K2[0] ^= 0x01;
    uint8_t c[64];
    rot_kdf_derive(K2, sizeof K2, (const uint8_t *)"signing-identity", 16, c, 64);
    expect_hex("flipped-key KAT signing-identity / 64", c, 64,
               "6fc663b0982822b5a9c4439c342b9cc4f3827fe3506087472854a59fe0e393aa6e1dcaa733b70369202d452960b7ab89203a4147270a0fbbc34f4cfb40528ea8");
    {
        size_t d = hamming(a, c, 64);
        check("key sensitivity: output differs", memcmp(a, c, 64) != 0);
        check("key sensitivity: balanced diff", d >= 205 && d <= 307);
    }

    if (failures) {
        printf("test_kdf: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_kdf: PASS\n");
    return 0;
}
