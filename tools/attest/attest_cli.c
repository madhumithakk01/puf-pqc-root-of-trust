/*
 * Thin ML-DSA-44 CLI for the Python attestation server: keygen-det / sign /
 * verify, hex over stdin/stdout. Not part of the device firmware.
 *
 *   keygen-det   stdin: <seed_hex>            stdout: <pk_hex>\n<sk_hex>\n
 *   sign         stdin: <sk_hex>\n<msg_hex>   stdout: <sig_hex>\n
 *   verify       stdin: <pk_hex>\n<sig_hex>\n<msg_hex>   exit 0 ok / 2 bad
 */

#include "api.h"
#include "randombytes.h"
#include "fips202.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- deterministic RNG so keygen-det is reproducible --- */

static shake256incctx rng;
static int rng_seeded = 0;

static void rng_seed(const uint8_t *s, size_t n)
{
    if (rng_seeded) {
        shake256_inc_ctx_release(&rng);
    }
    shake256_inc_init(&rng);
    shake256_inc_absorb(&rng, s, n);
    shake256_inc_finalize(&rng);
    rng_seeded = 1;
}

int randombytes(uint8_t *out, size_t n)
{
    if (!rng_seeded) {
        rng_seed((const uint8_t *)"attest_cli/default", 18);
    }
    shake256_inc_squeeze(out, n, &rng);
    return 0;
}

/* --- hex --- */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static long hex_decode(const char *s, uint8_t *out, size_t out_cap)
{
    size_t n = 0;
    while (s[0] && s[1]) {
        int hi = hexval((unsigned char)s[0]);
        int lo = hexval((unsigned char)s[1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        if (n >= out_cap) {
            return -1;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    if (s[0]) {
        return -1; /* odd length */
    }
    return (long)n;
}

static void hex_print(const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar(d[b[i] >> 4]);
        putchar(d[b[i] & 15]);
    }
    putchar('\n');
}

/* read up to `want` newline-delimited hex lines from stdin */
static int read_lines(char lines[][8192], int want)
{
    static char buf[32768];
    size_t total = 0, r;
    while ((r = fread(buf + total, 1, sizeof buf - 1 - total, stdin)) > 0) {
        total += r;
        if (total >= sizeof buf - 1) {
            break;
        }
    }
    buf[total] = 0;

    int got = 0;
    char *p = buf;
    while (got < want) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        while (len && (p[len - 1] == '\r' || p[len - 1] == ' ')) {
            len--;
        }
        if (len >= 8192) {
            return -1;
        }
        memcpy(lines[got], p, len);
        lines[got][len] = 0;
        got++;
        if (!nl) {
            break;
        }
        p = nl + 1;
    }
    return got;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: attest_cli <keygen-det|sign|verify>\n");
        return 64;
    }
    static char lines[3][8192];

    if (strcmp(argv[1], "keygen-det") == 0) {
        if (read_lines(lines, 1) < 1) {
            return 65;
        }
        uint8_t seed[64];
        long sn = hex_decode(lines[0], seed, sizeof seed);
        if (sn <= 0) {
            return 65;
        }
        rng_seed(seed, (size_t)sn);
        uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
            return 70;
        }
        hex_print(pk, sizeof pk);
        hex_print(sk, sizeof sk);
        return 0;
    }

    if (strcmp(argv[1], "sign") == 0) {
        if (read_lines(lines, 2) < 2) {
            return 65;
        }
        uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
        uint8_t msg[4096];
        long skn = hex_decode(lines[0], sk, sizeof sk);
        long mn = hex_decode(lines[1], msg, sizeof msg);
        if (skn != (long)sizeof sk || mn < 0) {
            return 65;
        }
        uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
        size_t sl = 0;
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &sl, msg, (size_t)mn, sk) != 0) {
            return 70;
        }
        hex_print(sig, sl);
        return 0;
    }

    if (strcmp(argv[1], "verify") == 0) {
        if (read_lines(lines, 3) < 3) {
            return 65;
        }
        uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
        uint8_t msg[4096];
        long pkn = hex_decode(lines[0], pk, sizeof pk);
        long sn = hex_decode(lines[1], sig, sizeof sig);
        long mn = hex_decode(lines[2], msg, sizeof msg);
        if (pkn != (long)sizeof pk || sn <= 0 || mn < 0) {
            puts("bad");
            return 2;
        }
        int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, (size_t)sn, msg,
                                                          (size_t)mn, pk);
        puts(rc == 0 ? "ok" : "bad");
        return rc == 0 ? 0 : 2;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 64;
}
