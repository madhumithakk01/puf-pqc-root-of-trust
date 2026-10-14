/*
 * Bench: cycles and retired instructions of each cryptographic operation on
 * the Hazard3 core, for comparison with the QEMU instruction counts.
 * Output: one JSON line per operation over USB.
 */

#include <stdio.h>
#include <string.h>

#include "hardware/clocks.h"
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"

#include "platform/rp2350/rp2350_platform.h"
#include "rot/rot_keys.h"
#include "rot/rot_rng.h"
#include "fips202.h"

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static rot_keys keys;
static uint8_t msg[1024], sig[ROT_DSA_SIG], ct[ROT_KEM_CT], ss[32], ss2[32], digest[32];

static uint64_t c0, i0;

static void begin(void) { c0 = rp2350_mcycle(); i0 = rp2350_minstret(); }

static void report(const char *name, unsigned reps)
{
    uint64_t c = rp2350_mcycle() - c0, i = rp2350_minstret() - i0;
    printf("{\"op\":\"%s\",\"cycles\":%llu,\"instret\":%llu,\"reps\":%u}\n", name,
           (unsigned long long)(c / reps), (unsigned long long)(i / reps), reps);
}

static void raw(void *ctx, uint8_t *b, size_t n) { (void)ctx; rp2350_trng_raw(b, n); }

int main(void)
{
    uint8_t uds[32];
    size_t slen = 0;

    stdio_init_all();
    for (int i = 0; i < 100 && !stdio_usb_connected(); i++) sleep_ms(20);
    rp2350_counters_enable();
    rot_rng_init(raw, NULL);
    for (int i = 0; i < 32; i++) uds[i] = (uint8_t)(i * 5 + 1);
    memset(msg, 0x5A, sizeof msg);

    for (;;) {
        printf("{\"bench\":\"start\",\"clk_hz\":%u}\n", (unsigned)clock_get_hz(clk_sys));

        begin(); shake256(digest, 32, msg, sizeof msg); report("shake256_1KB", 1);
        begin(); rot_keys_derive(uds, &keys); report("keys_derive(dsa+kem+kdf)", 1);
        begin(); PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &slen, msg, 64, keys.sk_dsa); report("mldsa44_sign", 1);
        begin(); PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, slen, msg, 64, keys.pk_dsa); report("mldsa44_verify", 1);
        begin(); PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, keys.pk_kem); report("mlkem512_encaps", 1);
        begin(); PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, keys.sk_kem); report("mlkem512_decaps", 1);
        printf("{\"bench\":\"done\",\"kem_agree\":%d}\n", memcmp(ss, ss2, 32) == 0);
        sleep_ms(5000);
    }
}
