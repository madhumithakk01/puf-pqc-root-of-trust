/*
 * Device-side attestation tests: report serialization matches the bytes the
 * Python server pins, and sign/verify round-trips with tamper rejection.
 * Deterministic keys via tests/common/detrand.c.
 */

#include "attest/attest.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

static int failures = 0;

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
    uint8_t nonce[ATTEST_NONCE_BYTES];
    for (int i = 0; i < (int)sizeof nonce; i++) {
        nonce[i] = (uint8_t)i;
    }

    uint8_t report[ATTEST_REPORT_BYTES];
    attest_report_serialize(1, 3, 2, nonce, report);

    char hex[2 * ATTEST_REPORT_BYTES + 1];
    for (unsigned i = 0; i < ATTEST_REPORT_BYTES; i++) {
        static const char d[] = "0123456789abcdef";
        hex[2 * i] = d[report[i] >> 4];
        hex[2 * i + 1] = d[report[i] & 15];
    }
    hex[2 * ATTEST_REPORT_BYTES] = 0;
    check("report serialization matches the pinned bytes",
          strcmp(hex,
                 "415452310100000003000000000000000200000000000000"
                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") == 0);

    uint8_t pk[ATTEST_PUBKEY_BYTES], sk[ATTEST_SECKEY_BYTES];
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);

    uint8_t sig[ATTEST_SIG_MAX_BYTES];
    size_t sig_len = 0;
    check("sign ok",
          attest_report_sign(report, sk, sig, sizeof sig, &sig_len) == 0 && sig_len > 0);
    check("verify accepts a genuine report",
          attest_report_verify(report, sig, sig_len, pk) == 0);

    uint8_t bad_report[ATTEST_REPORT_BYTES];
    memcpy(bad_report, report, sizeof bad_report);
    bad_report[8] ^= 0x01; /* flip fw_version */
    check("verify rejects a tampered report",
          attest_report_verify(bad_report, sig, sig_len, pk) != 0);

    uint8_t bad_sig[ATTEST_SIG_MAX_BYTES];
    memcpy(bad_sig, sig, sig_len);
    bad_sig[0] ^= 0x01;
    check("verify rejects a tampered signature",
          attest_report_verify(report, bad_sig, sig_len, pk) != 0);

    uint8_t pk2[ATTEST_PUBKEY_BYTES], sk2[ATTEST_SECKEY_BYTES];
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2, sk2);
    check("verify rejects the wrong public key",
          attest_report_verify(report, sig, sig_len, pk2) != 0);

    if (failures) {
        printf("test_attest: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_attest: PASS\n");
    return 0;
}
