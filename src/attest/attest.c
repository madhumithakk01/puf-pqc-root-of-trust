#include "attest/attest.h"

#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

static void wr_le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void wr_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

void attest_report_serialize(uint32_t device_id, uint64_t fw_version,
                             uint64_t cnt,
                             const uint8_t nonce[ATTEST_NONCE_BYTES],
                             uint8_t report[ATTEST_REPORT_BYTES])
{
    report[0] = ATTEST_MAGIC0;
    report[1] = ATTEST_MAGIC1;
    report[2] = ATTEST_MAGIC2;
    report[3] = ATTEST_MAGIC3;
    wr_le32(report + 4, device_id);
    wr_le64(report + 8, fw_version);
    wr_le64(report + 16, cnt);
    memcpy(report + 24, nonce, ATTEST_NONCE_BYTES);
}

int attest_report_sign(const uint8_t report[ATTEST_REPORT_BYTES],
                       const uint8_t sk[ATTEST_SECKEY_BYTES],
                       uint8_t *sig, size_t sig_cap, size_t *sig_len)
{
    if (!report || !sk || !sig || !sig_len || sig_cap < ATTEST_SIG_MAX_BYTES) {
        return -1;
    }
    size_t n = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &n, report,
                                                    ATTEST_REPORT_BYTES, sk) != 0) {
        return -2;
    }
    *sig_len = n;
    return 0;
}

int attest_report_verify(const uint8_t report[ATTEST_REPORT_BYTES],
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t pk[ATTEST_PUBKEY_BYTES])
{
    if (!report || !sig || !pk || sig_len == 0 || sig_len > ATTEST_SIG_MAX_BYTES) {
        return -1;
    }
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, report,
                                                 ATTEST_REPORT_BYTES, pk) != 0) {
        return -2;
    }
    return 0;
}
