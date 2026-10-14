/*
 * Tests for DLV1: a clean package passes; each refusal reason is produced by
 * exactly its own fault; combined faults prove the check order
 * (structure, signature, device, nonce, floor, digest).
 */

#include "dlv/dlv.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

#define OTA_LEN 1300u
#define DEVICE  0x1234ABCDu
#define FLOOR   2u

static uint8_t vpk[SB_PUBKEY_BYTES], vsk[SB_SECKEY_BYTES];
static uint8_t opk[SB_PUBKEY_BYTES], osk[SB_SECKEY_BYTES];
static uint8_t nonce[DLV_NONCE_BYTES];
static uint8_t ota[OTA_LEN];
static uint8_t pkg[DLV_PREFIX_BYTES + OTA_LEN];
static uint8_t work[DLV_PREFIX_BYTES + OTA_LEN];
static size_t pkg_len;

static int read_cb(void *ctx, uint64_t off, uint8_t *buf, size_t n)
{
    const uint8_t *base = ctx;
    memcpy(buf, base + DLV_PREFIX_BYTES + off, n);
    return 0;
}

static dlv_t manifest(void)
{
    dlv_t m;
    memset(&m, 0, sizeof m);
    m.device_id = DEVICE;
    memcpy(m.rot_nonce, nonce, sizeof nonce);
    m.svn = 3;
    memcpy(m.version, "1.1.0", 5);
    m.issued_unix = 1760400000;
    return m;
}

static void build(uint8_t *out, const dlv_t *m, const uint8_t *sk)
{
    size_t n;
    if (dlv_pack(m, sk, ota, OTA_LEN, out, sizeof pkg, &n) != 0 || n != sizeof pkg) {
        printf("pack failed\n");
        exit(1);
    }
}

/* The read callback reads from the same buffer that holds the prefix. */
static dlv_status run(const uint8_t *p, size_t len, uint32_t dev,
                      const uint8_t *nn, uint64_t floor)
{
    return dlv_check(p, len, vpk, dev, nn, floor, read_cb, (void *)p, NULL);
}

int main(void)
{
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(vpk, vsk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(opk, osk);
    for (unsigned i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0xC0 + i);
    for (unsigned i = 0; i < OTA_LEN; i++) ota[i] = (uint8_t)(i * 5 + 1);

    dlv_t m = manifest();
    build(pkg, &m, vsk);
    pkg_len = sizeof pkg;

    check("prefix is 2552 bytes", DLV_PREFIX_BYTES == 2552u);
    check("magic, version and sig_len fields",
          memcmp(pkg, "DLV1", 4) == 0 && pkg[4] == 1 && pkg[128] == 0x74 && pkg[129] == 0x09);

    dlv_t got;
    check("clean package accepted",
          dlv_check(pkg, pkg_len, vpk, DEVICE, nonce, FLOOR, read_cb, pkg, &got) == DLV_OK);
    check("parsed fields", got.device_id == DEVICE && got.svn == 3 && got.ota_len == OTA_LEN
          && memcmp(got.version, "1.1.0", 5) == 0 && memcmp(got.rot_nonce, nonce, 32) == 0);
    check("svn equal to floor accepted", run(pkg, pkg_len, DEVICE, nonce, 3) == DLV_OK);

    /* one fault, one reason */
    memcpy(work, pkg, pkg_len); work[0] = 'X';
    check("bad magic -> MALFORMED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);
    memcpy(work, pkg, pkg_len); work[6] = 1;
    check("nonzero flags -> MALFORMED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);
    memcpy(work, pkg, pkg_len); work[12] = 1;
    check("nonzero reserved -> MALFORMED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);
    memcpy(work, pkg, pkg_len); work[128]++;
    check("wrong sig_len -> MALFORMED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);
    check("truncated package -> MALFORMED", run(pkg, pkg_len - 1, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);
    check("shorter than the prefix -> MALFORMED", run(pkg, DLV_PREFIX_BYTES, DEVICE, nonce, FLOOR) == DLV_E_MALFORMED);

    build(work, &m, osk);
    check("signed by another key -> UNKNOWN_SIGNER", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_UNKNOWN_SIGNER);
    memcpy(work, pkg, pkg_len); work[50] ^= 1;
    check("manifest field altered after signing -> UNKNOWN_SIGNER", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_UNKNOWN_SIGNER);

    check("other device -> WRONG_DEVICE", run(pkg, pkg_len, DEVICE + 1, nonce, FLOOR) == DLV_E_WRONG_DEVICE);

    uint8_t other[32];
    memcpy(other, nonce, 32);
    other[31] ^= 1;
    check("different nonce -> STALE_NONCE", run(pkg, pkg_len, DEVICE, other, FLOOR) == DLV_E_STALE_NONCE);
    check("no outstanding nonce -> STALE_NONCE", run(pkg, pkg_len, DEVICE, NULL, FLOOR) == DLV_E_STALE_NONCE);

    check("svn below floor -> BELOW_FLOOR", run(pkg, pkg_len, DEVICE, nonce, 4) == DLV_E_BELOW_FLOOR);

    memcpy(work, pkg, pkg_len); work[DLV_PREFIX_BYTES + 700] ^= 0x80;
    check("one OTA1 byte flipped -> AUTH_FAILED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_AUTH_FAILED);
    memcpy(work, pkg, pkg_len); work[pkg_len - 1] ^= 1;
    check("last OTA1 byte flipped -> AUTH_FAILED", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_AUTH_FAILED);

    /* order: every later fault is present, the earlier one wins */
    dlv_t bad = manifest();
    bad.device_id = DEVICE + 9;
    bad.svn = 1;
    bad.rot_nonce[0] ^= 1;
    build(work, &bad, vsk);
    work[DLV_PREFIX_BYTES + 5] ^= 1; /* digest fault too */
    check("order: device before nonce, floor, digest", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_WRONG_DEVICE);
    bad.device_id = DEVICE;
    build(work, &bad, vsk);
    work[DLV_PREFIX_BYTES + 5] ^= 1;
    check("order: nonce before floor, digest", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_STALE_NONCE);
    memcpy(bad.rot_nonce, nonce, 32);
    build(work, &bad, vsk);
    work[DLV_PREFIX_BYTES + 5] ^= 1;
    check("order: floor before digest", run(work, pkg_len, DEVICE, nonce, FLOOR) == DLV_E_BELOW_FLOOR);
    build(work, &bad, osk);
    check("order: signature before device, nonce, floor", run(work, pkg_len, DEVICE + 1, other, FLOOR) == DLV_E_UNKNOWN_SIGNER);
    memcpy(work, pkg, pkg_len); work[0] = 'X';
    check("order: structure before signature", run(work, pkg_len, DEVICE + 1, other, 99) == DLV_E_MALFORMED);

    if (failures) {
        printf("test_dlv: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_dlv: PASS\n");
    return 0;
}
