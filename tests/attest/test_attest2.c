/*
 * Tests for ATR2 (attest2) and RCP1 (rot_receipt): serialization against
 * pinned digests (the Python verifier pins the same values), field offsets,
 * sign/verify, tamper rejection, and the receipt hash chain.
 */

#include "attest/attest2.h"
#include "rot/rot_receipt.h"

#include "fips202.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define ATR2_PIN "21e5dc9f8f3da17098a919d8c8b72f51c23ea654357c152e5717a5374fed105a"
#define RCP1_PIN "36752a23e201e2c9c78c34cf8515a03395b8b851b46fdbaa461a2efb0036246d"

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

static void hex_digest(const uint8_t *data, size_t len, char out[65])
{
    static const char h[] = "0123456789abcdef";
    uint8_t d[32];
    shake256(d, sizeof d, data, len);
    for (int i = 0; i < 32; i++) {
        out[2 * i] = h[d[i] >> 4];
        out[2 * i + 1] = h[d[i] & 15];
    }
    out[64] = 0;
}

static void fill(uint8_t *p, int n, int base)
{
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(base + i);
}

static atr2_t atr2_fixture(void)
{
    atr2_t a;
    memset(&a, 0, sizeof a);
    a.device_id = 0xA1B2C3D4u;
    a.svn = 2;
    a.floor = 2;
    fill(a.verifier_nonce, 32, 0x10);
    fill(a.rot_nonce, 32, 0x40);
    fill(a.image_digest, 32, 0x70);
    a.active_slot = 1;
    a.trial_state = 0;
    a.reset_cause = 1;
    a.flags = ATR2_FLAG_SIM_PUF;
    a.journal_seq = 9;
    a.last_receipt_seq = 4;
    a.bits_corrected = 123;
    a.worst_block = 4;
    fill(a.last_receipt_digest, 32, 0xA0);
    memcpy(a.version, "1.1.0", 5);
    return a;
}

static rcp_t rcp_fixture(void)
{
    rcp_t r;
    memset(&r, 0, sizeof r);
    r.seq = 5;
    r.device_id = 0xA1B2C3D4u;
    r.outcome = RCP_ROLLED_BACK;
    r.reason = RCP_REASON_HEALTH_FAIL_BPM;
    r.slot = 1;
    r.from_svn = 2;
    r.to_svn = 3;
    r.floor_before = 2;
    r.floor_after = 2;
    fill(r.image_digest, 32, 0x11);
    fill(r.package_digest, 32, 0x31);
    fill(r.rot_nonce, 32, 0x51);
    fill(r.evidence_digest, 32, 0x71);
    fill(r.prev_digest, 32, 0x91);
    r.journal_seq = 12;
    memcpy(r.version, "1.2.0", 5);
    return r;
}

static uint8_t pk[ATR2_PUBKEY_BYTES], sk[ATR2_SECKEY_BYTES];
static uint8_t pk2[ATR2_PUBKEY_BYTES], sk2[ATR2_SECKEY_BYTES];

static void test_atr2(void)
{
    uint8_t body[ATR2_BODY_BYTES], obj[ATR2_TOTAL_BYTES], t[ATR2_TOTAL_BYTES];
    atr2_t a = atr2_fixture(), b;
    char hex[65];

    atr2_serialize(body, &a);
    hex_digest(body, sizeof body, hex);
    if (strcmp(ATR2_PIN, "21e5dc9f8f3da17098a919d8c8b72f51c23ea654357c152e5717a5374fed105a") == 0) printf("ATR2 digest %s\n", hex);
    check("ATR2 body matches the pinned digest", strcmp(hex, ATR2_PIN) == 0);
    check("ATR2 offsets", memcmp(body, "ATR2", 4) == 0 && body[4] == 0xD4 && body[8] == 2
          && body[24] == 0x10 && body[56] == 0x40 && body[88] == 0x70 && body[120] == 1
          && body[123] == 1 && body[124] == 9 && body[128] == 4 && body[132] == 123
          && body[134] == 4 && body[136] == 0xA0 && body[168] == '1' && body[184] == 0);
    check("ATR2 parse round trip", atr2_parse(body, &b) == 0 && b.device_id == a.device_id
          && b.svn == 2 && b.floor == 2 && b.bits_corrected == 123 && b.worst_block == 4
          && memcmp(b.rot_nonce, a.rot_nonce, 32) == 0 && memcmp(b.version, a.version, 16) == 0);

    memcpy(t, body, sizeof body); t[135] = 1;
    check("ATR2 reserved byte rejected", atr2_parse(t, &b) != 0);
    memcpy(t, body, sizeof body); t[0] = 'X';
    check("ATR2 bad magic rejected", atr2_parse(t, &b) != 0);

    check("ATR2 sign", atr2_sign(body, sk, obj) == 0);
    check("ATR2 verify", atr2_verify(obj, sizeof obj, pk) == 0);
    check("ATR2 wrong key rejected", atr2_verify(obj, sizeof obj, pk2) != 0);
    memcpy(t, obj, sizeof obj); t[16] ^= 1;
    check("ATR2 altered floor rejected", atr2_verify(t, sizeof t, pk) != 0);
    memcpy(t, obj, sizeof obj); t[200] ^= 1;
    check("ATR2 altered signature rejected", atr2_verify(t, sizeof t, pk) != 0);
    check("ATR2 truncated rejected", atr2_verify(obj, sizeof obj - 1, pk) != 0);
}

static void test_rcp(void)
{
    uint8_t body[RCP_BODY_BYTES], obj[RCP_TOTAL_BYTES], t[RCP_TOTAL_BYTES];
    rcp_t r = rcp_fixture(), g;
    char hex[65];

    rcp_serialize(body, &r);
    hex_digest(body, sizeof body, hex);
    if (strcmp(RCP1_PIN, "36752a23e201e2c9c78c34cf8515a03395b8b851b46fdbaa461a2efb0036246d") == 0) printf("RCP1 digest %s\n", hex);
    check("RCP1 body matches the pinned digest", strcmp(hex, RCP1_PIN) == 0);
    check("RCP1 offsets", memcmp(body, "RCP1", 4) == 0 && body[4] == 5 && body[8] == 0xD4
          && body[12] == 2 && body[13] == 20 && body[14] == 1 && body[16] == 2 && body[24] == 3
          && body[32] == 2 && body[40] == 2 && body[48] == 0x11 && body[80] == 0x31
          && body[112] == 0x51 && body[144] == 0x71 && body[176] == 0x91 && body[208] == 12
          && body[212] == '1' && body[228] == 0);
    check("RCP1 parse round trip", rcp_parse(body, &g) == 0 && g.seq == 5 && g.outcome == 2
          && g.reason == 20 && g.to_svn == 3 && g.floor_after == 2
          && memcmp(g.prev_digest, r.prev_digest, 32) == 0);
    memcpy(t, body, sizeof body); t[240] = 1;
    check("RCP1 reserved bytes rejected", rcp_parse(t, &g) != 0);

    check("RCP1 sign", rcp_sign(body, sk, obj) == 0);
    check("RCP1 verify", rcp_verify(obj, sizeof obj, pk) == 0);
    check("RCP1 wrong key rejected", rcp_verify(obj, sizeof obj, pk2) != 0);
    memcpy(t, obj, sizeof obj); t[13] = 0;
    check("RCP1 altered reason rejected", rcp_verify(t, sizeof t, pk) != 0);
}

#define N 4
static uint8_t chain[N][RCP_TOTAL_BYTES];

static void build_chain(void)
{
    uint8_t prev[32] = {0};
    for (int i = 0; i < N; i++) {
        rcp_t r = rcp_fixture();
        uint8_t body[RCP_BODY_BYTES];
        r.seq = (uint32_t)i + 1;
        memcpy(r.prev_digest, prev, 32);
        rcp_serialize(body, &r);
        rcp_sign(body, sk, chain[i]);
        rcp_chain_digest(chain[i], prev);
    }
}

static void test_chain(void)
{
    uint8_t zero[32] = {0};
    static uint8_t buf[N][RCP_TOTAL_BYTES];

    build_chain();
    check("chain of 4 verifies", rcp_verify_chain(&chain[0][0], N, pk, zero) == 0);
    {
        uint8_t d[32];
        rcp_chain_digest(chain[1], d);
        check("chain suffix verifies with its predecessor digest",
              rcp_verify_chain(&chain[2][0], 2, pk, d) == 0);
    }
    check("wrong key fails at receipt 1", rcp_verify_chain(&chain[0][0], N, pk2, zero) == 1);

    memcpy(buf, chain, sizeof chain);
    memcpy(buf[1], chain[2], RCP_TOTAL_BYTES);
    memcpy(buf[2], chain[1], RCP_TOTAL_BYTES);
    check("reordered receipts detected", rcp_verify_chain(&buf[0][0], N, pk, zero) == 2);

    memcpy(buf[0], chain[0], RCP_TOTAL_BYTES);
    memcpy(buf[1], chain[2], RCP_TOTAL_BYTES);
    memcpy(buf[2], chain[3], RCP_TOTAL_BYTES);
    check("removed receipt detected", rcp_verify_chain(&buf[0][0], 3, pk, zero) == 2);

    memcpy(buf, chain, sizeof chain);
    buf[1][14] ^= 1;
    check("altered receipt detected", rcp_verify_chain(&buf[0][0], N, pk, zero) == 2);

    check("chain not starting from zero detected", rcp_verify_chain(&chain[1][0], 3, pk, zero) == 1);
}

int main(void)
{
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2, sk2);
    test_atr2();
    test_rcp();
    test_chain();
    if (failures) {
        printf("test_attest2: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_attest2: PASS\n");
    return 0;
}
