/*
 * Tests for the secure boot decision.
 *
 * Key material is deterministic (tests/common/detrand.c), so the vendor public
 * key is pinned by digest. The bulk of the file is the decision matrix from
 * the phase's exit criteria: a valid image at an allowed version boots; a
 * wrong signature, a wrong version, and a tampered counter each refuse
 * independently, and the first failing gate wins.
 */

#include "secure_boot/secure_boot.h"
#include "rollback/rollback.h"
#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include "fips202.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static void expect_digest(const char *name, const uint8_t *data, size_t len,
                          const char *want)
{
    uint8_t d[32];
    char hex[65];
    shake256(d, sizeof d, data, len);
    for (int i = 0; i < 32; i++) {
        static const char h[] = "0123456789abcdef";
        hex[2 * i] = h[d[i] >> 4];
        hex[2 * i + 1] = h[d[i] & 15];
    }
    hex[64] = 0;
    if (strncmp(hex, want, 64) != 0) {
        printf("  FAIL %s\n    want %s\n    got  %s\n", name, want, hex);
        failures++;
    } else {
        printf("  ok   %s\n", name);
    }
}

#define BODY_LEN 96u
#define IMG_CAP (28u + BODY_LEN + SB_SIG_MAX_BYTES)

int main(void)
{
    uint8_t pk[SB_PUBKEY_BYTES], sk[SB_SECKEY_BYTES];
    uint8_t pk2[SB_PUBKEY_BYTES], sk2[SB_SECKEY_BYTES];
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2, sk2);

    secure_boot_otp otp;
    memcpy(otp.vendor_pubkey, pk, SB_PUBKEY_BYTES);
    expect_digest("vendor pubkey digest (determinism)", otp.vendor_pubkey,
                  SB_PUBKEY_BYTES,
                  "1a4fc75d3d82bcda7689622d8f95a3c867c6a578e5b2a98111c91b1d16fa565d");

    uint8_t rbkey[ROLLBACK_KEY_BYTES];
    for (int i = 0; i < (int)sizeof rbkey; i++) {
        rbkey[i] = (uint8_t)(0x40 + i);
    }
    rollback_store rb;
    rollback_enroll(&rb, rbkey, 0);
    rollback_update(&rb, rbkey, 3, 0); /* authenticated counter = 3 */

    uint8_t body[BODY_LEN];
    for (unsigned i = 0; i < BODY_LEN; i++) {
        body[i] = (uint8_t)(i * 7 + 1);
    }

    uint8_t img3[IMG_CAP], img5[IMG_CAP], img2[IMG_CAP], imgw[IMG_CAP];
    size_t n3, n5, n2, nw;
    check("pack fw=3", secure_boot_pack(3, body, BODY_LEN, sk, img3, IMG_CAP, &n3) == 0);
    check("pack fw=5", secure_boot_pack(5, body, BODY_LEN, sk, img5, IMG_CAP, &n5) == 0);
    check("pack fw=2", secure_boot_pack(2, body, BODY_LEN, sk, img2, IMG_CAP, &n2) == 0);
    check("pack fw=3 wrong key",
          secure_boot_pack(3, body, BODY_LEN, sk2, imgw, IMG_CAP, &nw) == 0);

    sb_result r;

    /* --- accepts --- */
    check("valid image, fw == cnt -> BOOT",
          secure_boot_check(&otp, img3, n3, &rb, rbkey, &r) == SB_BOOT &&
          r.fw_version == 3 && r.counter == 3);
    check("valid image, fw > cnt -> BOOT",
          secure_boot_check(&otp, img5, n5, &rb, rbkey, &r) == SB_BOOT);

    /* --- wrong version --- */
    check("fw < cnt -> REFUSE_ROLLBACK",
          secure_boot_check(&otp, img2, n2, &rb, rbkey, &r) == SB_REFUSE_ROLLBACK &&
          r.counter == 3 && r.fw_version == 2);

    /* --- wrong signature --- */
    {
        uint8_t t[IMG_CAP];
        memcpy(t, img3, n3);
        t[n3 - 1] ^= 0x01; /* last signature byte */
        check("flipped signature -> REFUSE_BAD_SIGNATURE",
              secure_boot_check(&otp, t, n3, &rb, rbkey, &r) == SB_REFUSE_BAD_SIGNATURE);

        memcpy(t, img3, n3);
        t[SB_AUTH_HDR_BYTES + 10] ^= 0x01; /* a body byte, signature intact */
        check("flipped body -> REFUSE_BAD_SIGNATURE",
              secure_boot_check(&otp, t, n3, &rb, rbkey, &r) == SB_REFUSE_BAD_SIGNATURE);

        memcpy(t, img3, n3);
        t[8] = 9; /* rewrite fw_version in place, do not re-sign */
        sb_decision d = secure_boot_check(&otp, t, n3, &rb, rbkey, &r);
        check("in-place fw_version bump -> REFUSE_BAD_SIGNATURE (not BOOT)",
              d == SB_REFUSE_BAD_SIGNATURE);

        check("signed by wrong key -> REFUSE_BAD_SIGNATURE",
              secure_boot_check(&otp, imgw, nw, &rb, rbkey, &r) == SB_REFUSE_BAD_SIGNATURE);
    }

    /* --- tampered counter --- */
    {
        rollback_store t = rb;
        /* newest page is index 1 after enroll+update */
        t.page[1][8] ^= 0x01; /* flip a bit of cnt */
        check("tampered counter page -> REFUSE_COUNTER",
              secure_boot_check(&otp, img3, n3, &t, rbkey, &r) == SB_REFUSE_COUNTER &&
              r.rollback_rc == ROLLBACK_ERR_TAMPER);

        rollback_store both = rb;
        both.page[0][20] ^= 0x01;
        both.page[1][20] ^= 0x01;
        check("both counter pages corrupt -> REFUSE_COUNTER",
              secure_boot_check(&otp, img3, n3, &both, rbkey, &r) == SB_REFUSE_COUNTER);

        rollback_store blank;
        memset(&blank, 0, sizeof blank);
        check("un-enrolled counter store -> REFUSE_COUNTER",
              secure_boot_check(&otp, img3, n3, &blank, rbkey, &r) == SB_REFUSE_COUNTER &&
              r.rollback_rc == ROLLBACK_ERR_NO_VALID_PAGE);

        rollback_store torn = rb;
        rollback_update(&torn, rbkey, 4, 20); /* power loss mid counter bump */
        check("torn counter update -> REFUSE_COUNTER (safe: refuse, not misboot)",
              secure_boot_check(&otp, img3, n3, &torn, rbkey, &r) == SB_REFUSE_COUNTER);
    }

    /* --- malformed --- */
    {
        check("truncated image -> REFUSE_MALFORMED",
              secure_boot_check(&otp, img3, 10, &rb, rbkey, &r) == SB_REFUSE_MALFORMED);
        uint8_t t[IMG_CAP];
        memcpy(t, img3, n3);
        t[0] = 'X';
        check("bad magic -> REFUSE_MALFORMED",
              secure_boot_check(&otp, t, n3, &rb, rbkey, &r) == SB_REFUSE_MALFORMED);
        memcpy(t, img3, n3);
        t[SB_AUTH_HDR_BYTES + BODY_LEN] = 0xff; /* sig_len byte 0 */
        t[SB_AUTH_HDR_BYTES + BODY_LEN + 1] = 0xff;
        check("absurd sig_len -> REFUSE_MALFORMED",
              secure_boot_check(&otp, t, n3, &rb, rbkey, &r) == SB_REFUSE_MALFORMED);
        memcpy(t, img3, n3);
        t[16] = 0xff; /* body_len byte 0 -> huge */
        check("absurd body_len -> REFUSE_MALFORMED",
              secure_boot_check(&otp, t, n3, &rb, rbkey, &r) == SB_REFUSE_MALFORMED);
    }

    /* --- gate ordering: signature before counter before version --- */
    {
        uint8_t t[IMG_CAP];
        memcpy(t, img2, n2);     /* fw=2 < cnt, would be ROLLBACK */
        t[n2 - 1] ^= 0x01;       /* also break the signature */
        check("bad sig + low version -> BAD_SIGNATURE wins",
              secure_boot_check(&otp, t, n2, &rb, rbkey, &r) == SB_REFUSE_BAD_SIGNATURE);

        rollback_store tam = rb;
        tam.page[1][8] ^= 0x01;  /* tamper counter */
        check("valid sig + low version + tampered counter -> COUNTER wins",
              secure_boot_check(&otp, img2, n2, &tam, rbkey, &r) == SB_REFUSE_COUNTER);
    }

    if (failures) {
        printf("test_secure_boot: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_secure_boot: PASS\n");
    return 0;
}
