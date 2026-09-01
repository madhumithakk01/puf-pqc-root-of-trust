/*
 * Tests for confidential OTA delivery.
 *
 * Deterministic key material (tests/common/detrand.c). Covers the phase's exit
 * criteria: a correctly packaged update installs and boots; a package
 * encrypted for another device's KEM key fails to decapsulate here. Plus
 * tamper, downgrade, wrong-signer, malformed, and A/B bank behaviour.
 */

#include "ota/ota.h"
#include "secure_boot/secure_boot.h"
#include "rollback/rollback.h"

#include "fips202.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
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

static ota_flash F;
static uint8_t signed0[OTA_BANK_BYTES];
static uint8_t pkg[OTA_OVERHEAD_BYTES + 8192];
static uint8_t tmp[sizeof pkg];
static uint8_t body0[64];
static uint8_t body[128];

static int active_boots(const secure_boot_otp *otp, const rollback_store *rb,
                        const uint8_t *rbkey, uint64_t *fw_out)
{
    size_t al;
    const uint8_t *ai = ota_active_image(&F, &al);
    sb_result sb;
    sb_decision d = secure_boot_check(otp, ai, al, rb, rbkey, &sb);
    if (fw_out) {
        *fw_out = sb.fw_version;
    }
    return d == SB_BOOT;
}

int main(void)
{
    uint8_t kpk[OTA_KEM_PK_BYTES], ksk[OTA_KEM_SK_BYTES];
    uint8_t kpk2[OTA_KEM_PK_BYTES], ksk2[OTA_KEM_SK_BYTES];
    uint8_t spk[SB_PUBKEY_BYTES], ssk[SB_SECKEY_BYTES];
    uint8_t spk2[SB_PUBKEY_BYTES], ssk2[SB_SECKEY_BYTES];
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kpk, ksk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kpk2, ksk2);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(spk, ssk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(spk2, ssk2);

    secure_boot_otp otp;
    memcpy(otp.vendor_pubkey, spk, SB_PUBKEY_BYTES);

    uint8_t rbkey[ROLLBACK_KEY_BYTES];
    for (int i = 0; i < (int)sizeof rbkey; i++) {
        rbkey[i] = (uint8_t)(0x40 + i);
    }
    rollback_store rb;
    rollback_enroll(&rb, rbkey, 0);
    rollback_update(&rb, rbkey, 2, 0); /* authenticated counter = 2 */

    for (unsigned i = 0; i < sizeof body0; i++) body0[i] = (uint8_t)(i + 1);
    for (unsigned i = 0; i < sizeof body;  i++) body[i]  = (uint8_t)(i * 3 + 7);

    size_t n0 = 0;
    check("pack initial fw=2",
          secure_boot_pack(2, body0, sizeof body0, ssk, signed0, sizeof signed0, &n0) == 0);
    ota_flash_init(&F, signed0, n0);

    ota_result r;
    size_t pn = 0;

    /* --- 1. happy path: install, stage, confirm, boot --- */
    check("ota_pack fw=3", ota_pack(3, body, sizeof body, ssk, kpk, pkg, sizeof pkg, &pn) == 0);
    check("install -> OK, bank 1 pending, active still 0",
          ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r) == OTA_OK &&
          r.installed_bank == 1 && F.pending == 1 && F.active == 0);
    {
        /* deterministic given the fixed detrand stream and this being the
         * first ota_pack/ota_install after setup */
        uint8_t d[32];
        char hex[65];
        shake256(d, sizeof d, F.bank[1], F.bank_len[1]);
        for (int i = 0; i < 32; i++) {
            static const char h[] = "0123456789abcdef";
            hex[2 * i] = h[d[i] >> 4];
            hex[2 * i + 1] = h[d[i] & 15];
        }
        hex[64] = 0;
        check("staged image digest (determinism)",
              strncmp(hex,
                      "4ec9a0b5ca65594c1597a723e9bb7c810d403a0798cd8356ff89d0a303d6bfb4",
                      64) == 0);
    }
    {
        size_t al;
        const uint8_t *ai = ota_active_image(&F, &al);
        check("pre-confirm: active is still the old image",
              al == n0 && memcmp(ai, signed0, n0) == 0);
    }
    {
        sb_result sb;
        check("staged image passes secure boot",
              secure_boot_check(&otp, F.bank[1], F.bank_len[1], &rb, rbkey, &sb) == SB_BOOT);
    }
    ota_confirm(&F);
    {
        uint64_t fw = 0;
        check("post-confirm: active is bank 1", F.active == 1);
        check("post-confirm: active image boots at fw=3",
              active_boots(&otp, &rb, rbkey, &fw) && fw == 3);
    }

    /* --- 2. package for another device -> decapsulation gives wrong secret --- */
    ota_flash_init(&F, signed0, n0);
    check("ota_pack fw=3 for device 2",
          ota_pack(3, body, sizeof body, ssk, kpk2, pkg, sizeof pkg, &pn) == 0);
    check("install with device-1 key -> OTA_ERR_AUTH",
          ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_AUTH);
    check("nothing staged, active unchanged",
          F.pending == OTA_BANK_NONE && F.active == 0 && F.bank_len[1] == 0);

    /* --- 3-5. tamper --- */
    check("re-pack fw=3 for device 1",
          ota_pack(3, body, sizeof body, ssk, kpk, pkg, sizeof pkg, &pn) == 0);
    memcpy(tmp, pkg, pn);
    tmp[OTA_PREFIX_BYTES + 5] ^= 0x01;
    check("tampered payload ciphertext -> AUTH",
          ota_install(&F, tmp, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_AUTH);
    memcpy(tmp, pkg, pn);
    tmp[OTA_HDR_BYTES + 3] ^= 0x01;
    check("tampered KEM ciphertext -> AUTH",
          ota_install(&F, tmp, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_AUTH);
    memcpy(tmp, pkg, pn);
    tmp[pn - 1] ^= 0x01;
    check("tampered tag -> AUTH",
          ota_install(&F, tmp, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_AUTH);

    /* --- 6. inner signature by the wrong key --- */
    check("ota_pack signed by wrong key",
          ota_pack(3, body, sizeof body, ssk2, kpk, pkg, sizeof pkg, &pn) == 0);
    check("wrong signer -> REJECTED_BY_SECURE_BOOT (BAD_SIGNATURE)",
          ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_REJECTED_BY_SECURE_BOOT &&
          r.sb_decision == SB_REFUSE_BAD_SIGNATURE && F.pending == OTA_BANK_NONE);

    /* --- 7. downgrade below the counter --- */
    check("ota_pack fw=1 (< counter 2)",
          ota_pack(1, body, sizeof body, ssk, kpk, pkg, sizeof pkg, &pn) == 0);
    check("downgrade -> REJECTED_BY_SECURE_BOOT (ROLLBACK)",
          ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_REJECTED_BY_SECURE_BOOT &&
          r.sb_decision == SB_REFUSE_ROLLBACK);

    /* --- 8. malformed --- */
    check("re-pack fw=3", ota_pack(3, body, sizeof body, ssk, kpk, pkg, sizeof pkg, &pn) == 0);
    check("truncated -> MALFORMED",
          ota_install(&F, pkg, OTA_OVERHEAD_BYTES - 1, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_MALFORMED);
    memcpy(tmp, pkg, pn);
    tmp[0] = 'X';
    check("bad magic -> MALFORMED",
          ota_install(&F, tmp, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_MALFORMED);
    memcpy(tmp, pkg, pn);
    {
        size_t lo = OTA_HDR_BYTES + OTA_KEM_CT_BYTES + OTA_NONCE_BYTES;
        tmp[lo] = 0xff; tmp[lo + 1] = 0xff; tmp[lo + 2] = 0xff; tmp[lo + 3] = 0xff;
    }
    check("absurd payload_len -> MALFORMED",
          ota_install(&F, tmp, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_MALFORMED);

    /* --- 9. A/B bank behaviour --- */
    ota_flash_init(&F, signed0, n0);
    check("re-pack fw=3", ota_pack(3, body, sizeof body, ssk, kpk, pkg, sizeof pkg, &pn) == 0);
    ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r);
    ota_reject(&F);
    check("after reject: no pending, active 0, bank 1 wiped",
          F.pending == OTA_BANK_NONE && F.active == 0 && F.bank_len[1] == 0);
    {
        size_t al;
        const uint8_t *ai = ota_active_image(&F, &al);
        check("after reject: old image intact", al == n0 && memcmp(ai, signed0, n0) == 0);
    }
    ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r);
    ota_confirm(&F);
    check("re-pack fw=3 for device 2",
          ota_pack(3, body, sizeof body, ssk, kpk2, pkg, sizeof pkg, &pn) == 0);
    check("failed OTA after a confirm: AUTH, active stays 1, no pending",
          ota_install(&F, pkg, pn, ksk, &otp, &rb, rbkey, &r) == OTA_ERR_AUTH &&
          F.active == 1 && F.pending == OTA_BANK_NONE);

    if (failures) {
        printf("test_ota: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_ota: PASS\n");
    return 0;
}
