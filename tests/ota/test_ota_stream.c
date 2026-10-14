/*
 * Streaming AEAD equals the one-shot functions for any chunking, and
 * ota_pack_signed wraps images larger than the simulated bank, which a host
 * streaming decrypt then recovers and verifies.
 */

#include "ota/ota.h"
#include "ota/ota_aead.h"
#include "secure_boot/secure_boot.h"
#include "kdf/kdf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

/* fixed-seed xorshift: reproducible lengths and chunkings */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

#define MAXLEN 3000

static void test_chunking(void)
{
    uint8_t ekey[32], mkey[32], nonce[24];
    static uint8_t pt[MAXLEN], one[MAXLEN], str[MAXLEN];
    int bad_xor = 0, bad_mac = 0;

    for (int i = 0; i < 32; i++) { ekey[i] = (uint8_t)(i + 1); mkey[i] = (uint8_t)(0x80 + i); }
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(0x30 + i);

    for (int iter = 0; iter < 200; iter++) {
        size_t len = rnd() % (MAXLEN + 1);
        for (size_t i = 0; i < len; i++) pt[i] = (uint8_t)rnd();

        memcpy(one, pt, len);
        ota_aead_xor(ekey, nonce, one, len);

        memcpy(str, pt, len);
        ota_aead_stream s;
        ota_aead_stream_init(&s, ekey, nonce);
        for (size_t off = 0; off < len;) {
            size_t n = 1 + rnd() % 300;
            if (n > len - off) n = len - off;
            ota_aead_stream_xor(&s, str + off, n);
            off += n;
        }
        ota_aead_stream_release(&s);
        if (memcmp(one, str, len) != 0) bad_xor++;

        uint8_t t1[32], t2[32];
        ota_aead_mac(mkey, nonce, one, len, t1);
        ota_aead_mac_ctx m;
        ota_aead_mac_init(&m, mkey, nonce, len);
        for (size_t off = 0; off < len;) {
            size_t n = rnd() % 400; /* includes empty updates */
            if (n > len - off) n = len - off;
            ota_aead_mac_update(&m, one + off, n);
            off += n;
        }
        ota_aead_mac_final(&m, t2);
        if (memcmp(t1, t2, 32) != 0) bad_mac++;
    }
    check("200 lengths/chunkings: stream XOR equals one-shot", bad_xor == 0);
    check("200 lengths/chunkings: streamed MAC equals one-shot", bad_mac == 0);
}

#define IMG_BODY 20000u

static void test_pack_signed(void)
{
    static uint8_t kpk[OTA_KEM_PK_BYTES], ksk[OTA_KEM_SK_BYTES];
    static uint8_t spk[SB_PUBKEY_BYTES], ssk[SB_SECKEY_BYTES];
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kpk, ksk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(spk, ssk);

    uint8_t *body = malloc(IMG_BODY);
    size_t img_cap = SB_AUTH_HDR_BYTES + IMG_BODY + 4 + SB_SIG_MAX_BYTES;
    uint8_t *img = malloc(img_cap);
    uint8_t *pkg = malloc(OTA_OVERHEAD_BYTES + img_cap);
    uint8_t *dec = malloc(img_cap);
    for (unsigned i = 0; i < IMG_BODY; i++) body[i] = (uint8_t)(i * 7 + 3);

    size_t img_len = 0, pkg_len = 0;
    check("sign a 20 KB image (above the 8 KB simulated bank)",
          secure_boot_pack(5, body, IMG_BODY, ssk, img, img_cap, &img_len) == 0);
    check("ota_pack_signed wraps it",
          ota_pack_signed(img, img_len, kpk, pkg, OTA_OVERHEAD_BYTES + img_cap, &pkg_len) == 0
          && pkg_len == OTA_OVERHEAD_BYTES + img_len);
    check("package has OTA1 magic and length field",
          memcmp(pkg, "OTA1", 4) == 0 && pkg[8 + OTA_KEM_CT_BYTES + OTA_NONCE_BYTES] == (uint8_t)img_len);
    check("ciphertext differs from plaintext",
          memcmp(pkg + OTA_PREFIX_BYTES, img, 64) != 0);

    /* host streaming open: decapsulate, check tag over chunks, decrypt over chunks */
    const uint8_t *kem_ct = pkg + OTA_HDR_BYTES;
    const uint8_t *nonce = kem_ct + OTA_KEM_CT_BYTES;
    const uint8_t *ct = pkg + OTA_PREFIX_BYTES;
    uint8_t ss[32], ek[32], mk[32], tag[32];
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, kem_ct, ksk);
    ota_aead_derive_keys(ss, 32, ek, mk);

    ota_aead_mac_ctx m;
    ota_aead_mac_init(&m, mk, nonce, img_len);
    for (size_t off = 0; off < img_len; off += 4096) {
        size_t n = img_len - off < 4096 ? img_len - off : 4096;
        ota_aead_mac_update(&m, ct + off, n);
    }
    ota_aead_mac_final(&m, tag);
    check("streamed tag matches the package tag", ota_aead_tag_equal(tag, ct + img_len));

    memcpy(dec, ct, img_len);
    ota_aead_stream s;
    ota_aead_stream_init(&s, ek, nonce);
    for (size_t off = 0; off < img_len; off += 4096) {
        size_t n = img_len - off < 4096 ? img_len - off : 4096;
        ota_aead_stream_xor(&s, dec + off, n);
    }
    ota_aead_stream_release(&s);
    check("streamed decrypt recovers the signed image", memcmp(dec, img, img_len) == 0);

    /* the recovered image passes the unchanged secure boot check */
    secure_boot_otp otp;
    memcpy(otp.vendor_pubkey, spk, SB_PUBKEY_BYTES);
    uint8_t rbkey[ROLLBACK_KEY_BYTES] = {0};
    rollback_store rb;
    rollback_enroll(&rb, rbkey, 0);
    sb_result r;
    check("secure_boot_check accepts the recovered image",
          secure_boot_check(&otp, dec, img_len, &rb, rbkey, &r) == SB_BOOT);

    /* too-small output buffer is refused */
    check("undersized output refused",
          ota_pack_signed(img, img_len, kpk, pkg, OTA_OVERHEAD_BYTES + img_len - 1, &pkg_len) == -2);

    free(body); free(img); free(pkg); free(dec);
}

int main(void)
{
    test_chunking();
    test_pack_signed();
    if (failures) {
        printf("test_ota_stream: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_ota_stream: PASS\n");
    return 0;
}
