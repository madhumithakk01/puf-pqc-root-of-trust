/*
 * vendor_cli: the vendor's offline tool.
 *
 *   keygen NAME [--seed HEX32]                 ML-DSA-44 key pair -> NAME.pk, NAME.sk
 *   keygen-device NAME --seed HEX32            device identity from a UDS (test devices):
 *                                              NAME.dsa.pk, NAME.kem.pk, prints the device id
 *   sign-image --app F --svn N --version S --key SK --out F
 *              [--golden-from v10|v11 | --golden-bpm X10 [--golden-spo2 X10]]
 *              [--tol-bpm X10] [--tol-spo2 X10] [--min-live N] [--deadline MS] [--build-id HEX40]
 *                                              SBI1 image: APM1 manifest + application binary
 *   package --image F --device-id HEX --kem-pk F --nonce HEX --svn N --version S --key SK --out F
 *                                              DLV1 around OTA1 (ML-KEM-512 + SHAKE256 EtM)
 *   verify-image --pk F IMAGE                  exit 0 if the SBI1 signature verifies under the key
 *   inspect FILE                               describe an SBI1, DLV1, ENR1, ATR2 or RCP1 object
 *   inspect-rotdata FILE                       describe a rot_data dump and account for every byte
 *   issue-cert --ca-sk F --enr1 F --out F      ATC1 enrollment certificate from a verified ENR1
 *
 * Output of the inspect commands is JSON on stdout. Key files are raw bytes.
 */

#include "apm/apm.h"
#include "attest/attest2.h"
#include "dlv/dlv.h"
#include "dsp/dsp.h"
#include "golden/golden_trace.h"
#include "ota/ota.h"
#include "rot/rot_crc32.h"
#include "rot/rot_enroll.h"
#include "rot/rot_flash_map.h"
#include "rot/rot_helper.h"
#include "rot/rot_journal.h"
#include "rot/rot_keys.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_receipt.h"
#include "rot/rot_rng.h"
#include "rot/rot_util.h"
#include "secure_boot/secure_boot.h"

#include "api.h"
#include "fips202.h"
#include "randombytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

static void die(const char *msg)
{
    fprintf(stderr, "vendor_cli: %s\n", msg);
    exit(1);
}

static const char *opt(int argc, char **argv, const char *name)
{
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

static const char *need(int argc, char **argv, const char *name)
{
    const char *v = opt(argc, argv, name);
    if (!v) {
        fprintf(stderr, "vendor_cli: missing %s\n", name);
        exit(2);
    }
    return v;
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long n;
    if (!f) {
        fprintf(stderr, "vendor_cli: cannot open %s\n", path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) die("read failed");
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static void write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "vendor_cli: cannot write %s\n", path);
        exit(1);
    }
    fclose(f);
}

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = strlen(h);
    if (n % 2 || n / 2 > cap) die("bad hex argument");
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) die("bad hex argument");
        out[i] = (uint8_t)v;
    }
    return n / 2;
}

static void phex(const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
}

static void fpr_of(const uint8_t *pk, size_t n)
{
    uint8_t f[32];
    rot_fingerprint(pk, n, f);
    phex(f, 32);
}

/* Operating-system entropy for everything that is not seeded explicitly. */
static void os_raw(void *ctx, uint8_t *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    (void)ctx;
    if (!f || fread(buf, 1, n, f) != n) die("no operating-system randomness available");
    fclose(f);
}

static void cmd_keygen(int argc, char **argv)
{
    uint8_t pk[SB_PUBKEY_BYTES], sk[SB_SECKEY_BYTES];
    const char *seed = opt(argc, argv, "--seed");
    char path[512];

    if (argc < 1) die("keygen NAME");
    if (seed) {
        uint8_t s[32];
        if (unhex(seed, s, 32) != 32) die("--seed needs 32 bytes");
        rot_rng_seed_once(s, 32);
    }
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    rot_rng_reset();
    snprintf(path, sizeof path, "%s.pk", argv[0]);
    write_file(path, pk, sizeof pk);
    snprintf(path, sizeof path, "%s.sk", argv[0]);
    write_file(path, sk, sizeof sk);
    printf("{\"name\":\"%s\",\"fingerprint\":\"", argv[0]);
    fpr_of(pk, sizeof pk);
    printf("\"}\n");
}

static void cmd_keygen_device(int argc, char **argv)
{
    static rot_keys k;
    uint8_t uds[32];
    char path[512];
    const char *seed = need(argc, argv, "--seed");

    if (argc < 1) die("keygen-device NAME --seed HEX32");
    if (unhex(seed, uds, 32) != 32) die("--seed needs 32 bytes");
    if (rot_keys_derive(uds, &k) != 0) die("key derivation failed");
    snprintf(path, sizeof path, "%s.dsa.pk", argv[0]);
    write_file(path, k.pk_dsa, sizeof k.pk_dsa);
    snprintf(path, sizeof path, "%s.kem.pk", argv[0]);
    write_file(path, k.pk_kem, sizeof k.pk_kem);
    printf("{\"name\":\"%s\",\"device_id\":\"%08x\",\"fingerprint_dsa\":\"", argv[0], k.device_id);
    phex(k.fpr_dsa, 32);
    printf("\",\"fingerprint_kem\":\"");
    phex(k.fpr_kem, 32);
    printf("\"}\n");
}

static void cmd_sign_image(int argc, char **argv)
{
    size_t app_len, sk_len, img_cap, img_len = 0, body_len;
    uint8_t *app = read_file(need(argc, argv, "--app"), &app_len);
    uint8_t *sk = read_file(need(argc, argv, "--key"), &sk_len);
    uint8_t *body, *img;
    apm_t m;
    const char *ver = need(argc, argv, "--version");
    const char *golden_from = opt(argc, argv, "--golden-from");
    uint64_t svn = strtoull(need(argc, argv, "--svn"), NULL, 0);
    const char *v;

    if (sk_len != SB_SECKEY_BYTES) die("--key is not an ML-DSA-44 secret key");
    if (app_len == 0) die("empty application binary");
    memset(&m, 0, sizeof m);
    if (strlen(ver) > 16) die("version string over 16 bytes");
    memcpy(m.version, ver, strlen(ver));
    m.svn = svn;
    m.app_bin_len = (uint32_t)app_len;
    m.tol_bpm_x10 = (uint16_t)((v = opt(argc, argv, "--tol-bpm")) ? atoi(v) : 30);
    m.tol_spo2_x10 = (uint16_t)((v = opt(argc, argv, "--tol-spo2")) ? atoi(v) : 20);
    m.min_live_samples = (uint16_t)((v = opt(argc, argv, "--min-live")) ? atoi(v) : 50);
    m.trial_deadline_ms = (uint16_t)((v = opt(argc, argv, "--deadline")) ? atoi(v) : 15000);

    if (golden_from) {
        dsp_t d;
        dsp_out o;
        dsp_variant dv = strcmp(golden_from, "v10") == 0 ? DSP_V10 : DSP_V11;
        if (strcmp(golden_from, "v10") != 0 && strcmp(golden_from, "v11") != 0) die("--golden-from v10|v11");
        dsp_init(&d, dv);
        for (unsigned i = 0; i < GOLDEN_SAMPLES; i++) dsp_push(&d, golden_red[i], golden_ir[i]);
        dsp_result(&d, &o);
        m.golden_bpm_x10 = o.bpm_x10;
        m.golden_spo2_x10 = o.spo2_x10;
        m.flags = dv == DSP_V10 ? 0 : APM_FLAG_HAS_SPO2;
    } else {
        m.golden_bpm_x10 = (uint16_t)atoi(need(argc, argv, "--golden-bpm"));
        v = opt(argc, argv, "--golden-spo2");
        m.golden_spo2_x10 = v ? (uint16_t)atoi(v) : APM_SPO2_NONE;
        m.flags = v ? APM_FLAG_HAS_SPO2 : 0;
    }
    if (m.golden_spo2_x10 == APM_SPO2_NONE) m.flags &= (uint16_t)~APM_FLAG_HAS_SPO2;
    if ((v = opt(argc, argv, "--build-id"))) {
        if (unhex(v, m.build_id, 20) != 20) die("--build-id needs 20 bytes");
    }
    {
        /* the manifest records the golden trace it was calibrated on */
        shake256incctx st;
        shake256_inc_init(&st);
        shake256_inc_absorb(&st, (const uint8_t *)"apm/v1/golden", 13);
        shake256_inc_absorb(&st, (const uint8_t *)golden_red, sizeof(uint32_t) * GOLDEN_SAMPLES);
        shake256_inc_absorb(&st, (const uint8_t *)golden_ir, sizeof(uint32_t) * GOLDEN_SAMPLES);
        shake256_inc_finalize(&st);
        shake256_inc_squeeze(m.golden_digest, 32, &st);
        shake256_inc_ctx_release(&st);
    }

    body_len = APM_BYTES + app_len;
    body = malloc(body_len);
    img_cap = SB_AUTH_HDR_BYTES + body_len + 4 + SB_SIG_MAX_BYTES;
    img = malloc(img_cap);
    if (!body || !img) die("out of memory");
    apm_build(body, &m);
    memcpy(body + APM_BYTES, app, app_len);
    if (secure_boot_pack(svn, body, body_len, sk, img, img_cap, &img_len) != 0) die("signing failed");
    write_file(need(argc, argv, "--out"), img, img_len);
    printf("{\"svn\":%llu,\"version\":\"%s\",\"golden_bpm_x10\":%u,\"golden_spo2_x10\":%u,"
           "\"app_len\":%zu,\"image_len\":%zu}\n",
           (unsigned long long)svn, ver, m.golden_bpm_x10, m.golden_spo2_x10, app_len, img_len);
}

static void cmd_package(int argc, char **argv)
{
    size_t img_len, kem_len, sk_len, ota_len = 0, total = 0;
    uint8_t *img = read_file(need(argc, argv, "--image"), &img_len);
    uint8_t *kem = read_file(need(argc, argv, "--kem-pk"), &kem_len);
    uint8_t *sk = read_file(need(argc, argv, "--key"), &sk_len);
    uint8_t nonce[32], idb[4];
    uint8_t *ota, *out;
    dlv_t m;
    const char *ver = need(argc, argv, "--version");

    if (kem_len != OTA_KEM_PK_BYTES) die("--kem-pk is not an ML-KEM-512 public key");
    if (sk_len != SB_SECKEY_BYTES) die("--key is not an ML-DSA-44 secret key");
    if (unhex(need(argc, argv, "--nonce"), nonce, 32) != 32) die("--nonce needs 32 bytes");
    if (unhex(need(argc, argv, "--device-id"), idb, 4) != 4) die("--device-id needs 4 bytes (hex, big-endian as printed)");
    if (strlen(ver) > 16) die("version string over 16 bytes");

    memset(&m, 0, sizeof m);
    m.device_id = ((uint32_t)idb[0] << 24) | ((uint32_t)idb[1] << 16) | ((uint32_t)idb[2] << 8) | idb[3];
    memcpy(m.rot_nonce, nonce, 32);
    m.svn = strtoull(need(argc, argv, "--svn"), NULL, 0);
    memcpy(m.version, ver, strlen(ver));
    m.issued_unix = (uint64_t)strtoull(opt(argc, argv, "--issued") ? opt(argc, argv, "--issued") : "0", NULL, 0);

    ota = malloc(OTA_OVERHEAD_BYTES + img_len);
    out = malloc(DLV_PREFIX_BYTES + OTA_OVERHEAD_BYTES + img_len);
    if (!ota || !out) die("out of memory");
    if (ota_pack_signed(img, img_len, kem, ota, OTA_OVERHEAD_BYTES + img_len, &ota_len) != 0) die("OTA packing failed");
    if (dlv_pack(&m, sk, ota, ota_len, out, DLV_PREFIX_BYTES + OTA_OVERHEAD_BYTES + img_len, &total) != 0) die("DLV packing failed");
    write_file(need(argc, argv, "--out"), out, total);
    printf("{\"package_len\":%zu,\"dlv_overhead\":%u,\"ota_overhead\":%u,\"image_len\":%zu,\"ota_digest\":\"",
           total, DLV_PREFIX_BYTES, (unsigned)OTA_OVERHEAD_BYTES, img_len);
    {
        uint8_t dg[32];
        dlv_ota_digest(ota, ota_len, dg);
        phex(dg, 32);
    }
    printf("\"}\n");
}

static void print_str16(const char *s)
{
    for (int i = 0; i < 16 && s[i]; i++) putchar(s[i]);
}

static void cmd_inspect(int argc, char **argv)
{
    size_t n;
    uint8_t *d;

    if (argc < 1) die("inspect FILE");
    d = read_file(argv[0], &n);
    if (n >= 4 && memcmp(d, "SBI1", 4) == 0) {
        uint64_t fw = rot_get64(d + 8), body = rot_get64(d + 16);
        apm_t a;
        apm_status st = body >= APM_BYTES ? apm_parse(d + SB_AUTH_HDR_BYTES, (size_t)body, fw, &a) : APM_E_SHORT;
        printf("{\"kind\":\"SBI1\",\"fw_version\":%llu,\"body_len\":%llu,\"sig_len\":%u,\"total\":%zu,"
               "\"binary_offset_in_image\":%u,\"apm_status\":%d",
               (unsigned long long)fw, (unsigned long long)body, rot_get32(d + SB_AUTH_HDR_BYTES + body), n,
               SB_AUTH_HDR_BYTES + APM_BYTES, (int)st);
        if (st == APM_OK) {
            printf(",\"apm\":{\"version\":\"");
            print_str16(a.version);
            printf("\",\"app_bin_len\":%u,\"golden_bpm_x10\":%u,\"tol_bpm_x10\":%u,\"golden_spo2_x10\":%u,"
                   "\"tol_spo2_x10\":%u,\"min_live_samples\":%u,\"trial_deadline_ms\":%u,\"golden_digest\":\"",
                   a.app_bin_len, a.golden_bpm_x10, a.tol_bpm_x10, a.golden_spo2_x10, a.tol_spo2_x10,
                   a.min_live_samples, a.trial_deadline_ms);
            phex(a.golden_digest, 32);
            printf("\"}");
        }
        printf("}\n");
    } else if (n >= 4 && memcmp(d, "DLV1", 4) == 0) {
        printf("{\"kind\":\"DLV1\",\"device_id\":\"%08x\",\"svn\":%llu,\"version\":\"", rot_get32(d + 8),
               (unsigned long long)rot_get64(d + 48));
        print_str16((const char *)d + 56);
        printf("\",\"rot_nonce\":\"");
        phex(d + 16, 32);
        printf("\",\"ota_len\":%llu,\"ota_digest\":\"", (unsigned long long)rot_get64(d + 72));
        phex(d + 80, 32);
        printf("\",\"total\":%zu,\"dlv_overhead\":%u,\"ota_magic\":\"%.4s\",\"ota_overhead\":%u,\"image_len\":%lld}\n",
               n, DLV_PREFIX_BYTES, n > DLV_PREFIX_BYTES ? (const char *)d + DLV_PREFIX_BYTES : "",
               (unsigned)OTA_OVERHEAD_BYTES, (long long)n - DLV_PREFIX_BYTES - (long long)OTA_OVERHEAD_BYTES);
    } else if (n == ROT_ENR1_BYTES && memcmp(d, "ENR1", 4) == 0) {
        printf("{\"kind\":\"ENR1\",\"device_id\":\"%08x\",\"valid\":%s,\"fingerprint_dsa\":\"", rot_get32(d + 4),
               rot_enr1_verify(d, n) == 0 ? "true" : "false");
        fpr_of(d + 8, ROT_DSA_PK);
        printf("\"}\n");
    } else if (n == ATR2_TOTAL_BYTES && memcmp(d, "ATR2", 4) == 0) {
        atr2_t a;
        if (atr2_parse(d, &a) != 0) die("malformed ATR2");
        printf("{\"kind\":\"ATR2\",\"device_id\":\"%08x\",\"svn\":%llu,\"floor\":%llu,\"slot\":%u,\"trial\":%u,"
               "\"flags\":%u,\"journal_seq\":%u,\"receipt_seq\":%u,\"bits_corrected\":%u,\"worst_block\":%u}\n",
               a.device_id, (unsigned long long)a.svn, (unsigned long long)a.floor, a.active_slot, a.trial_state,
               a.flags, a.journal_seq, a.last_receipt_seq, a.bits_corrected, a.worst_block);
    } else if (n == RCP_TOTAL_BYTES && memcmp(d, "RCP1", 4) == 0) {
        rcp_t r;
        if (rcp_parse(d, &r) != 0) die("malformed RCP1");
        printf("{\"kind\":\"RCP1\",\"seq\":%u,\"device_id\":\"%08x\",\"outcome\":%u,\"reason\":%u,\"slot\":%u,"
               "\"from_svn\":%llu,\"to_svn\":%llu,\"floor_before\":%llu,\"floor_after\":%llu}\n",
               r.seq, r.device_id, r.outcome, r.reason, r.slot, (unsigned long long)r.from_svn,
               (unsigned long long)r.to_svn, (unsigned long long)r.floor_before, (unsigned long long)r.floor_after);
    } else {
        die("unrecognised file");
    }
    free(d);
}

/* bytes of a sector that are neither erased (0xFF) nor accounted for by `used` */
static unsigned unaccounted(const uint8_t *sec, size_t used)
{
    unsigned bad = 0;
    for (size_t i = used; i < ROT_FLASH_SECTOR; i++) {
        if (sec[i] != 0xFF) bad++;
    }
    return bad;
}

static void cmd_inspect_rotdata(int argc, char **argv)
{
    size_t n;
    uint8_t *d;
    unsigned total_bad = 0;

    if (argc < 1) die("inspect-rotdata FILE");
    d = read_file(argv[0], &n);
    if (n != ROT_REGION_DATA_SIZE) die("a rot_data dump is exactly 192 KB");

    printf("{\"kind\":\"rot_data\",\"sectors\":[\n");
    for (unsigned s = 0; s < ROT_DATA_SECTORS; s++) {
        const uint8_t *sec = d + s * ROT_FLASH_SECTOR;
        const char *name = "spare";
        size_t used = 0;
        int blank = rot_all_byte(sec, ROT_FLASH_SECTOR, 0xFF);
        unsigned bad;

        if (s == ROT_SECTOR_HLP1) { name = "HLP1"; used = ROT_HLP_BYTES; }
        else if (s == ROT_SECTOR_ANC1) { name = "ANC1"; used = 1352; }
        else if (s == ROT_SECTOR_RBC1_A || s == ROT_SECTOR_RBC1_B) { name = "RBC1"; used = 64; }
        else if (s == ROT_SECTOR_JNL1_A || s == ROT_SECTOR_JNL1_B) { name = "JNL1"; used = 128; }
        else if (s == ROT_SECTOR_MBX1) { name = "MBX1"; used = 12 + 64 + 4; }
        else if (s == ROT_SECTOR_ATR2) { name = "ATR2"; used = ATR2_TOTAL_BYTES; }
        else if (s >= ROT_SECTOR_RCP1_FIRST && s < ROT_SECTOR_RCP1_FIRST + ROT_RCP1_RING) { name = "RCP1"; used = RCP_TOTAL_BYTES; }

        if (!blank && s >= ROT_SECTOR_SPARE_FIRST) used = 0;
        bad = blank ? 0 : unaccounted(sec, used);
        if (!blank && used && memcmp(sec, name, 4) != 0 && strcmp(name, "RBC1") != 0 && strcmp(name, "spare") != 0) {
            bad += 1;
        }
        total_bad += bad;

        printf("  {\"sector\":%u,\"record\":\"%s\",\"present\":%s,\"unaccounted_bytes\":%u", s, name,
               blank ? "false" : "true", bad);
        if (!blank && strcmp(name, "HLP1") == 0) {
            printf(",\"device_id\":\"%08x\",\"pairs_selected\":%u,\"pairs_available\":%u,\"flags\":%u,"
                   "\"crc_ok\":%s,\"fingerprint_dsa\":\"",
                   rot_get32(sec + 24), rot_get16(sec + 20), rot_get16(sec + 22), rot_get16(sec + 6),
                   rot_crc32(0, sec, 2656) == rot_get32(sec + 2656) ? "true" : "false");
            phex(sec + 32, 32);
            printf("\"");
        } else if (!blank && strcmp(name, "ANC1") == 0) {
            printf(",\"vendor_key_fingerprint\":\"");
            fpr_of(sec + 8, ROT_DSA_PK);
            printf("\",\"tag\":\"");
            phex(sec + 1320, 32);
            printf("\"");
        } else if (!blank && strcmp(name, "RBC1") == 0) {
            printf(",\"seq\":%u,\"cnt\":%llu,\"tag\":\"", rot_get32(sec + 4), (unsigned long long)rot_get64(sec + 8));
            phex(sec + 16, 32);
            printf("\"");
        } else if (!blank && strcmp(name, "JNL1") == 0) {
            printf(",\"seq\":%u,\"active\":%u,\"status\":[%u,%u],\"trial\":%u,\"nonce_outstanding\":%u,"
                   "\"receipt_seq\":%u", rot_get32(sec + 4), sec[8], sec[9], sec[10], sec[11], sec[13],
                   rot_get32(sec + 56));
        } else if (!blank && strcmp(name, "RCP1") == 0) {
            printf(",\"seq\":%u,\"outcome\":%u,\"reason\":%u", rot_get32(sec + 4), sec[12], sec[13]);
        }
        printf("}%s\n", s + 1 < ROT_DATA_SECTORS ? "," : "");
    }
    printf("],\"unaccounted_bytes_total\":%u,\"holds_only_public_records\":%s}\n", total_bad,
           total_bad == 0 ? "true" : "false");
    free(d);
}

static void cmd_verify_image(int argc, char **argv)
{
    size_t pk_len, n;
    uint8_t *pk = read_file(need(argc, argv, "--pk"), &pk_len);
    uint8_t *img;
    uint64_t body;
    uint32_t sig_len;

    if (argc < 1) die("verify-image --pk F IMAGE");
    img = read_file(argv[argc - 1], &n);
    if (pk_len != SB_PUBKEY_BYTES || n < SB_AUTH_HDR_BYTES + 4 || memcmp(img, "SBI1", 4) != 0) exit(1);
    body = rot_get64(img + 16);
    if (body > n || SB_AUTH_HDR_BYTES + body + 4 > n) exit(1);
    sig_len = rot_get32(img + SB_AUTH_HDR_BYTES + body);
    if (sig_len != SB_SIG_MAX_BYTES || SB_AUTH_HDR_BYTES + body + 4 + sig_len > n) exit(1);
    exit(PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(img + SB_AUTH_HDR_BYTES + body + 4, sig_len, img,
                                                  SB_AUTH_HDR_BYTES + (size_t)body, pk) == 0 ? 0 : 1);
}

static void cmd_issue_cert(int argc, char **argv)
{
    size_t ca_len, e_len, sig_len = 0;
    uint8_t *ca = read_file(need(argc, argv, "--ca-sk"), &ca_len);
    uint8_t *e = read_file(need(argc, argv, "--enr1"), &e_len);
    uint8_t cert[8 + ROT_DSA_PK + 4 + ROT_DSA_SIG];

    if (ca_len != SB_SECKEY_BYTES) die("--ca-sk is not an ML-DSA-44 secret key");
    if (rot_enr1_verify(e, e_len) != 0) die("ENR1 proof of possession does not verify");

    memcpy(cert, "ATC1", 4);
    memcpy(cert + 4, e + 4, 4);               /* device id, as in ENR1 */
    memcpy(cert + 8, e + 8, ROT_DSA_PK);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(cert + 8 + ROT_DSA_PK + 4, &sig_len, cert,
                                                    8 + ROT_DSA_PK, ca) != 0) die("signing failed");
    rot_put32(cert + 8 + ROT_DSA_PK, (uint32_t)sig_len);
    write_file(need(argc, argv, "--out"), cert, 8 + ROT_DSA_PK + 4 + sig_len);
    printf("{\"device_id\":\"%08x\",\"cert_len\":%zu}\n", rot_get32(e + 4), 8 + ROT_DSA_PK + 4 + sig_len);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: vendor_cli keygen|keygen-device|sign-image|package|inspect|inspect-rotdata|issue-cert ...\n");
        return 2;
    }
    rot_rng_init(os_raw, NULL);
    if (strcmp(argv[1], "keygen") == 0) cmd_keygen(argc - 2, argv + 2);
    else if (strcmp(argv[1], "keygen-device") == 0) cmd_keygen_device(argc - 2, argv + 2);
    else if (strcmp(argv[1], "sign-image") == 0) cmd_sign_image(argc - 2, argv + 2);
    else if (strcmp(argv[1], "package") == 0) cmd_package(argc - 2, argv + 2);
    else if (strcmp(argv[1], "inspect") == 0) cmd_inspect(argc - 2, argv + 2);
    else if (strcmp(argv[1], "inspect-rotdata") == 0) cmd_inspect_rotdata(argc - 2, argv + 2);
    else if (strcmp(argv[1], "verify-image") == 0) cmd_verify_image(argc - 2, argv + 2);
    else if (strcmp(argv[1], "issue-cert") == 0) cmd_issue_cert(argc - 2, argv + 2);
    else {
        fprintf(stderr, "vendor_cli: unknown command %s\n", argv[1]);
        return 2;
    }
    return 0;
}
