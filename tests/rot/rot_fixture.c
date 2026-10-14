#include "rot_fixture.h"

#include "rot/rot_counter.h"
#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_keys.h"
#include "rot/rot_rng.h"
#include "rot/rot_receipts.h"
#include "rot/rot_trial.h"

#include "apm/apm.h"
#include "attest/attest2.h"
#include "dlv/dlv.h"
#include "ota/ota.h"
#include "puf/puf_sim.h"
#include "secure_boot/secure_boot.h"

#include <stdio.h>
#include <string.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

static void copy_ver(char dst[16], const char *ver)
{
    size_t n = strlen(ver);
    memset(dst, 0, 16);
    memcpy(dst, ver, n > 16 ? 16 : n);
}

static void seeded_keypair(uint8_t tag, uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(tag * 17 + i);
    }
    rot_rng_seed_once(seed, sizeof seed);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    rot_rng_reset();
}

void fx_init(fx_t *f, uint32_t puf_id)
{
    memset(f, 0, sizeof *f);
    flash_model_init(&f->fm, ROT_FLASH_TOTAL);
    flash_model_platform(&f->fm, &f->p);
    f->puf_id = puf_id;
    f->noise_ppm = 20000; /* 2 % */
    f->reset_cause = RC_POR;
    rot_rng_init(f->p.trng_raw, f->p.ctx);
    seeded_keypair(1, f->vendor_pk, f->vendor_sk);
    seeded_keypair(2, f->other_pk, f->other_sk);
}

void fx_free(fx_t *f)
{
    flash_model_free(&f->fm);
}

static void read_window(fx_t *f, uint32_t id, uint8_t *w)
{
    uint8_t noise[8];
    f->boot_no++;
    memcpy(noise, "noise", 5);
    noise[5] = (uint8_t)f->boot_no;
    noise[6] = (uint8_t)(f->boot_no >> 8);
    noise[7] = (uint8_t)(f->boot_no >> 16);
    puf_sim_response_noisy(id, f->noise_ppm, noise, sizeof noise, w, ROT_BOOT_WINDOW_BYTES);
}

int fx_enroll(fx_t *f)
{
    static uint8_t reads[5][ROT_BOOT_WINDOW_BYTES];
    const uint8_t *rp[5];
    rot_enroll_params prm = { 0, 0x20070000u, 100 };
    rot_enroll_result res;
    int rc;

    for (int i = 0; i < 5; i++) {
        read_window(f, f->puf_id, reads[i]);
        rp[i] = reads[i];
    }
    rc = rot_enroll_run(&f->p, rp, 5, f->vendor_pk, &prm, &res);
    if (rc == 0) {
        f->device_id = res.device_id;
        memcpy(f->enr1, res.enr1, sizeof f->enr1);
        memcpy(f->dev_pk_dsa, res.enr1 + 8, ROT_DSA_PK);
        memcpy(f->dev_pk_kem, res.enr1 + 8 + ROT_DSA_PK, ROT_KEM_PK);
    }
    return rc;
}

static int boot_with(fx_t *f, uint32_t id, int puf_retry)
{
    static rot_boot_in in;
    memset(&in, 0, sizeof in);
    read_window(f, id, in.window);
    in.reset_cause = f->reset_cause;
    in.puf_retry = (uint8_t)puf_retry;
    in.die_temp_x10 = 250;
    memcpy(in.build_id, "fixture-build-id-000", 20);
    rot_boot_run(&f->p, &in, &f->out);
    f->reset_cause = RC_PSTATE;
    return f->out.action == BOOT_CHAIN ? 0 : (int)f->out.action;
}

int fx_boot(fx_t *f)
{
    return boot_with(f, f->puf_id, 0);
}

int fx_boot_wrong_chip(fx_t *f, uint32_t other, int puf_retry)
{
    return boot_with(f, other, puf_retry);
}

size_t fx_image(const fx_t *f, uint8_t *out, size_t cap, uint64_t svn, const char *ver,
                uint16_t golden_bpm_x10, uint16_t golden_spo2_x10, size_t app_len,
                const uint8_t *signing_sk)
{
    static uint8_t body[APM_BYTES + 16384];
    apm_t m;
    size_t out_len = 0;
    (void)f;

    memset(&m, 0, sizeof m);
    m.flags = golden_spo2_x10 == APM_SPO2_NONE ? 0 : APM_FLAG_HAS_SPO2;
    copy_ver(m.version, ver);
    m.svn = svn;
    m.app_bin_len = (uint32_t)app_len;
    m.golden_bpm_x10 = golden_bpm_x10;
    m.tol_bpm_x10 = 30;
    m.golden_spo2_x10 = golden_spo2_x10;
    m.tol_spo2_x10 = 20;
    m.min_live_samples = 50;
    m.trial_deadline_ms = 15000;
    memset(m.golden_digest, 0x77, 32);
    memset(m.build_id, 0x42, 20);
    apm_build(body, &m);
    for (size_t i = 0; i < app_len; i++) {
        body[APM_BYTES + i] = (uint8_t)((i * 131 + svn * 7) >> 2);
    }
    if (secure_boot_pack(svn, body, APM_BYTES + app_len, signing_sk, out, cap, &out_len) != 0) {
        return 0;
    }
    return out_len;
}

void fx_put_slot(fx_t *f, int slot, const uint8_t *img, size_t len)
{
    uint32_t off = ROT_SLOT_OFF(slot);
    memset(f->fm.mem + off, 0xFF, ROT_REGION_APP_A_SIZE);
    memcpy(f->fm.mem + off, img, len);
}

static void put_mbx(fx_t *f, uint8_t type, const uint8_t *payload, uint16_t len)
{
    uint8_t rec[128];
    size_t n = rot_mailbox_build(rec, ++f->mbx_seq, type, payload, len);
    uint32_t off = ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1);
    memset(f->fm.mem + off, 0xFF, ROT_FLASH_SECTOR);
    memcpy(f->fm.mem + off, rec, n);
}

void fx_mbx_attest(fx_t *f, const uint8_t nonce[32])
{
    put_mbx(f, MBX_ATTEST_REQ, nonce, 32);
}

void fx_mbx_health(fx_t *f, uint64_t svn, uint16_t bpm_x10, uint16_t spo2_x10, uint8_t part_id,
                   uint8_t sensor_ok, uint16_t live)
{
    rot_hev_t h;
    uint8_t b[HEV1_BYTES];
    memset(&h, 0, sizeof h);
    h.svn = svn;
    h.golden_bpm_x10 = bpm_x10;
    h.golden_spo2_x10 = spo2_x10;
    h.beats = 25;
    h.mean_rr_ms = 833;
    h.part_id = part_id;
    h.sensor_ok = sensor_ok;
    h.live_samples = live;
    h.selftest_ms = 400;
    h.verdict = 1;
    rot_hev_build(b, &h);
    put_mbx(f, MBX_HEALTH_REPORT, b, HEV1_BYTES);
}

void fx_mbx_install(fx_t *f, uint32_t pkg_len, uint32_t pkg_crc)
{
    uint8_t pl[8];
    pl[0] = (uint8_t)pkg_len; pl[1] = (uint8_t)(pkg_len >> 8);
    pl[2] = (uint8_t)(pkg_len >> 16); pl[3] = (uint8_t)(pkg_len >> 24);
    pl[4] = (uint8_t)pkg_crc; pl[5] = (uint8_t)(pkg_crc >> 8);
    pl[6] = (uint8_t)(pkg_crc >> 16); pl[7] = (uint8_t)(pkg_crc >> 24);
    put_mbx(f, MBX_INSTALL_REQ, pl, 8);
}

size_t fx_package(const fx_t *f, uint8_t *out, size_t cap, const uint8_t *image, size_t image_len,
                  uint32_t device_id, const uint8_t nonce[32], uint64_t svn, const char *ver,
                  const uint8_t kem_pk[ROT_KEM_PK], const uint8_t *sign_sk)
{
    static uint8_t ota[ROT_REGION_STAGING_SIZE / 8];
    size_t ota_len = 0, total = 0;
    dlv_t m;
    (void)f;

    if (ota_pack_signed(image, image_len, kem_pk, ota, sizeof ota, &ota_len) != 0) {
        return 0;
    }
    memset(&m, 0, sizeof m);
    m.device_id = device_id;
    memcpy(m.rot_nonce, nonce, 32);
    m.svn = svn;
    copy_ver(m.version, ver);
    m.issued_unix = 1760400000;
    if (dlv_pack(&m, sign_sk, ota, ota_len, out, cap, &total) != 0) {
        return 0;
    }
    return total;
}

void fx_stage_and_request(fx_t *f, const uint8_t *pkg, size_t len)
{
    memset(f->fm.mem + ROT_REGION_STAGING_OFF, 0xFF, ROT_REGION_STAGING_SIZE);
    memcpy(f->fm.mem + ROT_REGION_STAGING_OFF, pkg, len);
    fx_mbx_install(f, (uint32_t)len, rot_crc32(0, pkg, len));
}

int fx_attest(fx_t *f, const uint8_t verifier_nonce[32], uint8_t rot_nonce[32])
{
    atr2_t a;
    fx_mbx_attest(f, verifier_nonce);
    if (fx_boot(f) != 0) {
        return -1;
    }
    if (!(f->out.hnd.flags & HND_F_ATTEST) || f->out.hnd.atr2_len != ATR2_TOTAL_BYTES) {
        return -2;
    }
    if (atr2_verify(f->out.hnd.atr2, ATR2_TOTAL_BYTES, f->dev_pk_dsa) != 0) {
        return -3;
    }
    if (atr2_parse(f->out.hnd.atr2, &a) != 0 || memcmp(a.verifier_nonce, verifier_nonce, 32) != 0) {
        return -4;
    }
    memcpy(rot_nonce, a.rot_nonce, 32);
    return 0;
}

static int derive_keys(fx_t *f, rot_keys *k)
{
    /* reconstruct the way the boot does, for test-side record access */
    static uint8_t w[ROT_BOOT_WINDOW_BYTES];
    rot_hlp_t h;
    uint8_t uds[32];
    if (rot_hlp_read(&f->p, &h) != ROT_HLP_OK) {
        return -1;
    }
    read_window(f, f->puf_id, w);
    if (rot_puf_reconstruct(w, &h, uds, NULL) != 0) {
        return -2;
    }
    return rot_keys_derive(uds, k);
}

int fx_rederive(fx_t *f, rot_keys *k)
{
    return derive_keys(f, k);
}

int fx_set_journal(fx_t *f, const rot_journal_t *want)
{
    static rot_keys k;
    rot_journal_t cur;
    if (derive_keys(f, &k) != 0 || rot_journal_load(&f->p, k.journal_key, &cur) != 0) {
        return -1;
    }
    cur.active = want->active;
    cur.status[0] = want->status[0];
    cur.status[1] = want->status[1];
    cur.trial_state = want->trial_state;
    cur.trial_slot = want->trial_slot;
    cur.trial_svn = want->trial_svn;
    cur.nonce_state = want->nonce_state;
    memcpy(cur.nonce, want->nonce, 32);
    return rot_journal_commit(&f->p, k.journal_key, &cur);
}

int fx_journal(fx_t *f, rot_journal_t *j)
{
    static rot_keys k;
    if (derive_keys(f, &k) != 0) {
        return -1;
    }
    return rot_journal_load(&f->p, k.journal_key, j);
}

int fx_floor(fx_t *f, uint64_t *floor)
{
    static rot_keys k;
    if (derive_keys(f, &k) != 0) {
        return -1;
    }
    return rot_counter_read(&f->p, k.rb_key, floor);
}

int fx_receipt(fx_t *f, uint32_t seq, uint8_t obj[RCP_TOTAL_BYTES], rcp_t *r)
{
    if (rot_receipts_read(&f->p, seq, obj) != ROT_RCPS_OK) {
        return -1;
    }
    if (rcp_verify(obj, RCP_TOTAL_BYTES, f->dev_pk_dsa) != 0) {
        return -2;
    }
    return rcp_parse(obj, r);
}

void fx_save(fx_t *f, uint8_t *buf)
{
    memcpy(buf, f->fm.mem, f->fm.size);
}

void fx_restore(fx_t *f, const uint8_t *buf)
{
    memcpy(f->fm.mem, buf, f->fm.size);
    flash_model_power_on(&f->fm);
}
