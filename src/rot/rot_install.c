#include "rot/rot_install.h"

#include "rot/rot_crc32.h"
#include "rot/rot_flash.h"
#include "rot/rot_receipts.h"
#include "rot/rot_util.h"

#include "dlv/dlv.h"
#include "ota/ota.h"
#include "ota/ota_aead.h"
#include "fips202.h"

#include <string.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define CHUNK ROT_FLASH_SECTOR

typedef struct {
    const rot_platform *p;
    const uint8_t *ota;
} read_ctx;

static int read_cb(void *ctx, uint64_t off, uint8_t *buf, size_t n)
{
    const read_ctx *r = ctx;
    memcpy(buf, r->ota + off, n);
    return 0;
}

static void raw_digest(const uint8_t *data, size_t len, uint8_t out[32])
{
    shake256incctx st;
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)"dlv/v1/raw", 10);
    shake256_inc_absorb(&st, data, len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, 32, &st);
    shake256_inc_ctx_release(&st);
}

/* Write a REFUSED receipt and commit the journal. */
static int refuse(rot_ctx *c, rot_journal_t *j, int reason, const dlv_t *m,
                  const uint8_t pkg_digest[32], const uint8_t image_digest[32],
                  rot_install_result *out)
{
    rcp_t r;
    uint64_t active_svn = 0;

    memset(&r, 0, sizeof r);
    if (j->status[j->active] == SLOT_GOOD) {
        rot_slot_header_svn(c->p, j->active, &active_svn);
    }
    r.outcome = RCP_REFUSED;
    r.reason = (uint8_t)reason;
    r.slot = j->active;
    r.from_svn = active_svn;
    r.floor_before = c->floor;
    r.floor_after = c->floor;
    memcpy(r.package_digest, pkg_digest, 32);
    if (image_digest) {
        memcpy(r.image_digest, image_digest, 32);
    }
    if (m) {
        r.to_svn = m->svn;
        memcpy(r.rot_nonce, m->rot_nonce, 32);
        memcpy(r.version, m->version, 16);
    }
    if (rot_receipts_issue(c->p, c->k, j, &r) != ROT_RCPS_OK
        || rot_journal_commit(c->p, c->k->journal_key, j) != ROT_JNL_OK) {
        return ROT_INST_IO;
    }
    out->refused = 1;
    out->reason = reason;
    memcpy(out->pkg_digest, pkg_digest, 32);
    return ROT_INST_OK;
}

static int wipe_slot(const rot_platform *p, int slot, uint64_t used)
{
    uint32_t sectors = (uint32_t)((used + CHUNK - 1) / CHUNK);
    if (sectors == 0) {
        sectors = 1;
    }
    return rot_flash_erase(p, ROT_SLOT_OFF(slot), sectors * CHUNK);
}

int rot_install_run(rot_ctx *c, rot_journal_t *j, const rot_mbx_t *req,
                    unsigned attempts, rot_install_result *out)
{
    const rot_platform *p = c->p;
    const uint8_t *stage = p->flash_xip(p->ctx, ROT_REGION_STAGING_OFF);
    uint32_t pkg_len, pkg_crc;
    uint8_t pkg_digest[32];
    dlv_t m;
    dlv_status ds;
    read_ctx rc = { p, NULL };
    int target = 1 - j->active;

    memset(out, 0, sizeof *out);
    memset(pkg_digest, 0, sizeof pkg_digest);
    if (!stage || req->type != MBX_INSTALL_REQ || req->len != 8) {
        return ROT_INST_IO;
    }
    pkg_len = rot_get32(req->payload);
    pkg_crc = rot_get32(req->payload + 4);

    if (attempts >= ROT_INSTALL_MAX_ATTEMPTS) {
        raw_digest(stage, pkg_len > ROT_REGION_STAGING_SIZE ? ROT_REGION_STAGING_SIZE : pkg_len,
                   pkg_digest);
        return refuse(c, j, RCP_REASON_PKG_MALFORMED, NULL, pkg_digest, NULL, out);
    }

    /* the size claim is untrusted: nothing below reads beyond the staging region */
    if (pkg_len <= DLV_PREFIX_BYTES || pkg_len > ROT_REGION_STAGING_SIZE) {
        raw_digest(stage, pkg_len > ROT_REGION_STAGING_SIZE ? ROT_REGION_STAGING_SIZE : pkg_len,
                   pkg_digest);
        return refuse(c, j, RCP_REASON_PKG_MALFORMED, NULL, pkg_digest, NULL, out);
    }
    if (rot_crc32(0, stage, pkg_len) != pkg_crc) {
        raw_digest(stage, pkg_len, pkg_digest);
        return refuse(c, j, RCP_REASON_PKG_MALFORMED, NULL, pkg_digest, NULL, out);
    }

    rc.ota = stage + DLV_PREFIX_BYTES;
    memset(&m, 0, sizeof m);
    ds = dlv_check(stage, pkg_len, c->vendor_pk, c->k->device_id,
                   j->nonce_state == NONCE_OUTSTANDING ? j->nonce : NULL, c->floor,
                   read_cb, &rc, &m);
    if (ds != DLV_OK) {
        /* the digest field is only meaningful once the signature verified */
        if (ds == DLV_E_MALFORMED || ds == DLV_E_UNKNOWN_SIGNER) {
            raw_digest(stage, pkg_len, pkg_digest);
            return refuse(c, j, (int)ds, NULL, pkg_digest, NULL, out);
        }
        memcpy(pkg_digest, m.ota_digest, 32);
        return refuse(c, j, (int)ds, &m, pkg_digest, NULL, out);
    }
    memcpy(pkg_digest, m.ota_digest, 32);

    /* OTA1 framing */
    {
        const uint8_t *ota = rc.ota;
        uint64_t payload_len;

        if (m.ota_len <= OTA_OVERHEAD_BYTES || memcmp(ota, "OTA1", 4) != 0 || ota[4] != 1) {
            return refuse(c, j, RCP_REASON_PKG_MALFORMED, &m, pkg_digest, NULL, out);
        }
        payload_len = rot_get64(ota + OTA_HDR_BYTES + OTA_KEM_CT_BYTES + OTA_NONCE_BYTES);
        if (payload_len == 0 || payload_len > ROT_REGION_APP_A_SIZE
            || m.ota_len != OTA_PREFIX_BYTES + payload_len + OTA_TAG_BYTES) {
            return refuse(c, j, RCP_REASON_PKG_MALFORMED, &m, pkg_digest, NULL, out);
        }

        {
            const uint8_t *kem_ct = ota + OTA_HDR_BYTES;
            const uint8_t *nonce = kem_ct + OTA_KEM_CT_BYTES;
            const uint8_t *ct = ota + OTA_PREFIX_BYTES;
            const uint8_t *tag = ct + payload_len;
            uint8_t ss[OTA_KEM_SS_BYTES], ek[OTA_AEAD_KEY_BYTES], mk[OTA_AEAD_KEY_BYTES];
            uint8_t want[OTA_AEAD_TAG_BYTES];
            ota_aead_mac_ctx mac;
            ota_aead_stream ks;
            static uint8_t buf[CHUNK];
            rot_slot_info info;
            int vrc;

            /* U13 */
            PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, kem_ct, c->k->sk_kem);
            ota_aead_derive_keys(ss, sizeof ss, ek, mk);
            rot_wipe(ss, sizeof ss);

            ota_aead_mac_init(&mac, mk, nonce, payload_len);
            for (uint64_t off = 0; off < payload_len; off += CHUNK) {
                size_t n = payload_len - off < CHUNK ? (size_t)(payload_len - off) : CHUNK;
                ota_aead_mac_update(&mac, ct + off, n);
                p->wdt_feed(p->ctx);
            }
            ota_aead_mac_final(&mac, want);
            rot_wipe(mk, sizeof mk);
            if (!ota_aead_tag_equal(want, tag)) {
                rot_wipe(ek, sizeof ek);
                return refuse(c, j, RCP_REASON_PKG_MAC_FAILED, &m, pkg_digest, NULL, out);
            }

            /* U14: the nonce is spent before anything is written */
            j->nonce_state = NONCE_NONE;
            memset(j->nonce, 0, sizeof j->nonce);
            j->status[target] = SLOT_EMPTY;
            if (rot_journal_commit(p, c->k->journal_key, j) != ROT_JNL_OK) {
                rot_wipe(ek, sizeof ek);
                return ROT_INST_IO;
            }

            ota_aead_stream_init(&ks, ek, nonce);
            rot_wipe(ek, sizeof ek);
            for (uint64_t off = 0; off < payload_len; off += CHUNK) {
                size_t n = payload_len - off < CHUNK ? (size_t)(payload_len - off) : CHUNK;
                memcpy(buf, ct + off, n);
                ota_aead_stream_xor(&ks, buf, n);
                if (rot_flash_put(p, ROT_SLOT_OFF(target) + (uint32_t)off, buf, n) != 0) {
                    ota_aead_stream_release(&ks);
                    rot_wipe(buf, sizeof buf);
                    return ROT_INST_IO;
                }
                p->wdt_feed(p->ctx);
            }
            ota_aead_stream_release(&ks);
            rot_wipe(buf, sizeof buf);

            /* U15 */
            memset(&info, 0, sizeof info);
            vrc = rot_slot_verify(c, target, &info);
            if (vrc == ROT_SLOT_COUNTER) {
                return ROT_INST_COUNTER;
            }
            if (vrc == 0 && info.svn != m.svn) {
                vrc = RCP_REASON_IMG_SVN_MISMATCH;
            }
            if (vrc != 0) {
                int reason = vrc > 0 ? vrc : RCP_REASON_IMG_MALFORMED;
                if (wipe_slot(p, target, payload_len) != 0) {
                    return ROT_INST_IO;
                }
                return refuse(c, j, reason, &m, pkg_digest, NULL, out);
            }

            /* U16 */
            j->status[target] = SLOT_TRIAL;
            j->trial_state = TRIAL_RUNNING;
            j->trial_slot = (uint8_t)target;
            j->trial_svn = m.svn;
            if (rot_journal_commit(p, c->k->journal_key, j) != ROT_JNL_OK) {
                return ROT_INST_IO;
            }
            out->trial_started = 1;
            out->slot = (uint8_t)target;
            out->svn = m.svn;
            memcpy(out->pkg_digest, pkg_digest, 32);
            return ROT_INST_OK;
        }
    }
}
