#include "rot/rot_enroll.h"

#include "rot/rot_anchor.h"
#include "rot/rot_counter.h"
#include "rot/rot_journal.h"
#include "rot/rot_rng.h"
#include "rot/rot_util.h"

#include "puf/vn_debias.h"

#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */

#include <string.h>

int rot_enroll_run(const rot_platform *p,
                   const uint8_t *const *reads, unsigned n_reads,
                   const uint8_t vendor_pk[ROT_DSA_PK],
                   const rot_enroll_params *prm,
                   rot_enroll_result *out)
{
    static uint8_t ref[ROT_HLP_WINDOW_BYTES], stable[ROT_HLP_WINDOW_BYTES];
    static rot_hlp_t hlp;
    static rot_keys keys;
    uint8_t w[ROT_HLP_W_BYTES], rnd[32], uds[ROT_UDS_BYTES];
    uint8_t body[ROT_ENR1_BODY];
    fuzzy_params fp = { ROT_HLP_BLOCKS, ROT_HLP_REP };
    unsigned avail = 0;
    int rc = ROT_ENR_OK;

    if (!reads || n_reads == 0 || n_reads > ROT_ENROLL_MAX_READS || (n_reads & 1u) == 0) {
        return ROT_ENR_ARGS;
    }

    rot_rng_init(p->trng_raw, p->ctx);
    memset(&hlp, 0, sizeof hlp);

    if (vn_majority(reads, n_reads, ROT_HLP_WINDOW_BYTES, ref) != 0) {
        return ROT_ENR_ARGS;
    }
    if (prm->flags & ROT_HLP_F_STABLE) {
        vn_stable_mask(reads, n_reads, ROT_HLP_WINDOW_BYTES, stable);
    }
    if (vn_select_pairs(ref, ROT_HLP_WINDOW_BYTES, (prm->flags & ROT_HLP_F_STABLE) ? stable : NULL,
                        ROT_HLP_PAIRS, hlp.bitmap, &avail) != 0) {
        rc = ROT_ENR_FEW_PAIRS;
        if (out) {
            out->pairs_available = avail;
        }
        goto done;
    }
    if (vn_extract(ref, ROT_HLP_WINDOW_BYTES, hlp.bitmap, ROT_HLP_PAIRS, w) != 0) {
        rc = ROT_ENR_ARGS;
        goto done;
    }
    if (rot_rng_bytes(rnd, sizeof rnd) != 0) {
        rc = ROT_ENR_RNG;
        goto done;
    }
    if (fuzzy_gen(fp, w, sizeof w, rnd, sizeof rnd, hlp.helper, sizeof hlp.helper,
                  uds, sizeof uds) != 0) {
        rc = ROT_ENR_ARGS;
        goto done;
    }
    if (rot_keys_derive(uds, &keys) != 0) {
        rc = ROT_ENR_KEYGEN;
        goto done;
    }

    hlp.flags = prm->flags;
    hlp.window_addr = prm->window_addr;
    hlp.pairs_available = (uint16_t)(avail > 0xFFFFu ? 0xFFFFu : avail);
    hlp.device_id = keys.device_id;
    hlp.t_off_ms = prm->t_off_ms;
    memcpy(hlp.fpr_dsa, keys.fpr_dsa, 32);
    memcpy(hlp.fpr_kem, keys.fpr_kem, 32);

    /* proof of possession */
    memcpy(body, "ENR1", 4);
    rot_put32(body + 4, keys.device_id);
    memcpy(body + 8, keys.pk_dsa, ROT_DSA_PK);
    memcpy(body + 8 + ROT_DSA_PK, keys.pk_kem, ROT_KEM_PK);
    if (out) {
        size_t sig_len = 0;
        memcpy(out->enr1, body, sizeof body);
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(out->enr1 + ROT_ENR1_BODY + 4, &sig_len,
                                                        body, sizeof body, keys.sk_dsa) != 0
            || sig_len != ROT_DSA_SIG) {
            rc = ROT_ENR_KEYGEN;
            goto done;
        }
        rot_put32(out->enr1 + ROT_ENR1_BODY, (uint32_t)sig_len);
        out->device_id = keys.device_id;
        memcpy(out->fpr_dsa, keys.fpr_dsa, 32);
        memcpy(out->fpr_kem, keys.fpr_kem, 32);
        out->pairs_available = avail;
    }

    /* records; HLP1 last so an interrupted enrollment can be redone */
    {
        rot_journal_t j;
        memset(&j, 0, sizeof j);
        j.active = 0;
        j.status[0] = SLOT_GOOD;
        j.status[1] = SLOT_EMPTY;

        if (rot_anchor_seal(p, keys.anchor_key, vendor_pk) != 0
            || rot_counter_enroll(p, keys.rb_key, 1) != ROT_CTR_OK
            || rot_journal_enroll(p, keys.journal_key, &j) != ROT_JNL_OK
            || rot_hlp_write(p, &hlp) != ROT_HLP_OK) {
            rc = ROT_ENR_IO;
        }
    }

done:
    rot_wipe(uds, sizeof uds);
    rot_wipe(w, sizeof w);
    rot_wipe(rnd, sizeof rnd);
    rot_keys_wipe(&keys);
    return rc;
}

int rot_enr1_verify(const uint8_t *enr1, size_t len)
{
    if (len != ROT_ENR1_BYTES || memcmp(enr1, "ENR1", 4) != 0
        || rot_get32(enr1 + ROT_ENR1_BODY) != ROT_DSA_SIG) {
        return -1;
    }
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(enr1 + ROT_ENR1_BODY + 4, ROT_DSA_SIG,
                                                    enr1, ROT_ENR1_BODY, enr1 + 8) == 0 ? 0 : -1;
}
