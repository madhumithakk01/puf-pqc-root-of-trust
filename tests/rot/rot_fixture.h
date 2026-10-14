#ifndef ROT_FIXTURE_H
#define ROT_FIXTURE_H

/*
 * Host fixture for the RoT core: a simulated device (flash model plus a
 * simulated PUF window with per-boot noise), a vendor with signing keys, and
 * helpers that play the application's part (mailbox writes, staging writes).
 */

#include "flash_model.h"

#include "rot/rot_boot.h"
#include "rot/rot_enroll.h"
#include "rot/rot_journal.h"
#include "rot/rot_keys.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_receipt.h"

typedef struct {
    flash_model fm;
    rot_platform p;
    uint32_t puf_id;          /* simulated chip identity */
    uint32_t noise_ppm;       /* per-boot bit error rate of the window */
    uint32_t boot_no;         /* varies the noise */
    uint8_t  vendor_pk[ROT_DSA_PK];
    uint8_t  vendor_sk[ROT_DSA_SK];
    uint8_t  other_pk[ROT_DSA_PK];  /* an unrelated signer */
    uint8_t  other_sk[ROT_DSA_SK];
    /* device facts learned at enrollment */
    uint32_t device_id;
    uint8_t  dev_pk_dsa[ROT_DSA_PK];
    uint8_t  dev_pk_kem[ROT_KEM_PK];
    uint8_t  enr1[ROT_ENR1_BYTES];
    uint32_t mbx_seq;
    rot_boot_out out;         /* result of the latest boot */
    uint8_t  reset_cause;     /* cause reported to the next boot */
} fx_t;

void fx_init(fx_t *f, uint32_t puf_id);
void fx_free(fx_t *f);

/* Enroll with five noisy reads. Returns the rot_enroll_run code. */
int fx_enroll(fx_t *f);

/* One boot: noisy window, rot_boot_run, result in f->out. Returns the action. */
int fx_boot(fx_t *f);

/* A boot with a window from a different chip (key will not reconstruct). */
int fx_boot_wrong_chip(fx_t *f, uint32_t other_puf_id, int puf_retry);

/* Build a signed SBI1 image for `svn` with an APM1 manifest. Returns its length. */
size_t fx_image(const fx_t *f, uint8_t *out, size_t cap, uint64_t svn, const char *ver,
                uint16_t golden_bpm_x10, uint16_t golden_spo2_x10, size_t app_len,
                const uint8_t *signing_sk);

/* Copy an image into a slot, bypassing the power model. */
void fx_put_slot(fx_t *f, int slot, const uint8_t *img, size_t len);

/* Application-side requests, written to the mailbox sector. */
void fx_mbx_attest(fx_t *f, const uint8_t verifier_nonce[32]);
void fx_mbx_health(fx_t *f, uint64_t svn, uint16_t bpm_x10, uint16_t spo2_x10, uint8_t part_id,
                   uint8_t sensor_ok, uint16_t live);
void fx_mbx_install(fx_t *f, uint32_t pkg_len, uint32_t pkg_crc);

/*
 * Vendor-side delivery package for `image`: OTA1 for `kem_pk`, wrapped in a
 * DLV1 signed by `sign_sk`. Returns its length.
 */
size_t fx_package(const fx_t *f, uint8_t *out, size_t cap, const uint8_t *image, size_t image_len,
                  uint32_t device_id, const uint8_t nonce[32], uint64_t svn, const char *ver,
                  const uint8_t kem_pk[ROT_KEM_PK], const uint8_t *sign_sk);

/* Stage a package and queue the install request. */
void fx_stage_and_request(fx_t *f, const uint8_t *pkg, size_t len);

/* Attest and return the RoT nonce, verifying the ATR2 signature on the way. */
int fx_attest(fx_t *f, const uint8_t verifier_nonce[32], uint8_t rot_nonce[32]);

/* Persistent state readers (decoded through the real record code). */
int fx_journal(fx_t *f, rot_journal_t *j);
int fx_floor(fx_t *f, uint64_t *floor);
int fx_receipt(fx_t *f, uint32_t seq, uint8_t obj[RCP_TOTAL_BYTES], rcp_t *r);

/* Overwrite the journal state (commits a new page), for building scenarios. */
int fx_set_journal(fx_t *f, const rot_journal_t *j);

/* Helper-data record access for tamper tests. */
int fx_rederive(fx_t *f, rot_keys *k);

/* Snapshot and restore of the whole flash. */
void fx_save(fx_t *f, uint8_t *buf);
void fx_restore(fx_t *f, const uint8_t *buf);

#endif
