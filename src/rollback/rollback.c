#include "rollback/rollback.h"

#include "kdf/kdf.h"

#include <string.h>

#define MAGIC0 'R'
#define MAGIC1 'B'
#define MAGIC2 'C'
#define MAGIC3 '1'
#define TAG_DOMAIN "rollback/v1/tag"

#define OFF_MAGIC 0u
#define OFF_SEQ   4u
#define OFF_CNT   8u
#define OFF_TAG   16u
#define AUTHED_LEN 16u /* magic || seq || cnt */

static void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static uint64_t rd_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static void compute_tag(const uint8_t key[ROLLBACK_KEY_BYTES],
                        const uint8_t authed[AUTHED_LEN],
                        uint8_t tag[ROLLBACK_TAG_BYTES])
{
    uint8_t msg[sizeof TAG_DOMAIN - 1 + AUTHED_LEN];
    memcpy(msg, TAG_DOMAIN, sizeof TAG_DOMAIN - 1);
    memcpy(msg + sizeof TAG_DOMAIN - 1, authed, AUTHED_LEN);
    rot_kdf_derive(key, ROLLBACK_KEY_BYTES, msg, sizeof msg,
                   tag, ROLLBACK_TAG_BYTES);
}

static int has_magic(const uint8_t *page)
{
    return page[0] == MAGIC0 && page[1] == MAGIC1 &&
           page[2] == MAGIC2 && page[3] == MAGIC3;
}

/* constant-time tag compare */
static int tag_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (unsigned i = 0; i < ROLLBACK_TAG_BYTES; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return d == 0;
}

static int page_valid(const uint8_t *page, const uint8_t key[ROLLBACK_KEY_BYTES],
                      uint32_t *seq, uint64_t *cnt)
{
    if (!has_magic(page)) {
        return 0;
    }
    uint8_t want[ROLLBACK_TAG_BYTES];
    compute_tag(key, page, want);
    if (!tag_equal(want, page + OFF_TAG)) {
        return 0;
    }
    if (seq) {
        *seq = rd_le32(page + OFF_SEQ);
    }
    if (cnt) {
        *cnt = rd_le64(page + OFF_CNT);
    }
    return 1;
}

static void marshal(uint8_t page[ROLLBACK_PAGE_BYTES],
                    const uint8_t key[ROLLBACK_KEY_BYTES],
                    uint32_t seq, uint64_t cnt)
{
    memset(page, 0, ROLLBACK_PAGE_BYTES);
    page[0] = MAGIC0;
    page[1] = MAGIC1;
    page[2] = MAGIC2;
    page[3] = MAGIC3;
    wr_le32(page + OFF_SEQ, seq);
    wr_le64(page + OFF_CNT, cnt);
    compute_tag(key, page, page + OFF_TAG);
}

/* newest valid page: returns index 0/1 and its (seq,cnt), or -1 if none */
static int newest(const rollback_store *s, const uint8_t key[ROLLBACK_KEY_BYTES],
                  uint32_t *seq_out, uint64_t *cnt_out)
{
    int best = -1;
    uint32_t best_seq = 0;
    uint64_t best_cnt = 0;
    for (int i = 0; i < 2; i++) {
        uint32_t seq;
        uint64_t cnt;
        if (page_valid(s->page[i], key, &seq, &cnt)) {
            if (best < 0 || seq > best_seq) {
                best = i;
                best_seq = seq;
                best_cnt = cnt;
            }
        }
    }
    if (best >= 0) {
        if (seq_out) *seq_out = best_seq;
        if (cnt_out) *cnt_out = best_cnt;
    }
    return best;
}

int rollback_enroll(rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES], uint64_t cnt)
{
    if (!s || !key) {
        return ROLLBACK_ERR_ARG;
    }
    memset(s, 0, sizeof *s);
    marshal(s->page[0], key, 1u, cnt);
    return ROLLBACK_OK;
}

int rollback_read(const rollback_store *s,
                  const uint8_t key[ROLLBACK_KEY_BYTES], uint64_t *cnt)
{
    if (!s || !key || !cnt) {
        return ROLLBACK_ERR_ARG;
    }
    uint64_t c;
    if (newest(s, key, NULL, &c) < 0) {
        return ROLLBACK_ERR_NO_VALID_PAGE;
    }
    *cnt = c;
    return ROLLBACK_OK;
}

int rollback_verify(const rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES],
                    uint64_t *cnt, unsigned *tampered_pages)
{
    if (!s || !key || !cnt) {
        return ROLLBACK_ERR_ARG;
    }
    unsigned tampered = 0;
    int good = 0;
    uint64_t best_cnt = 0;
    uint32_t best_seq = 0;
    for (int i = 0; i < 2; i++) {
        uint32_t seq;
        uint64_t c;
        if (page_valid(s->page[i], key, &seq, &c)) {
            if (!good || seq > best_seq) {
                best_seq = seq;
                best_cnt = c;
            }
            good = 1;
        } else if (has_magic(s->page[i])) {
            tampered |= (1u << i);
        }
    }
    if (tampered_pages) {
        *tampered_pages = tampered;
    }
    if (good) {
        *cnt = best_cnt;
    }
    if (tampered) {
        return ROLLBACK_ERR_TAMPER;
    }
    return good ? ROLLBACK_OK : ROLLBACK_ERR_NO_VALID_PAGE;
}

int rollback_update(rollback_store *s,
                    const uint8_t key[ROLLBACK_KEY_BYTES],
                    uint64_t new_cnt, size_t fault_after_bytes)
{
    if (!s || !key) {
        return ROLLBACK_ERR_ARG;
    }
    uint32_t cur_seq;
    uint64_t cur_cnt;
    int cur = newest(s, key, &cur_seq, &cur_cnt);
    if (cur < 0) {
        return ROLLBACK_ERR_NO_VALID_PAGE;
    }
    if (new_cnt <= cur_cnt) {
        return ROLLBACK_ERR_MONOTONIC;
    }

    uint8_t rec[ROLLBACK_PAGE_BYTES];
    marshal(rec, key, cur_seq + 1u, new_cnt);

    int target = 1 - cur;
    if (fault_after_bytes == 0u || fault_after_bytes >= ROLLBACK_PAGE_BYTES) {
        memcpy(s->page[target], rec, ROLLBACK_PAGE_BYTES);
        return ROLLBACK_OK;
    }

    memcpy(s->page[target], rec, fault_after_bytes);
    memset(s->page[target] + fault_after_bytes, 0xFF,
           ROLLBACK_PAGE_BYTES - fault_after_bytes);
    return ROLLBACK_ERR_WRITE_INTERRUPTED;
}
