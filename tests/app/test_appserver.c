/*
 * Application request handler: transfer state machine, mailbox requests,
 * erase-ahead, error replies, receipts paging, identity.
 */

#include "proto/app_server.h"

#include "rot/rot_crc32.h"
#include "rot/rot_receipt.h"
#include "rot/rot_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, int ok)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) failures++;
}

#define STAGING (256u * 1024u)

typedef struct {
    uint8_t staging[STAGING];
    uint8_t mbx[128];
    size_t mbx_len;
    int mbx_writes;
    unsigned erases;
    uint32_t erase_end;
    int fail_write;
    rot_handoff_t h;
    int have_h;
    int receipts_missing_below;
} dev_t;

static int st_erase(void *c, uint32_t off, uint32_t len)
{
    dev_t *d = c;
    if (off + len > STAGING) return -1;
    memset(d->staging + off, 0xFF, len);
    d->erases++;
    d->erase_end = off + len;
    return 0;
}

static int st_write(void *c, uint32_t off, const uint8_t *data, size_t n)
{
    dev_t *d = c;
    if (d->fail_write || off + n > STAGING || off + n > d->erase_end) return -1;
    memcpy(d->staging + off, data, n);
    return 0;
}

static int mb_write(void *c, const uint8_t *rec, size_t n)
{
    dev_t *d = c;
    memcpy(d->mbx, rec, n);
    d->mbx_len = n;
    d->mbx_writes++;
    return 0;
}

static int rc_read(void *c, uint32_t seq, uint8_t *obj)
{
    dev_t *d = c;
    if (seq < (uint32_t)d->receipts_missing_below) return -1;
    memset(obj, 0, RCP_TOTAL_BYTES);
    memcpy(obj, "RCP1", 4);
    rot_put32(obj + 4, seq);
    return 0;
}

static const rot_handoff_t *ho(void *c)
{
    dev_t *d = c;
    return d->have_h ? &d->h : NULL;
}

static dev_t D;
static app_server S;
static uint8_t resp[PQW1_MAX_FRAME];

/* Send a request through the real framing and return the parsed response. */
static int call(uint8_t type, uint16_t seq, const uint8_t *payload, uint32_t len, pqw1_frame *out)
{
    static uint8_t req[PQW1_MAX_FRAME];
    static pqw1_parser rp;
    pqw1_frame f;
    size_t n = pqw1_encode(req, sizeof req, type, 0, seq, payload, len), rl;
    pqw1_event e = PQW1_NEED_MORE;

    pqw1_parser_init(&rp);
    for (size_t i = 0; i < n; i++) e = pqw1_feed(&rp, req[i], &f);
    if (e != PQW1_FRAME) return -1;
    rl = app_server_handle(&S, &f, resp, sizeof resp);
    if (rl == 0) return -2;
    pqw1_parser_init(&rp);
    e = PQW1_NEED_MORE;
    for (size_t i = 0; i < rl; i++) e = pqw1_feed(&rp, resp[i], out);
    return e == PQW1_FRAME ? 0 : -3;
}

static const char *json_of(const pqw1_frame *f, char *buf, size_t cap)
{
    size_t n = f->len < cap - 1 ? f->len : cap - 1;
    memcpy(buf, f->payload, n);
    buf[n] = 0;
    return buf;
}

static int is_err(const pqw1_frame *f, int code)
{
    char b[128], want[16];
    json_of(f, b, sizeof b);
    snprintf(want, sizeof want, "\"code\":%d", code);
    return f->type == PQW1_R_ERR && strstr(b, want) != NULL;
}

static void pkg_payload(uint8_t *pl, uint32_t len, uint32_t crc)
{
    rot_put32(pl, len);
    rot_put32(pl + 4, crc);
}

int main(void)
{
    static uint8_t data[20000], chunk[4 + APP_CHUNK_MAX];
    app_services svc = { &D, st_erase, st_write, mb_write, rc_read, ho };
    pqw1_frame f;
    uint8_t pl[8];
    char js[1100];

    for (unsigned i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 13 + 5);
    app_server_init(&S, &svc, STAGING, 100);

    check("HELLO without a boot report is an error", call(PQW1_HELLO, 1, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_NO_ATTEST));

    D.have_h = 1;
    D.h.device_id = 0xDEADBEEFu;
    D.h.svn = 2;
    D.h.floor = 2;
    strcpy(D.h.version_str, "1.1.0");
    D.h.active_slot = 1;
    D.h.receipt_seq = 5;
    D.h.slot_status[0] = 3;
    D.h.slot_status[1] = 1;
    memset(D.h.pk_dsa, 0xA5, ROT_DSA_PK);
    memset(D.h.pk_kem, 0x5A, ROT_KEM_PK);
    rot_handoff_seal(&D.h);

    check("HELLO returns the status JSON", call(PQW1_HELLO, 2, NULL, 0, &f) == 0 && f.type == PQW1_R_STATUS
          && f.seq == 2 && strstr(json_of(&f, js, sizeof js), "\"device_id\":\"deadbeef\"")
          && strstr(js, "\"svn\":2") && strstr(js, "\"version\":\"1.1.0\"") && strstr(js, "\"slot_status\":[3,1]"));
    check("GET_BOOTREPORT adds the measurements", call(PQW1_GET_BOOTREPORT, 3, NULL, 0, &f) == 0
          && f.type == PQW1_R_BOOTREPORT && strstr(json_of(&f, js, sizeof js), "\"bits_corrected\"")
          && strstr(js, "\"cycles\":["));
    check("VITALS_SUB acknowledges and flags the subscription", call(PQW1_VITALS_SUB, 4, NULL, 0, &f) == 0
          && f.type == PQW1_R_ACK && S.vitals_subscribed);

    {
        const uint8_t *id;
        check("GET_IDENTITY returns id and both public keys", call(PQW1_GET_IDENTITY, 5, NULL, 0, &f) == 0
              && f.type == PQW1_R_IDENTITY && f.len == 4 + ROT_DSA_PK + ROT_KEM_PK
              && (id = f.payload, rot_get32(id) == 0xDEADBEEFu) && id[4] == 0xA5 && id[4 + ROT_DSA_PK] == 0x5A);
    }

    check("GET_ATTEST before any attestation is an error", call(PQW1_GET_ATTEST, 6, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_NO_ATTEST));
    D.h.flags |= HND_F_ATTEST;
    D.h.atr2_len = ATR2_TOTAL_BYTES;
    memset(D.h.atr2, 0x33, ATR2_TOTAL_BYTES);
    rot_handoff_seal(&D.h);
    check("GET_ATTEST returns the report", call(PQW1_GET_ATTEST, 7, NULL, 0, &f) == 0 && f.type == PQW1_R_ATTEST
          && f.len == ATR2_TOTAL_BYTES && f.payload[0] == 0x33);

    /* attest request */
    {
        uint8_t nonce[32];
        uint32_t crc;
        for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(0x40 + i);
        check("a 31-byte nonce is refused", call(PQW1_ATTEST_REQ, 8, nonce, 31, &f) == 0 && is_err(&f, APP_ERR_BAD_REQUEST)
              && D.mbx_writes == 0 && !S.pending_reboot);
        check("ATTEST_REQ writes the mailbox and asks for a reboot", call(PQW1_ATTEST_REQ, 9, nonce, 32, &f) == 0
              && f.type == PQW1_R_ACK && D.mbx_writes == 1 && S.pending_reboot);
        crc = rot_crc32(0, D.mbx, D.mbx_len - 4);
        check("mailbox record: magic, seq, type, length, payload, CRC", memcmp(D.mbx, "MBX1", 4) == 0
              && rot_get32(D.mbx + 4) == 101 && D.mbx[8] == 1 && rot_get16(D.mbx + 10) == 32
              && memcmp(D.mbx + 12, nonce, 32) == 0 && rot_get32(D.mbx + D.mbx_len - 4) == crc && D.mbx_len == 12 + 32 + 4);
        S.pending_reboot = 0;
    }

    /* package transfer */
    check("a chunk before BEGIN is a state error", (rot_put32(chunk, 0), call(PQW1_PKG_CHUNK, 10, chunk, 4 + 100, &f) == 0)
          && is_err(&f, APP_ERR_BAD_STATE));
    check("END before BEGIN is a state error", call(PQW1_PKG_END, 11, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_BAD_STATE));
    pkg_payload(pl, STAGING + 1, 0);
    check("a package larger than staging is refused", call(PQW1_PKG_BEGIN, 12, pl, 8, &f) == 0 && is_err(&f, APP_ERR_TOO_BIG));
    pkg_payload(pl, 0, 0);
    check("a zero-length package is refused", call(PQW1_PKG_BEGIN, 13, pl, 8, &f) == 0 && is_err(&f, APP_ERR_TOO_BIG));
    check("BEGIN with a short payload is refused", call(PQW1_PKG_BEGIN, 14, pl, 7, &f) == 0 && is_err(&f, APP_ERR_BAD_REQUEST));

    {
        uint32_t total = sizeof data, crc = rot_crc32(0, data, sizeof data), off = 0;
        D.erases = 0;
        pkg_payload(pl, total, crc);
        check("BEGIN", call(PQW1_PKG_BEGIN, 20, pl, 8, &f) == 0 && f.type == PQW1_R_READY);

        rot_put32(chunk, 4096);
        memcpy(chunk + 4, data + 4096, 1000);
        check("a chunk at the wrong offset is refused and names the offset", call(PQW1_PKG_CHUNK, 21, chunk, 4 + 1000, &f) == 0
              && is_err(&f, APP_ERR_BAD_OFFSET) && strstr(json_of(&f, js, sizeof js), "expected offset 0"));

        while (off < total) {
            uint32_t n = total - off > APP_CHUNK_MAX ? APP_CHUNK_MAX : total - off;
            rot_put32(chunk, off);
            memcpy(chunk + 4, data + off, n);
            if (call(PQW1_PKG_CHUNK, 22, chunk, 4 + n, &f) != 0 || f.type != PQW1_R_CHUNK_ACK
                || rot_get32(f.payload) != off + n) {
                break;
            }
            off += n;
        }
        check("all chunks acknowledged with the next offset", off == total);
        check("staging holds the package", memcmp(D.staging, data, total) == 0);
        check("erase-ahead works in 64 KB blocks (one block for 20 KB)", D.erases == 1 && D.erase_end == APP_ERASE_AHEAD);

        rot_put32(chunk, total);
        check("a chunk beyond the announced length is refused", call(PQW1_PKG_CHUNK, 23, chunk, 4 + 10, &f) == 0
              && is_err(&f, APP_ERR_TOO_BIG));
        check("an oversized chunk is refused", call(PQW1_PKG_CHUNK, 24, chunk, 4 + APP_CHUNK_MAX + 1, &f) == 0
              && is_err(&f, APP_ERR_BAD_REQUEST));

        D.mbx_writes = 0;
        check("END queues the install request", call(PQW1_PKG_END, 25, NULL, 0, &f) == 0 && f.type == PQW1_R_ACK
              && D.mbx_writes == 1 && S.pending_reboot && D.mbx[8] == 2 && rot_get32(D.mbx + 12) == total
              && rot_get32(D.mbx + 16) == crc);
        S.pending_reboot = 0;
        check("a second END has no transfer to finish", call(PQW1_PKG_END, 26, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_BAD_STATE));
    }

    /* CRC mismatch */
    {
        uint32_t crc = rot_crc32(0, data, 500) ^ 1;
        D.mbx_writes = 0;
        pkg_payload(pl, 500, crc);
        call(PQW1_PKG_BEGIN, 30, pl, 8, &f);
        rot_put32(chunk, 0);
        memcpy(chunk + 4, data, 500);
        call(PQW1_PKG_CHUNK, 31, chunk, 4 + 500, &f);
        check("a package whose CRC does not match is refused at END", call(PQW1_PKG_END, 32, NULL, 0, &f) == 0
              && is_err(&f, APP_ERR_CRC) && D.mbx_writes == 0 && !S.pending_reboot);
    }

    /* short package: END before all bytes arrived */
    {
        pkg_payload(pl, 1000, 0);
        call(PQW1_PKG_BEGIN, 33, pl, 8, &f);
        rot_put32(chunk, 0);
        call(PQW1_PKG_CHUNK, 34, chunk, 4 + 400, &f);
        check("END before the last byte is refused", call(PQW1_PKG_END, 35, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_BAD_OFFSET));
    }

    /* a failing flash write is reported */
    {
        pkg_payload(pl, 100, 0);
        call(PQW1_PKG_BEGIN, 36, pl, 8, &f);
        D.fail_write = 1;
        rot_put32(chunk, 0);
        check("a staging write failure is reported", call(PQW1_PKG_CHUNK, 37, chunk, 4 + 100, &f) == 0 && is_err(&f, APP_ERR_IO));
        D.fail_write = 0;
    }

    /* receipts paging */
    {
        uint32_t q;
        uint8_t arg[4];
        rot_put32(arg, 0);
        check("GET_RECEIPTS since 0 returns three at a time", call(PQW1_GET_RECEIPTS, 40, arg, 4, &f) == 0
              && f.type == PQW1_R_RECEIPTS && rot_get16(f.payload) == 3 && f.len == 2 + 3 * RCP_TOTAL_BYTES);
        q = rot_get32(f.payload + 2 + 2 * RCP_TOTAL_BYTES + 4);
        check("they are receipts 1, 2, 3 in order", q == 3 && rot_get32(f.payload + 2 + 4) == 1);
        rot_put32(arg, 3);
        check("the next call continues with 4 and 5", call(PQW1_GET_RECEIPTS, 41, arg, 4, &f) == 0
              && rot_get16(f.payload) == 2 && rot_get32(f.payload + 2 + 4) == 4);
        rot_put32(arg, 5);
        check("nothing newer returns an empty list", call(PQW1_GET_RECEIPTS, 42, arg, 4, &f) == 0 && rot_get16(f.payload) == 0);
        D.receipts_missing_below = 4;
        rot_put32(arg, 0);
        check("receipts that left the ring are skipped without gaps in what is returned",
              call(PQW1_GET_RECEIPTS, 43, arg, 4, &f) == 0 && rot_get16(f.payload) == 2 && rot_get32(f.payload + 2 + 4) == 4);
        check("GET_RECEIPTS needs a 4-byte argument", call(PQW1_GET_RECEIPTS, 44, arg, 3, &f) == 0 && is_err(&f, APP_ERR_BAD_REQUEST));
    }

    check("unknown request type", call(0x7E, 50, NULL, 0, &f) == 0 && is_err(&f, APP_ERR_UNKNOWN));
    check("responses echo the request sequence number", call(PQW1_HELLO, 4242, NULL, 0, &f) == 0 && f.seq == 4242);

    if (failures) {
        printf("test_appserver: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_appserver: PASS\n");
    return 0;
}
