#include "proto/app_server.h"

#include "rot/rot_crc32.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_receipt.h"
#include "rot/rot_util.h"

#include <stdio.h>
#include <string.h>

void app_server_init(app_server *s, const app_services *svc, uint32_t staging_size, uint32_t first_mbx_seq)
{
    memset(s, 0, sizeof *s);
    s->svc = svc;
    s->staging_size = staging_size;
    s->mbx_seq = first_mbx_seq;
}

static size_t reply(uint8_t *resp, size_t cap, uint8_t type, uint16_t seq, const uint8_t *p, uint32_t n)
{
    return pqw1_encode(resp, cap, type, PQW1_FLAG_LAST, seq, p, n);
}

static size_t err(uint8_t *resp, size_t cap, uint16_t seq, int code, const char *msg)
{
    char json[96];
    int n = snprintf(json, sizeof json, "{\"code\":%d,\"msg\":\"%s\"}", code, msg);
    return reply(resp, cap, PQW1_R_ERR, seq, (const uint8_t *)json, (uint32_t)n);
}

static size_t reply_json(uint8_t *resp, size_t cap, uint8_t type, uint16_t seq, const char *json, int n)
{
    if (n < 0 || (size_t)n >= 1024) {
        return err(resp, cap, seq, APP_ERR_IO, "json");
    }
    return reply(resp, cap, type, seq, (const uint8_t *)json, (uint32_t)n);
}

static size_t send_mailbox(app_server *s, uint8_t *resp, size_t cap, uint16_t seq, uint8_t type,
                           const uint8_t *payload, uint16_t len)
{
    uint8_t rec[ROT_MBX_HDR + ROT_MBX_MAX_PAYLOAD + 4];
    size_t n = rot_mailbox_build(rec, ++s->mbx_seq, type, payload, len);

    if (s->svc->mailbox_write(s->svc->ctx, rec, n) != 0) {
        return err(resp, cap, seq, APP_ERR_IO, "mailbox");
    }
    s->pending_reboot = 1;
    return reply(resp, cap, PQW1_R_ACK, seq, NULL, 0);
}

static size_t status_json(app_server *s, uint8_t *resp, size_t cap, uint16_t seq, uint8_t type, int full)
{
    char json[1024];
    const rot_handoff_t *h = s->svc->handoff(s->svc->ctx);
    int n;

    if (!h || !rot_handoff_valid(h)) {
        return err(resp, cap, seq, APP_ERR_NO_ATTEST, "no boot report");
    }
    n = snprintf(json, sizeof json,
                 "{\"proto\":1,\"device_id\":\"%08x\",\"svn\":%llu,\"floor\":%llu,\"version\":\"%.16s\","
                 "\"slot\":%u,\"trial\":%u,\"sim_puf\":%u,\"slot_status\":[%u,%u],\"receipt_seq\":%u",
                 (unsigned)h->device_id, (unsigned long long)h->svn, (unsigned long long)h->floor,
                 h->version_str, h->active_slot, (h->flags & HND_F_TRIAL) ? 1u : 0u,
                 (h->flags & HND_F_SIM_PUF) ? 1u : 0u, h->slot_status[0], h->slot_status[1],
                 (unsigned)h->receipt_seq);
    if (full && n > 0) {
        n += snprintf(json + n, sizeof json - (size_t)n,
                      ",\"reset_cause\":%u,\"refreshes\":%u,\"bits_corrected\":%u,\"worst_block\":%u,"
                      "\"temp_x10\":%d,\"journal_seq\":%u,\"last_event\":%u,"
                      "\"last_reason\":%u,\"cycles\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],"
                      "\"attest\":%u,\"new_receipt\":%u",
                      h->reset_cause, h->refresh_count, h->bits_corrected, h->worst_block,
                      h->die_temp_x10, (unsigned)h->journal_seq,
                      h->last_event, h->last_reason, (unsigned)h->cycles[0], (unsigned)h->cycles[1],
                      (unsigned)h->cycles[2], (unsigned)h->cycles[3], (unsigned)h->cycles[4],
                      (unsigned)h->cycles[5], (unsigned)h->cycles[6], (unsigned)h->cycles[7],
                      (unsigned)h->cycles[8], (unsigned)h->cycles[9], (unsigned)h->cycles[10],
                      (unsigned)h->cycles[11], (h->flags & HND_F_ATTEST) ? 1u : 0u,
                      (h->flags & HND_F_NEW_RECEIPT) ? 1u : 0u);
    }
    if (n > 0) {
        n += snprintf(json + n, sizeof json - (size_t)n, "}");
    }
    return reply_json(resp, cap, type, seq, json, n);
}

size_t app_server_handle(app_server *s, const pqw1_frame *req, uint8_t *resp, size_t cap)
{
    const uint8_t *p = req->payload;
    uint32_t len = req->len;
    uint16_t seq = req->seq;

    switch (req->type) {
    case PQW1_HELLO:
        return status_json(s, resp, cap, seq, PQW1_R_STATUS, 0);

    case PQW1_VITALS_SUB:
        s->vitals_subscribed = 1;
        return reply(resp, cap, PQW1_R_ACK, seq, NULL, 0);

    case PQW1_ATTEST_REQ:
        if (len != 32) {
            return err(resp, cap, seq, APP_ERR_BAD_REQUEST, "nonce must be 32 bytes");
        }
        return send_mailbox(s, resp, cap, seq, MBX_ATTEST_REQ, p, 32);

    case PQW1_GET_ATTEST: {
        const rot_handoff_t *h = s->svc->handoff(s->svc->ctx);
        if (!h || !rot_handoff_valid(h) || !(h->flags & HND_F_ATTEST) || h->atr2_len != ATR2_TOTAL_BYTES) {
            return err(resp, cap, seq, APP_ERR_NO_ATTEST, "no attestation");
        }
        return reply(resp, cap, PQW1_R_ATTEST, seq, h->atr2, h->atr2_len);
    }

    case PQW1_PKG_BEGIN: {
        uint32_t total, crc;
        if (len != 8) {
            return err(resp, cap, seq, APP_ERR_BAD_REQUEST, "begin: len and crc");
        }
        total = rot_get32(p);
        crc = rot_get32(p + 4);
        if (total == 0 || total > s->staging_size) {
            return err(resp, cap, seq, APP_ERR_TOO_BIG, "package size");
        }
        s->receiving = 1;
        s->pkg_len = total;
        s->pkg_crc_claim = crc;
        s->next_off = 0;
        s->crc_run = 0;
        s->erased_upto = 0;
        return reply(resp, cap, PQW1_R_READY, seq, NULL, 0);
    }

    case PQW1_PKG_CHUNK: {
        uint32_t off, n;
        if (!s->receiving) {
            return err(resp, cap, seq, APP_ERR_BAD_STATE, "no transfer");
        }
        if (len < 5 || len - 4 > APP_CHUNK_MAX) {
            return err(resp, cap, seq, APP_ERR_BAD_REQUEST, "chunk size");
        }
        off = rot_get32(p);
        n = len - 4;
        if (off != s->next_off) {
            /* the sender resumes from the offset in the error */
            char msg[48];
            snprintf(msg, sizeof msg, "expected offset %u", (unsigned)s->next_off);
            return err(resp, cap, seq, APP_ERR_BAD_OFFSET, msg);
        }
        if ((uint64_t)off + n > s->pkg_len) {
            return err(resp, cap, seq, APP_ERR_TOO_BIG, "past the announced length");
        }
        while (s->erased_upto < off + n) {
            uint32_t blk = APP_ERASE_AHEAD;
            if (s->erased_upto + blk > s->staging_size) {
                blk = s->staging_size - s->erased_upto;
            }
            if (s->svc->staging_erase(s->svc->ctx, s->erased_upto, blk) != 0) {
                return err(resp, cap, seq, APP_ERR_IO, "erase");
            }
            s->erased_upto += blk;
        }
        if (s->svc->staging_write(s->svc->ctx, off, p + 4, n) != 0) {
            return err(resp, cap, seq, APP_ERR_IO, "write");
        }
        s->crc_run = rot_crc32(s->crc_run, p + 4, n);
        s->next_off = off + n;
        {
            uint8_t ack[4];
            rot_put32(ack, s->next_off);
            return reply(resp, cap, PQW1_R_CHUNK_ACK, seq, ack, 4);
        }
    }

    case PQW1_PKG_END: {
        uint8_t pl[8];
        if (!s->receiving) {
            return err(resp, cap, seq, APP_ERR_BAD_STATE, "no transfer");
        }
        if (s->next_off != s->pkg_len) {
            char msg[48];
            snprintf(msg, sizeof msg, "expected offset %u", (unsigned)s->next_off);
            return err(resp, cap, seq, APP_ERR_BAD_OFFSET, msg);
        }
        if (s->crc_run != s->pkg_crc_claim) {
            s->receiving = 0;
            return err(resp, cap, seq, APP_ERR_CRC, "package crc");
        }
        s->receiving = 0;
        rot_put32(pl, s->pkg_len);
        rot_put32(pl + 4, s->crc_run);
        return send_mailbox(s, resp, cap, seq, MBX_INSTALL_REQ, pl, 8);
    }

    case PQW1_GET_RECEIPTS: {
        static uint8_t out[2 + APP_RECEIPTS_PER_FRAME * RCP_TOTAL_BYTES];
        const rot_handoff_t *h = s->svc->handoff(s->svc->ctx);
        uint32_t since, last, count = 0;
        if (len != 4) {
            return err(resp, cap, seq, APP_ERR_BAD_REQUEST, "since_seq");
        }
        if (!h || !rot_handoff_valid(h)) {
            return err(resp, cap, seq, APP_ERR_NO_ATTEST, "no boot report");
        }
        since = rot_get32(p);
        last = h->receipt_seq;
        for (uint32_t q = since + 1; q <= last && count < APP_RECEIPTS_PER_FRAME; q++) {
            if (s->svc->receipt_read(s->svc->ctx, q, out + 2 + count * RCP_TOTAL_BYTES) == 0) {
                count++;
            } else if (count) {
                break;   /* the ring no longer holds it; keep the sequence contiguous */
            }
        }
        rot_put16(out, (uint16_t)count);
        return reply(resp, cap, PQW1_R_RECEIPTS, seq, out, 2 + count * RCP_TOTAL_BYTES);
    }

    case PQW1_GET_BOOTREPORT:
        return status_json(s, resp, cap, seq, PQW1_R_BOOTREPORT, 1);

    case PQW1_GET_IDENTITY: {
        static uint8_t id[4 + ROT_DSA_PK + ROT_KEM_PK];
        const rot_handoff_t *h = s->svc->handoff(s->svc->ctx);
        if (!h || !rot_handoff_valid(h)) {
            return err(resp, cap, seq, APP_ERR_NO_ATTEST, "no boot report");
        }
        rot_put32(id, h->device_id);
        memcpy(id + 4, h->pk_dsa, ROT_DSA_PK);
        memcpy(id + 4 + ROT_DSA_PK, h->pk_kem, ROT_KEM_PK);
        return reply(resp, cap, PQW1_R_IDENTITY, seq, id, sizeof id);
    }

    default:
        return err(resp, cap, seq, APP_ERR_UNKNOWN, "unknown request");
    }
}
