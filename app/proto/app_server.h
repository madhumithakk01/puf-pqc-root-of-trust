#ifndef APP_SERVER_H
#define APP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "proto/pqw1.h"
#include "rot/rot_handoff.h"

/*
 * Request handling for the PQW1 protocol, independent of the transport and
 * of the board. The application never holds a key: it relays requests to the
 * RoT through the mailbox and stages incoming packages. Nothing here is
 * trusted by the RoT.
 */

typedef struct {
    void *ctx;
    /* Erase `len` bytes of the staging region starting at `off` (sector aligned). */
    int  (*staging_erase)(void *ctx, uint32_t off, uint32_t len);
    int  (*staging_write)(void *ctx, uint32_t off, const uint8_t *data, size_t n);
    /* Replace the mailbox record with `rec`. */
    int  (*mailbox_write)(void *ctx, const uint8_t *rec, size_t n);
    /* Copy receipt `seq` (2684 bytes) if it is still in the ring; 0 on success. */
    int  (*receipt_read)(void *ctx, uint32_t seq, uint8_t *obj);
    const rot_handoff_t *(*handoff)(void *ctx);
    /* Start a transfer of the current image's name for the status line. */
} app_services;

typedef struct {
    const app_services *svc;
    uint32_t staging_size;

    int      receiving;
    uint32_t pkg_len;
    uint32_t pkg_crc_claim;
    uint32_t next_off;
    uint32_t crc_run;
    uint32_t erased_upto;

    uint32_t mbx_seq;
    int      pending_reboot;   /* the transport reboots after the response is sent */
    int      vitals_subscribed;
} app_server;

#define APP_ERASE_AHEAD 0x10000u   /* 64 KB */
#define APP_CHUNK_MAX   4096u
#define APP_RECEIPTS_PER_FRAME 3u

enum {
    APP_ERR_BAD_REQUEST = 1,
    APP_ERR_NO_ATTEST = 2,
    APP_ERR_BAD_STATE = 3,
    APP_ERR_BAD_OFFSET = 4,
    APP_ERR_TOO_BIG = 5,
    APP_ERR_IO = 6,
    APP_ERR_CRC = 7,
    APP_ERR_UNKNOWN = 8,
};

void app_server_init(app_server *s, const app_services *svc, uint32_t staging_size, uint32_t first_mbx_seq);

/*
 * Handle one request frame. Writes a complete response frame into `resp`
 * and returns its length (never 0: errors are PQW1_R_ERR frames).
 */
size_t app_server_handle(app_server *s, const pqw1_frame *req, uint8_t *resp, size_t cap);

#endif
