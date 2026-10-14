#ifndef APP_PQW1_H
#define APP_PQW1_H

#include <stddef.h>
#include <stdint.h>

/*
 * PQW1: framing for the device protocol, independent of the transport.
 *
 *   0  4  "PQW1"
 *   4  1  type
 *   5  1  flags (bit 0 LAST)
 *   6  2  seq
 *   8  4  len (<= PQW1_MAX_PAYLOAD)
 *  12  n  payload
 * 12+n 4  CRC32 over bytes [4 : 12+n)
 *
 * The CRC catches transport errors only. Nothing about trust depends on it:
 * what matters is signed and checked by the RoT.
 *
 * Over USB serial each frame travels as one text line "@<base64>\n"; lines
 * starting with '#' are diagnostics.
 */

#define PQW1_MAX_PAYLOAD 8192u
#define PQW1_HDR         12u
#define PQW1_MAX_FRAME   (PQW1_HDR + PQW1_MAX_PAYLOAD + 4u)
#define PQW1_FLAG_LAST   0x01u

enum {
    PQW1_HELLO = 0x01, PQW1_VITALS_SUB = 0x02, PQW1_ATTEST_REQ = 0x03, PQW1_GET_ATTEST = 0x04,
    PQW1_PKG_BEGIN = 0x05, PQW1_PKG_CHUNK = 0x06, PQW1_PKG_END = 0x07, PQW1_GET_RECEIPTS = 0x08,
    PQW1_GET_BOOTREPORT = 0x09, PQW1_GET_IDENTITY = 0x0A,
    PQW1_R_STATUS = 0x81, PQW1_R_VITALS = 0x82, PQW1_R_ACK = 0x83, PQW1_R_ATTEST = 0x84,
    PQW1_R_READY = 0x85, PQW1_R_CHUNK_ACK = 0x86, PQW1_R_END_ACK = 0x87, PQW1_R_RECEIPTS = 0x88,
    PQW1_R_BOOTREPORT = 0x89, PQW1_R_IDENTITY = 0x8A, PQW1_R_ERR = 0xFF,
};

typedef struct {
    uint8_t  type;
    uint8_t  flags;
    uint16_t seq;
    uint32_t len;
    const uint8_t *payload;   /* points into the parser buffer, valid until the next feed */
} pqw1_frame;

/* Serialize a frame. Returns the length, or 0 if it does not fit or len is too large. */
size_t pqw1_encode(uint8_t *out, size_t cap, uint8_t type, uint8_t flags, uint16_t seq,
                   const uint8_t *payload, uint32_t len);

typedef enum {
    PQW1_NEED_MORE = 0,
    PQW1_FRAME,        /* a complete valid frame is in `frame` */
    PQW1_ERR_LEN,      /* announced length too large; the parser resynchronised */
    PQW1_ERR_CRC,      /* bad CRC; the frame was dropped */
} pqw1_event;

typedef struct {
    uint8_t  buf[PQW1_MAX_FRAME];
    size_t   have;
    size_t   want;      /* total length of the current frame once the header is in, else 0 */
    int      consumed_frame; /* the previous frame is dropped at the next feed */
} pqw1_parser;

void pqw1_parser_init(pqw1_parser *p);

/*
 * Feed one byte. On PQW1_FRAME, `*f` describes the frame. The payload stays
 * valid until the next call. After PQW1_ERR_LEN or PQW1_ERR_CRC the parser
 * has dropped one byte and may still hold a complete frame behind it: call
 * pqw1_poll until it returns PQW1_NEED_MORE.
 */
pqw1_event pqw1_feed(pqw1_parser *p, uint8_t byte, pqw1_frame *f);

/* Look at the buffered bytes again without adding any. */
pqw1_event pqw1_poll(pqw1_parser *p, pqw1_frame *f);

/* Base64 (standard alphabet, padded). Returns the output length or 0 on error / overflow. */
size_t pqw1_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap);
size_t pqw1_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap);

/* Wrap a frame as an '@' line including the newline. Returns length or 0. */
size_t pqw1_line_encode(const uint8_t *frame, size_t frame_len, char *out, size_t cap);

/*
 * Decode a complete line (without the newline) into frame bytes. Returns the
 * frame length, 0 if the line is a diagnostic or malformed.
 */
size_t pqw1_line_decode(const char *line, size_t n, uint8_t *frame, size_t cap);

#endif
