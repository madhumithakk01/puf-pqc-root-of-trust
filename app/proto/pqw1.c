#include "proto/pqw1.h"

#include "rot/rot_crc32.h"
#include "rot/rot_util.h"

#include <string.h>

size_t pqw1_encode(uint8_t *out, size_t cap, uint8_t type, uint8_t flags, uint16_t seq,
                   const uint8_t *payload, uint32_t len)
{
    size_t total = PQW1_HDR + (size_t)len + 4u;

    if (len > PQW1_MAX_PAYLOAD || total > cap) {
        return 0;
    }
    memcpy(out, "PQW1", 4);
    out[4] = type;
    out[5] = flags;
    rot_put16(out + 6, seq);
    rot_put32(out + 8, len);
    if (len) {
        memcpy(out + PQW1_HDR, payload, len);
    }
    rot_put32(out + PQW1_HDR + len, rot_crc32(0, out + 4, 8u + len));
    return total;
}

void pqw1_parser_init(pqw1_parser *p)
{
    p->have = 0;
    p->want = 0;
    p->consumed_frame = 0;
}

/* Drop `n` bytes from the front and keep scanning for a magic. */
static void shift(pqw1_parser *p, size_t n)
{
    if (n >= p->have) {
        p->have = 0;
    } else {
        memmove(p->buf, p->buf + n, p->have - n);
        p->have -= n;
    }
    p->want = 0;
}

/* Position of the first byte that may start a magic, or `have` if none. */
static size_t resync_point(const pqw1_parser *p)
{
    static const char magic[4] = { 'P', 'Q', 'W', '1' };
    for (size_t i = 0; i < p->have; i++) {
        size_t m = p->have - i < 4 ? p->have - i : 4;
        if (memcmp(p->buf + i, magic, m) == 0) {
            return i;
        }
    }
    return p->have;
}

static pqw1_event scan(pqw1_parser *p, pqw1_frame *f)
{
    size_t skip = resync_point(p);

    if (skip) {
        shift(p, skip);
    }
    if (p->have < 4) {
        return PQW1_NEED_MORE;
    }
    if (p->want == 0 && p->have >= PQW1_HDR) {
        uint32_t len = rot_get32(p->buf + 8);
        if (len > PQW1_MAX_PAYLOAD) {
            shift(p, 1);
            return PQW1_ERR_LEN;
        }
        p->want = PQW1_HDR + (size_t)len + 4u;
    }
    if (p->want == 0 || p->have < p->want) {
        return PQW1_NEED_MORE;
    }

    {
        uint32_t len = rot_get32(p->buf + 8);
        uint32_t crc = rot_get32(p->buf + PQW1_HDR + len);
        if (rot_crc32(0, p->buf + 4, 8u + len) != crc) {
            shift(p, 1);   /* the magic may have been a false start inside other data */
            return PQW1_ERR_CRC;
        }
        f->type = p->buf[4];
        f->flags = p->buf[5];
        f->seq = rot_get16(p->buf + 6);
        f->len = len;
        f->payload = p->buf + PQW1_HDR;
        p->consumed_frame = 1;
        return PQW1_FRAME;
    }
}

pqw1_event pqw1_poll(pqw1_parser *p, pqw1_frame *f)
{
    if (p->consumed_frame) {
        p->have = 0;
        p->want = 0;
        p->consumed_frame = 0;
    }
    return scan(p, f);
}

pqw1_event pqw1_feed(pqw1_parser *p, uint8_t byte, pqw1_frame *f)
{
    if (p->consumed_frame) {
        p->have = 0;
        p->want = 0;
        p->consumed_frame = 0;
    }
    if (p->have < sizeof p->buf) {
        p->buf[p->have++] = byte;
    }
    return scan(p, f);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t pqw1_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t o = 0;
    if (cap < ((n + 2) / 3) * 4 + 1) {
        return 0;
    }
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? B64[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t pqw1_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap)
{
    size_t o = 0;
    if (n == 0 || n % 4 != 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i += 4) {
        int a = b64val(in[i]), b = b64val(in[i + 1]);
        int c = in[i + 2] == '=' ? -2 : b64val(in[i + 2]);
        int d = in[i + 3] == '=' ? -2 : b64val(in[i + 3]);
        uint32_t v;

        if (a < 0 || b < 0 || c == -1 || d == -1) return 0;
        if ((c == -2 && d != -2) || ((c == -2 || d == -2) && i + 4 != n)) return 0;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)(c < 0 ? 0 : c) << 6) | (uint32_t)(d < 0 ? 0 : d);
        if (o + 1 > cap) return 0;
        out[o++] = (uint8_t)(v >> 16);
        if (c != -2) {
            if (o + 1 > cap) return 0;
            out[o++] = (uint8_t)(v >> 8);
        }
        if (d != -2) {
            if (o + 1 > cap) return 0;
            out[o++] = (uint8_t)v;
        }
    }
    return o;
}

size_t pqw1_line_encode(const uint8_t *frame, size_t frame_len, char *out, size_t cap)
{
    size_t n;
    if (cap < 3) {
        return 0;
    }
    out[0] = '@';
    n = pqw1_b64_encode(frame, frame_len, out + 1, cap - 2);
    if (n == 0) {
        return 0;
    }
    out[1 + n] = '\n';
    return n + 2;
}

size_t pqw1_line_decode(const char *line, size_t n, uint8_t *frame, size_t cap)
{
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        n--;
    }
    if (n < 2 || line[0] != '@') {
        return 0;
    }
    return pqw1_b64_decode(line + 1, n - 1, frame, cap);
}
