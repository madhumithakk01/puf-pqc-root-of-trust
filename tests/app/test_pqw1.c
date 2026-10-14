/*
 * PQW1 framing: round trip, byte-at-a-time and burst parsing, bad CRC,
 * oversize length, garbage between frames, resynchronisation, and the
 * base64 line adapter.
 */

#include "proto/pqw1.h"

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

typedef struct {
    int frames, err_crc, err_len;
    pqw1_frame last;
    uint8_t last_payload[PQW1_MAX_PAYLOAD];
    uint8_t types[32];
} sink_t;

static void feed_all(pqw1_parser *p, sink_t *s, const uint8_t *data, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        pqw1_frame f;
        pqw1_event e = pqw1_feed(p, data[i], &f);
        for (;;) {
            if (e == PQW1_FRAME) {
                if (s->frames < 32) s->types[s->frames] = f.type;
                s->frames++;
                s->last = f;
                memcpy(s->last_payload, f.payload, f.len);
                s->last.payload = s->last_payload;
            } else if (e == PQW1_ERR_CRC) s->err_crc++;
            else if (e == PQW1_ERR_LEN) s->err_len++;
            else break;
            e = pqw1_poll(p, &f);
        }
    }
}

int main(void)
{
    static uint8_t buf[PQW1_MAX_FRAME * 2], payload[PQW1_MAX_PAYLOAD];
    static pqw1_parser p;
    static sink_t s;
    size_t n;

    for (unsigned i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i * 7 + 1);

    n = pqw1_encode(buf, sizeof buf, PQW1_HELLO, 0, 1, NULL, 0);
    check("empty frame is 16 bytes", n == 16 && memcmp(buf, "PQW1", 4) == 0 && buf[4] == 1);
    {
        /* known answer: CRC32 over type..len of an empty HELLO seq 1 */
        uint8_t kat[16] = { 'P','Q','W','1', 0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
        extern uint32_t rot_crc32(uint32_t, const uint8_t *, size_t);
        uint32_t c = rot_crc32(0, kat + 4, 8);
        kat[12] = (uint8_t)c; kat[13] = (uint8_t)(c >> 8); kat[14] = (uint8_t)(c >> 16); kat[15] = (uint8_t)(c >> 24);
        check("empty frame matches the documented layout", memcmp(buf, kat, 16) == 0);
    }

    pqw1_parser_init(&p);
    memset(&s, 0, sizeof s);
    feed_all(&p, &s, buf, n);
    check("byte-at-a-time parse of an empty frame", s.frames == 1 && s.last.type == PQW1_HELLO
          && s.last.seq == 1 && s.last.len == 0);

    n = pqw1_encode(buf, sizeof buf, PQW1_PKG_CHUNK, PQW1_FLAG_LAST, 77, payload, 4096);
    check("4 KB chunk encodes", n == PQW1_HDR + 4096 + 4);
    memset(&s, 0, sizeof s);
    feed_all(&p, &s, buf, n);
    check("chunk parses with flags, seq and payload", s.frames == 1 && s.last.flags == PQW1_FLAG_LAST
          && s.last.seq == 77 && s.last.len == 4096 && memcmp(s.last.payload, payload, 4096) == 0);

    n = pqw1_encode(buf, sizeof buf, PQW1_PKG_CHUNK, 0, 2, payload, PQW1_MAX_PAYLOAD);
    check("maximum payload encodes", n == PQW1_MAX_FRAME);
    memset(&s, 0, sizeof s);
    feed_all(&p, &s, buf, n);
    check("maximum payload parses", s.frames == 1 && s.last.len == PQW1_MAX_PAYLOAD);
    check("oversize payload refused at encode", pqw1_encode(buf, sizeof buf, 1, 0, 0, payload, PQW1_MAX_PAYLOAD + 1) == 0);
    check("too small an output buffer refused", pqw1_encode(buf, 15, 1, 0, 0, NULL, 0) == 0);

    /* three frames back to back, one burst */
    {
        size_t o = 0;
        o += pqw1_encode(buf + o, sizeof buf - o, PQW1_HELLO, 0, 1, NULL, 0);
        o += pqw1_encode(buf + o, sizeof buf - o, PQW1_ATTEST_REQ, 0, 2, payload, 32);
        o += pqw1_encode(buf + o, sizeof buf - o, PQW1_GET_ATTEST, 0, 3, NULL, 0);
        memset(&s, 0, sizeof s);
        feed_all(&p, &s, buf, o);
        check("three frames in one burst", s.frames == 3 && s.types[0] == PQW1_HELLO
              && s.types[1] == PQW1_ATTEST_REQ && s.types[2] == PQW1_GET_ATTEST);
    }

    /* bad CRC: flip a payload byte */
    n = pqw1_encode(buf, sizeof buf, PQW1_ATTEST_REQ, 0, 5, payload, 32);
    buf[PQW1_HDR + 3] ^= 1;
    memset(&s, 0, sizeof s);
    feed_all(&p, &s, buf, n);
    check("a flipped payload bit is a CRC error, no frame", s.frames == 0 && s.err_crc >= 1);

    /* the parser recovers and takes the next good frame */
    n = pqw1_encode(buf, sizeof buf, PQW1_GET_ATTEST, 0, 6, NULL, 0);
    feed_all(&p, &s, buf, n);
    check("the next good frame is accepted after the error", s.frames == 1 && s.last.seq == 6);

    /* oversize announced length */
    {
        uint8_t bad[16] = { 'P','Q','W','1', 0x06, 0, 1, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0 };
        memset(&s, 0, sizeof s);
        feed_all(&p, &s, bad, sizeof bad);
        check("announced length above the maximum is refused", s.frames == 0 && s.err_len >= 1);
        n = pqw1_encode(buf, sizeof buf, PQW1_HELLO, 0, 7, NULL, 0);
        feed_all(&p, &s, buf, n);
        check("and the parser resynchronises on the next frame", s.frames == 1 && s.last.seq == 7);
    }

    /* garbage and partial magics before and between frames */
    {
        uint8_t junk[] = { 0x00, 'P', 'Q', 'x', 'P', 'Q', 'W', 0xFF, 0x13, 'P' };
        size_t o = 0;
        memcpy(buf + o, junk, sizeof junk); o += sizeof junk;
        o += pqw1_encode(buf + o, sizeof buf - o, PQW1_HELLO, 0, 8, NULL, 0);
        memcpy(buf + o, junk, sizeof junk); o += sizeof junk;
        o += pqw1_encode(buf + o, sizeof buf - o, PQW1_GET_IDENTITY, 0, 9, NULL, 0);
        memset(&s, 0, sizeof s);
        feed_all(&p, &s, buf, o);
        check("frames are found among garbage and partial magics", s.frames == 2 && s.types[0] == PQW1_HELLO
              && s.types[1] == PQW1_GET_IDENTITY);
    }

    /* a frame embedded in the payload of a corrupted frame */
    {
        uint8_t inner[64], outer[256];
        size_t il = pqw1_encode(inner, sizeof inner, PQW1_HELLO, 0, 11, NULL, 0);
        size_t ol = pqw1_encode(outer, sizeof outer, PQW1_PKG_CHUNK, 0, 10, inner, (uint32_t)il);
        outer[ol - 1] ^= 1; /* corrupt the outer CRC */
        memset(&s, 0, sizeof s);
        feed_all(&p, &s, outer, ol);
        check("the inner frame is recovered when the outer one is corrupt", s.frames == 1 && s.last.seq == 11);
    }

    /* base64 */
    {
        char text[64];
        uint8_t back[16];
        check("base64 of 'Man'", pqw1_b64_encode((const uint8_t *)"Man", 3, text, sizeof text) == 4 && strcmp(text, "TWFu") == 0);
        check("base64 of 'Ma' is padded", pqw1_b64_encode((const uint8_t *)"Ma", 2, text, sizeof text) == 4 && strcmp(text, "TWE=") == 0);
        check("base64 of 'M' is padded", pqw1_b64_encode((const uint8_t *)"M", 1, text, sizeof text) == 4 && strcmp(text, "TQ==") == 0);
        check("decode 'TWE='", pqw1_b64_decode("TWE=", 4, back, sizeof back) == 2 && memcmp(back, "Ma", 2) == 0);
        check("decode rejects bad characters", pqw1_b64_decode("TW!u", 4, back, sizeof back) == 0);
        check("decode rejects bad length", pqw1_b64_decode("TWFuT", 5, back, sizeof back) == 0);
        check("decode rejects padding in the middle", pqw1_b64_decode("TQ==TWFu", 8, back, sizeof back) == 0);
        check("decode rejects overflow", pqw1_b64_decode("TWFuTWFu", 8, back, 3) == 0);
    }
    {
        static char line[2 * PQW1_MAX_FRAME];
        static uint8_t round[PQW1_MAX_FRAME];
        n = pqw1_encode(buf, sizeof buf, PQW1_PKG_CHUNK, 0, 12, payload, 1000);
        size_t ll = pqw1_line_encode(buf, n, line, sizeof line);
        check("line starts with '@' and ends with a newline", ll > 2 && line[0] == '@' && line[ll - 1] == '\n');
        check("line round trip", pqw1_line_decode(line, ll, round, sizeof round) == n && memcmp(round, buf, n) == 0);
        check("diagnostic lines are not frames", pqw1_line_decode("# boot ok", 9, round, sizeof round) == 0);
        check("empty line is not a frame", pqw1_line_decode("", 0, round, sizeof round) == 0);
    }

    if (failures) {
        printf("test_pqw1: FAIL (%d)\n", failures);
        return 1;
    }
    printf("test_pqw1: PASS\n");
    return 0;
}
