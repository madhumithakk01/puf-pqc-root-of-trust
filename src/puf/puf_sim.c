#include "puf/puf_sim.h"

#include "fips202.h"

#define RESP_DOMAIN  "puf-sim/response/v1"
#define NOISE_DOMAIN "puf-sim/noise/v1"
#define BER_SCALE    1000000u

static void put_le32(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

void puf_sim_response(uint32_t device_id, uint8_t *out, size_t out_len)
{
    uint8_t id[4];
    shake256incctx st;

    put_le32(id, device_id);
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)RESP_DOMAIN, sizeof RESP_DOMAIN - 1);
    shake256_inc_absorb(&st, id, sizeof id);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, out_len, &st);
    shake256_inc_ctx_release(&st);
}

void puf_sim_response_noisy(uint32_t device_id, uint32_t ber_ppm,
                            const uint8_t *noise, size_t noise_len,
                            uint8_t *out, size_t out_len)
{
    uint8_t id[4];
    shake256incctx st;

    if (ber_ppm > BER_SCALE) {
        ber_ppm = BER_SCALE;
    }

    puf_sim_response(device_id, out, out_len);
    if (ber_ppm == 0u || out_len == 0u) {
        return;
    }

    put_le32(id, device_id);
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, (const uint8_t *)NOISE_DOMAIN, sizeof NOISE_DOMAIN - 1);
    shake256_inc_absorb(&st, id, sizeof id);
    if (noise_len != 0u) {
        shake256_inc_absorb(&st, noise, noise_len);
    }
    shake256_inc_finalize(&st);

    for (size_t i = 0; i < out_len * 8u; i++) {
        uint8_t d[4];
        shake256_inc_squeeze(d, sizeof d, &st);
        uint32_t draw = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                        ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
        uint32_t bucket = (uint32_t)(((uint64_t)draw * BER_SCALE) >> 32);
        if (bucket < ber_ppm) {
            out[i >> 3] ^= (uint8_t)(1u << (i & 7u));
        }
    }
    shake256_inc_ctx_release(&st);
}

size_t puf_sim_hamming(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t bits = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t x = (uint8_t)(a[i] ^ b[i]);
        while (x != 0u) {
            bits += x & 1u;
            x = (uint8_t)(x >> 1);
        }
    }
    return bits;
}
