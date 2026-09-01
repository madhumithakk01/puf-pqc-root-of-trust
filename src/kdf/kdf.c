#include "kdf/kdf.h"

#include "fips202.h"

void rot_kdf_derive(const uint8_t *key, size_t key_len,
                    const uint8_t *label, size_t label_len,
                    uint8_t *out, size_t out_len)
{
    shake256incctx st;

    shake256_inc_init(&st);
    shake256_inc_absorb(&st, key, key_len);
    shake256_inc_absorb(&st, label, label_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, out_len, &st);
    shake256_inc_ctx_release(&st);
}
