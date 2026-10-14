#include "puf/vn_debias.h"

#include <string.h>

static unsigned bit_get(const uint8_t *b, size_t i)
{
    return (b[i >> 3] >> (i & 7u)) & 1u;
}

int vn_majority(const uint8_t *const *reads, unsigned n_reads, size_t len,
                uint8_t *out)
{
    if (!reads || !out || n_reads == 0 || (n_reads & 1u) == 0) return -1;
    memset(out, 0, len);
    for (size_t i = 0; i < len * 8; i++) {
        unsigned ones = 0;
        for (unsigned r = 0; r < n_reads; r++) ones += bit_get(reads[r], i);
        if (2u * ones > n_reads) out[i >> 3] |= (uint8_t)(1u << (i & 7u));
    }
    return 0;
}

int vn_stable_mask(const uint8_t *const *reads, unsigned n_reads, size_t len,
                   uint8_t *mask)
{
    if (!reads || !mask || n_reads == 0) return -1;
    for (size_t k = 0; k < len; k++) {
        uint8_t all1 = 0xFF, all0 = 0xFF;
        for (unsigned r = 0; r < n_reads; r++) {
            all1 &= reads[r][k];
            all0 &= (uint8_t)~reads[r][k];
        }
        mask[k] = (uint8_t)(all1 | all0);
    }
    return 0;
}

int vn_select_pairs(const uint8_t *ref, size_t len, const uint8_t *stable,
                    unsigned want, uint8_t *bitmap, unsigned *available)
{
    size_t pairs = len * 4; /* len * 8 bits / 2 */
    unsigned n = 0, marked = 0;

    memset(bitmap, 0, len / 2);
    for (size_t i = 0; i < pairs; i++) {
        if (bit_get(ref, 2 * i) == bit_get(ref, 2 * i + 1)) continue;
        if (stable && !(bit_get(stable, 2 * i) && bit_get(stable, 2 * i + 1))) continue;
        n++;
        if (marked < want) {
            bitmap[i >> 3] |= (uint8_t)(1u << (i & 7u));
            marked++;
        }
    }
    if (available) *available = n;
    return n >= want ? 0 : -1;
}

int vn_extract(const uint8_t *window, size_t len, const uint8_t *bitmap,
               unsigned want, uint8_t *out)
{
    size_t pairs = len * 4;
    unsigned j = 0;

    memset(out, 0, (want + 7u) / 8u);
    for (size_t i = 0; i < pairs; i++) {
        if (!bit_get(bitmap, i)) continue;
        if (j >= want) return -1;
        if (bit_get(window, 2 * i)) out[j >> 3] |= (uint8_t)(1u << (j & 7u));
        j++;
    }
    return j == want ? 0 : -1;
}
