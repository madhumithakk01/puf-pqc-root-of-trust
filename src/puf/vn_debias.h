#ifndef ROT_VN_DEBIAS_H
#define ROT_VN_DEBIAS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Von Neumann debiasing of a raw SRAM window.
 *
 * Bits are indexed LSB-first within each byte. Pair i is bits (2i, 2i+1). A
 * pair is usable when its two bits differ; the debiased bit is the first bit
 * of the pair. Selection happens once, at enrollment, on a reference formed
 * by majority vote over several fresh reads; the resulting bitmap is public
 * helper data (bit i set = pair i selected). Reconstruction reads the same
 * pairs from a single fresh read.
 */

/* Majority vote per bit over `n_reads` (odd) reads of `len` bytes each. */
int vn_majority(const uint8_t *const *reads, unsigned n_reads, size_t len,
                uint8_t *out);

/*
 * Mask with bit set where all reads agree on that bit (a stable bit).
 * Used to restrict selection to pairs whose both bits are stable.
 */
int vn_stable_mask(const uint8_t *const *reads, unsigned n_reads, size_t len,
                   uint8_t *mask);

/*
 * Select the first `want` usable pairs of `ref` (len bytes), ascending.
 * `stable` is NULL or a stable_mask; when given, a pair is usable only if
 * both of its bits are stable. `bitmap` receives len/2 bytes (one bit per
 * pair, zeroed first). `*available` receives the number of usable pairs in
 * the whole reference. Returns 0 when at least `want` pairs exist and exactly
 * `want` are marked, -1 otherwise (the bitmap then marks all usable pairs).
 */
int vn_select_pairs(const uint8_t *ref, size_t len, const uint8_t *stable,
                    unsigned want, uint8_t *bitmap, unsigned *available);

/*
 * Debiased bits of `window` for the pairs marked in `bitmap`, packed
 * LSB-first into `out` (ceil(want/8) bytes, zeroed first). `want` is the
 * number of marked pairs expected; returns 0, or -1 if the bitmap marks a
 * different number.
 */
int vn_extract(const uint8_t *window, size_t len, const uint8_t *bitmap,
               unsigned want, uint8_t *out);

#endif
