#ifndef ROT_FUZZY_EXTRACTOR_H
#define ROT_FUZZY_EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzzy extractor over a noisy PUF response, code-offset construction with a
 * repetition code (a secure sketch plus a SHAKE256 extractor).
 *
 * Gen(w)  -> (helper P, key R):  P = w XOR Encode(random message),
 *                                R = SHAKE256("fuzzy/v1/extract" || w)
 * Rep(w', P) -> R:  majority-decode each repetition block of (w' XOR P),
 *                   recover w, re-extract R. Equal to Gen's R whenever the
 *                   per-block error count stays within floor(rep/2).
 *
 * Bits are indexed LSB-first within each byte. Repetition block b occupies
 * bits [b*rep, b*rep + rep); the code message is `blocks` bits, so the helper
 * leaks at most (blocks*rep - blocks) bits of w and >= `blocks` bits of a
 * full-entropy w survive. Pick `blocks` >= the desired key strength (128).
 */

#define FUZZY_MAX_RESPONSE_BYTES 512

typedef struct {
    unsigned blocks; /* information bits, >= 1 */
    unsigned rep;    /* repetition factor, odd, >= 1 */
} fuzzy_params;

/* PUF-response / helper-data length these params consume, or 0 if invalid
 * (rep even, blocks*rep not a multiple of 8, or over FUZZY_MAX_RESPONSE_BYTES). */
size_t fuzzy_response_bytes(fuzzy_params p);

/*
 * Enrolment. `w` is the clean response (fuzzy_response_bytes(p) long), `rnd`
 * supplies the random code message (>= ceil(blocks/8) bytes). Writes `helper`
 * (same length as `w`) and `key` (`key_len` bytes). Returns 0, or negative on
 * a parameter / length error.
 */
int fuzzy_gen(fuzzy_params p,
              const uint8_t *w, size_t w_len,
              const uint8_t *rnd, size_t rnd_len,
              uint8_t *helper, size_t helper_len,
              uint8_t *key, size_t key_len);

/*
 * Reproduction. `w_noisy` is a fresh noisy read, `helper` from fuzzy_gen.
 * Writes `key`. Returns 0, or negative on a parameter / length error. A
 * successful return does not imply the key matches enrolment -- that holds
 * only while the noise stays within the code's correction capacity.
 */
int fuzzy_rep(fuzzy_params p,
              const uint8_t *w_noisy, size_t w_len,
              const uint8_t *helper, size_t helper_len,
              uint8_t *key, size_t key_len);

#endif /* ROT_FUZZY_EXTRACTOR_H */
