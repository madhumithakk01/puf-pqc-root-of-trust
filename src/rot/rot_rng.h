#ifndef ROT_RNG_H
#define ROT_RNG_H

#include <stddef.h>
#include <stdint.h>

/*
 * Randomness for the RoT.
 *
 * PQClean calls randombytes() for every random input. This module provides
 * that symbol with two modes:
 *
 *   one-shot seeded: the next calls consume exactly the bytes handed to
 *     rot_rng_seed_once(). ML-DSA key generation draws its 32-byte seed this
 *     way, so a key is a pure function of the PUF-derived seed. A call whose
 *     size does not match what remains of the seed is an error: it fails and
 *     the error flag is latched.
 *   conditioned hardware source: raw TRNG words absorbed into SHAKE256 with a
 *     label and counter, then squeezed. Used for signing randomness, RoT
 *     nonces and enrollment randomness.
 */

/* Raw entropy source: fills `n` bytes of raw TRNG output. */
typedef void (*rot_rng_raw_fn)(void *ctx, uint8_t *buf, size_t n);

void rot_rng_init(rot_rng_raw_fn raw, void *ctx);

/* Raw bytes absorbed per conditioned output block (>= 64, i.e. 512 bits). */
#define ROT_RNG_RAW_ABSORB_BYTES 64u

/* Conditioned random bytes. Returns 0, or -1 if no source is set. */
int rot_rng_bytes(uint8_t *out, size_t n);

/* Route the next randombytes() calls to `seed` (copied). */
void rot_rng_seed_once(const uint8_t *seed, size_t n);

/* 1 if seeded bytes remain unconsumed. */
int rot_rng_seed_pending(void);

/* 1 if a randombytes() call mismatched the seed; cleared by the next seed. */
int rot_rng_seed_error(void);

/* Drop any pending seed and clear the error flag. */
void rot_rng_reset(void);

#endif
