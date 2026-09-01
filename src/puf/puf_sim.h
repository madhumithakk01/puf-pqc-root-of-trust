#ifndef ROT_PUF_SIM_H
#define ROT_PUF_SIM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Simulated PUF for pre-hardware development.
 *
 * This is NOT a security primitive. It models a silicon PUF's observable
 * behaviour -- a device-unique raw fingerprint that reads back with some bit
 * error each power-up -- so the fuzzy extractor and the layers above it can be
 * built and characterised against controllable noise before real hardware
 * exists. It does not commit to SRAM-PUF vs RO-PUF or any particular part.
 */

/*
 * Clean (noise-free) raw response for a simulated device:
 *
 *   out = SHAKE256("puf-sim/response/v1" || LE32(device_id))   [out_len bytes]
 *
 * Deterministic: a device_id always yields the same bytes. Distinct ids yield
 * uniformly unrelated bytes (pairwise Hamming distance ~50 %). The output is an
 * XOF stream, so a shorter request is a prefix of a longer one.
 */
void puf_sim_response(uint32_t device_id, uint8_t *out, size_t out_len);

/*
 * Raw response as read on one simulated power-up: the clean response with each
 * bit flipped independently with probability ber_ppm / 1e6. The flip pattern is
 *
 *   SHAKE256("puf-sim/noise/v1" || LE32(device_id) || noise)
 *
 * so a given (device_id, ber_ppm, noise) is reproducible; vary `noise` to model
 * successive power-ups. ber_ppm is clamped to 1e6; ber_ppm == 0 returns the
 * clean response.
 */
void puf_sim_response_noisy(uint32_t device_id, uint32_t ber_ppm,
                            const uint8_t *noise, size_t noise_len,
                            uint8_t *out, size_t out_len);

/* Differing bits between two equal-length buffers. */
size_t puf_sim_hamming(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* ROT_PUF_SIM_H */
