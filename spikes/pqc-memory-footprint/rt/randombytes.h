#ifndef SPIKE_RANDOMBYTES_H
#define SPIKE_RANDOMBYTES_H

/*
 * Freestanding replacement for PQClean's common/randombytes.h, which pulls in
 * <unistd.h>. Placed ahead of third_party/pqclean/common on the include path.
 * The implementation (rt.c) is a fixed-seed SHAKE256 stream: deterministic, so
 * footprint and stack measurements are reproducible.
 */

#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t *output, size_t n);

#endif /* SPIKE_RANDOMBYTES_H */
