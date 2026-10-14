#ifndef ROT_FLASH_H
#define ROT_FLASH_H

#include "rot/rot_flash_map.h"
#include "rot/rot_platform.h"

/* Thin helpers over the platform flash ops. */

int rot_flash_read(const rot_platform *p, uint32_t off, uint8_t *buf, size_t n);

/*
 * Replace the sector at `off` with `len` bytes (<= one sector): erase, then
 * program `data` padded to a whole number of pages with 0xFF. Returns 0 or a
 * negative error. A power cut leaves a partly erased or partly programmed
 * sector; every record format tolerates that.
 */
int rot_flash_put(const rot_platform *p, uint32_t off, const uint8_t *data, size_t len);

/* Erase `len` bytes (multiple of the sector size) starting at `off`. */
int rot_flash_erase(const rot_platform *p, uint32_t off, size_t len);

/* Program without erasing (target must be erased). */
int rot_flash_program(const rot_platform *p, uint32_t off, const uint8_t *data, size_t len);

/* 1 if the whole sector reads 0xFF. */
int rot_flash_sector_blank(const rot_platform *p, uint32_t off);

#endif
