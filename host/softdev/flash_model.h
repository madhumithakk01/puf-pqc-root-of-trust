#ifndef SOFTDEV_FLASH_MODEL_H
#define SOFTDEV_FLASH_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include "rot/rot_platform.h"

/*
 * 4 MB flash model for host tests and the software device.
 *
 * Semantics follow the NOR flash on the board: erase sets a 4 KB sector to
 * 0xFF, program only clears bits. A power cut can be injected: after
 * `budget` cost units every flash operation fails and the operation that ran
 * out is applied only partly. Costs: one unit per byte programmed; one unit
 * per 256 bytes erased (16 per sector, the erased prefix is applied).
 * Reading never costs anything.
 */

typedef struct {
    uint8_t *mem;
    size_t   size;
    int64_t  budget;      /* remaining units; < 0 means no cut armed */
    int      dead;        /* set once a cut has happened */
    uint64_t spent;       /* units consumed since the last reset */
    uint64_t erases;      /* sectors erased since the last reset */
} flash_model;

/* Allocate and fill with 0xFF. Returns 0 or -1. */
int  flash_model_init(flash_model *f, size_t size);
void flash_model_free(flash_model *f);

/* Arm a power cut after `units` more units (>= 0). */
void flash_model_arm_cut(flash_model *f, int64_t units);
void flash_model_disarm(flash_model *f);
/* Restore power after a cut: operations work again, contents are kept. */
void flash_model_power_on(flash_model *f);

/* Fill a rot_platform with this model and a deterministic TRNG. */
void flash_model_platform(flash_model *f, rot_platform *p);

/* Optional file persistence (the software device). Returns 0 or -1. */
int flash_model_load(flash_model *f, const char *path);
int flash_model_save(const flash_model *f, const char *path);

#endif
