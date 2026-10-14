#ifndef APP_MAX30102_H
#define APP_MAX30102_H

#include <stddef.h>
#include <stdint.h>

/*
 * MAX30102 pulse-oximeter driver over an abstract I2C bus.
 *
 * Configuration: SpO2 mode (red + IR), 100 samples/s, 411 us pulse width,
 * 4096 nA ADC range, about 7 mA per LED, FIFO rollover on. Samples are 18-bit,
 * six bytes each (red then IR) from the FIFO.
 */

#define MAX30102_ADDR        0x57
#define MAX30102_PART_ID     0x15

#define MAX30102_REG_INT_STATUS1 0x00
#define MAX30102_REG_FIFO_WR     0x04
#define MAX30102_REG_FIFO_OVF    0x05
#define MAX30102_REG_FIFO_RD     0x06
#define MAX30102_REG_FIFO_DATA   0x07
#define MAX30102_REG_FIFO_CFG    0x08
#define MAX30102_REG_MODE        0x09
#define MAX30102_REG_SPO2_CFG    0x0A
#define MAX30102_REG_LED1_PA     0x0C
#define MAX30102_REG_LED2_PA     0x0D
#define MAX30102_REG_TEMP_INT    0x1F
#define MAX30102_REG_TEMP_FRAC   0x20
#define MAX30102_REG_TEMP_CFG    0x21
#define MAX30102_REG_REV_ID      0xFE
#define MAX30102_REG_PART_ID     0xFF

typedef struct {
    void *ctx;
    /* Both return 0 on success. `addr` is the 7-bit device address. */
    int (*write_reg)(void *ctx, uint8_t addr, uint8_t reg, const uint8_t *data, size_t n);
    int (*read_reg)(void *ctx, uint8_t addr, uint8_t reg, uint8_t *data, size_t n);
    void (*delay_ms)(void *ctx, unsigned ms);
} max30102_bus;

typedef struct {
    max30102_bus bus;
    uint8_t part_id;
    uint8_t rev_id;
} max30102;

enum {
    MAX30102_OK = 0,
    MAX30102_ERR_BUS = -1,
    MAX30102_ERR_PART = -2,    /* PART_ID is not 0x15 */
    MAX30102_ERR_RESET = -3,   /* reset bit never cleared */
};

/* Reset, check the part id, configure, clear the FIFO. */
int max30102_init(max30102 *d, const max30102_bus *bus);

/* Read PART_ID only (used by the health probe). Returns 0 and *id. */
int max30102_read_part_id(max30102 *d, uint8_t *id);

/*
 * Drain up to `max` samples from the FIFO. Returns the count (>= 0) or a
 * negative error. 18-bit values, red and IR in matching positions.
 */
int max30102_read_fifo(max30102 *d, uint32_t *red, uint32_t *ir, size_t max);

/* Die temperature in tenths of a degree C. Returns 0 and *t_x10. */
int max30102_read_temp(max30102 *d, int *t_x10);

#endif
