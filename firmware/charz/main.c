/*
 * Characterization firmware. Built with the RoT's memory layout and boot path
 * so the boot ROM behaves the same. The PUF zone is 20 blocks of 4 KB at
 * 0x20068000. On every boot, before anything else runs, charz measures each
 * block and prints one JSON line per block: reset cause, method, die
 * temperature, ones_permille, zero32 (all-0x00 32-byte chunks) and ff32.
 *
 * Commands over USB:
 *   cause | zone | temp
 *   probe <k>                       raw hex of a probe block (0, 4, 12, 16); key candidates are refused
 *   remanence <00|ff> <pstate:MS|run|por|watchdog>
 *   loop <n> <ms>                   n automatic Pstate cycles
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hardware/watchdog.h"
#include "pico/stdio_usb.h"
#include "pico/stdlib.h"

#include "platform/rp2350/rp2350_platform.h"
#include "rot/rot_handoff.h"
#include "rot/rot_reset.h"

#define BLOCKS 20u
#define LOOP_LEFT_SCRATCH SCR_REFRESHES
#define LOOP_MS_SCRATCH SCR_INSTALL

typedef struct {
    uint16_t ones_permille;
    uint16_t zero32, ff32;
} block_stat;

static block_stat stats[BLOCKS];

static int is_probe(unsigned k) { return k == 0 || k == 4 || k == 12 || k == 16; }

static void measure(void)
{
    for (unsigned k = 0; k < BLOCKS; k++) {
        const uint32_t *w = (const uint32_t *)(PUF_ZONE_BASE + k * PUF_BLOCK_SIZE);
        uint32_t ones = 0;
        uint16_t z = 0, f = 0;
        for (unsigned i = 0; i < PUF_BLOCK_SIZE / 4; i += 8) {
            uint32_t all_and = 0xFFFFFFFFu, all_or = 0;
            for (unsigned j = 0; j < 8; j++) {
                uint32_t v = w[i + j];
                ones += (uint32_t)__builtin_popcount(v);
                all_and &= v;
                all_or |= v;
            }
            if (all_or == 0) z++;
            if (all_and == 0xFFFFFFFFu) f++;
        }
        stats[k].ones_permille = (uint16_t)(ones * 1000u / (PUF_BLOCK_SIZE * 8u));
        stats[k].zero32 = z;
        stats[k].ff32 = f;
    }
}

static void print_zone(const char *cause_name, int fresh, unsigned pattern, const char *method, int temp)
{
    for (unsigned k = 0; k < BLOCKS; k++) {
        printf("{\"ev\":\"zone\",\"block\":%u,\"cause\":\"%s\",\"fresh\":%d,\"pattern\":%u,\"method\":\"%s\","
               "\"temp_x10\":%d,\"ones_permille\":%u,\"zero32\":%u,\"ff32\":%u}\n",
               k, cause_name, fresh, pattern, method, temp, stats[k].ones_permille, stats[k].zero32, stats[k].ff32);
    }
}

static const char *cause_name(unsigned c)
{
    static const char *n[] = { "unknown", "por", "run", "pstate", "watchdog", "brownout", "debug", "other" };
    return c < 8 ? n[c] : "?";
}

static void fill_zone(uint32_t v)
{
    volatile uint32_t *z = (volatile uint32_t *)PUF_ZONE_BASE;
    for (unsigned i = 0; i < PUF_ZONE_SIZE / 4; i++) z[i] = v;
}

static void pstate_off(unsigned ms, unsigned cause)
{
    rp2350_scratch_set(SCR_MARKER, rot_reset_marker((uint8_t)cause));
    stdio_flush();
    sleep_ms(30);
    rp2350_refresh(ms);
    printf("{\"ev\":\"refresh_failed\"}\n");
}

int main(void)
{
    uint32_t bits = rp2350_chip_reset_bits();
    uint32_t s0 = rp2350_scratch_get(SCR_MARKER);
    rot_reset_verdict v = rot_reset_classify(bits, s0);
    unsigned pattern, loops, method_ms;
    char line[96];
    unsigned len = 0;

    measure();                                   /* before anything else touches memory */
    pattern = rp2350_scratch_get(SCR_CHARZ);
    loops = rp2350_scratch_get(LOOP_LEFT_SCRATCH);
    method_ms = rp2350_scratch_get(LOOP_MS_SCRATCH);
    rp2350_scratch_set(SCR_MARKER, 0);
    rp2350_scratch_set(SCR_CHARZ, 0);

    stdio_init_all();
    for (int i = 0; i < 100 && !stdio_usb_connected(); i++) sleep_ms(20);
    rp2350_platform_init(&(rot_platform){ 0 });
    {
        int temp = rp2350_die_temp_x10();
        const char *method = pattern ? "remanence" : loops ? "loop" : "boot";
        print_zone(cause_name(v.cause), v.fresh, pattern, method, temp);
        printf("{\"ev\":\"charz\",\"cause\":\"%s\",\"fresh\":%d,\"original\":\"%s\",\"temp_x10\":%d}\n",
               cause_name(v.cause), v.fresh, cause_name(v.original), temp);
    }

    if (loops) {
        rp2350_scratch_set(LOOP_LEFT_SCRATCH, loops - 1);
        if (loops > 1) pstate_off(method_ms, RC_PSTATE);
        rp2350_scratch_set(LOOP_LEFT_SCRATCH, 0);
    }

    for (;;) {
        int c = getchar_timeout_us(10000);
        if (c == PICO_ERROR_TIMEOUT) continue;
        if (c == '\r') continue;
        if (c != '\n') {
            if (len + 1 < sizeof line) line[len++] = (char)c;
            continue;
        }
        line[len] = 0;
        len = 0;

        if (!strcmp(line, "cause")) {
            printf("{\"ev\":\"cause\",\"bits\":\"0x%08x\",\"cause\":\"%s\",\"fresh\":%d}\n", (unsigned)bits,
                   cause_name(v.cause), v.fresh);
        } else if (!strcmp(line, "zone")) {
            print_zone(cause_name(v.cause), v.fresh, 0, "query", rp2350_die_temp_x10());
        } else if (!strcmp(line, "temp")) {
            printf("{\"ev\":\"temp\",\"temp_x10\":%d}\n", rp2350_die_temp_x10());
        } else if (!strncmp(line, "probe ", 6)) {
            unsigned k = (unsigned)atoi(line + 6);
            if (!is_probe(k)) {
                printf("{\"ev\":\"refused\",\"why\":\"block %u is a key candidate or out of range\"}\n", k);
            } else {
                const uint8_t *b = (const uint8_t *)(PUF_ZONE_BASE + k * PUF_BLOCK_SIZE);
                printf("{\"ev\":\"probe\",\"block\":%u,\"hex\":\"", k);
                for (unsigned i = 0; i < PUF_BLOCK_SIZE; i++) printf("%02x", b[i]);
                printf("\"}\n");
            }
        } else if (!strncmp(line, "remanence ", 10)) {
            char pat[8], how[24];
            if (sscanf(line + 10, "%7s %23s", pat, how) == 2) {
                unsigned id = !strcmp(pat, "ff") ? 2 : 1;
                fill_zone(id == 2 ? 0xFFFFFFFFu : 0u);
                rp2350_scratch_set(SCR_CHARZ, id);
                if (!strncmp(how, "pstate:", 7)) {
                    pstate_off((unsigned)atoi(how + 7), v.cause);
                } else if (!strcmp(how, "watchdog")) {
                    stdio_flush();
                    watchdog_reboot(0, 0, 10);
                } else {
                    printf("{\"ev\":\"await_human\",\"do\":\"%s\"}\n", !strcmp(how, "run") ? "touch RUN to GND for 1 s" : "unplug USB for 2 s");
                }
            }
        } else if (!strncmp(line, "loop ", 5)) {
            unsigned n = 0, ms = 0;
            if (sscanf(line + 5, "%u %u", &n, &ms) == 2 && n > 0) {
                rp2350_scratch_set(LOOP_LEFT_SCRATCH, n);
                rp2350_scratch_set(LOOP_MS_SCRATCH, ms);
                pstate_off(ms, RC_PSTATE);
            }
        }
    }
}
