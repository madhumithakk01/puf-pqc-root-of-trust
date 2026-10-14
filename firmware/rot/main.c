/*
 * RoT image: runs from flash offset 0 on every reset.
 *
 *   B2  freshness gate: only a power-on, RUN or our own Pstate gives a usable
 *       PUF; anything else makes the RoT power its SRAM off and start over
 *   B3  copy the key window and zero it
 *   B4-B15  rot_boot_run (portable)
 *   B16 wipe and chain the application, or stay in SAFE / ENROLL mode
 *
 * Console: JSON lines over USB serial. Commands: STATUS, REBOOT, and in
 * ENROLL mode ENROLL <vendor public key, hex>.
 */

#include <stdio.h>
#include <string.h>

#include "hardware/watchdog.h"
#include "pico/stdio_usb.h"
#include "pico/stdlib.h"

#include "platform/rp2350/rp2350_platform.h"
#include "rot/rot_boot.h"
#include "rot/rot_enroll.h"
#include "rot/rot_flash.h"
#include "rot/rot_hev.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_reset.h"
#include "rot/rot_selftest.h"
#include "rot/rot_rng.h"
#include "rot/rot_util.h"

#ifndef ROT_CONSOLE_WAIT_MS
#define ROT_CONSOLE_WAIT_MS 1500
#endif
#ifndef ROT_T_OFF_MS
#define ROT_T_OFF_MS DEFAULT_T_OFF_MS
#endif
#ifndef ROT_SELFTEST
#define ROT_SELFTEST 0
#endif
#ifndef ROT_PMP_LOCK
#define ROT_PMP_LOCK 0
#endif
#ifndef ROT_STABLE_PAIRS
#define ROT_STABLE_PAIRS 0
#endif
#ifndef ROT_SIM_PUF
#define ROT_SIM_PUF 0
#endif
#ifndef ROT_BUILD_ID
#define ROT_BUILD_ID "0000000000000000000"
#endif

static rot_platform plat;
static rot_boot_in in;
static rot_boot_out out;

static void trng_for_rng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx;
    rp2350_trng_raw(buf, n);
}

/* One line from the console, without the newline. Returns length, 0 if none yet. */
static size_t read_line(char *buf, size_t cap)
{
    static size_t n;
    int c;

    while ((c = getchar_timeout_us(0)) != PICO_ERROR_TIMEOUT) {
        if (c == '\r') continue;
        if (c == '\n') {
            size_t len = n;
            buf[n] = 0;
            n = 0;
            return len ? len : 0;
        }
        if (n + 1 < cap) buf[n++] = (char)c;
    }
    return 0;
}

static void reboot_now(void)
{
    watchdog_reboot(0, 0, 10);
    for (;;) {
    }
}

static void refresh_or_safe(void)
{
    int rc = rp2350_refresh(ROT_T_OFF_MS);
    printf("{\"ev\":\"refresh_failed\",\"rc\":%d}\n", rc);
}

static void safe_mode(int reason)
{
    static char line[64];
    uint32_t next = 0;

    for (;;) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (now >= next) {
            printf("{\"ev\":\"safe\",\"reason\":\"%s\",\"image_reason\":%d}\n", rot_safe_name(reason),
                   out.image_reason);
            next = now + 2000;
        }
        if (read_line(line, sizeof line)) {
            if (!strcmp(line, "REBOOT")) reboot_now();
            if (!strcmp(line, "STATUS")) next = 0;
        }
        sleep_ms(20);
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ---- factory enrollment ------------------------------------------- */

#define STAGING_SECTOR(i) (ROT_REGION_STAGING_OFF + (i) * ROT_FLASH_SECTOR)
#define ENROLL_READS 5u

static void erase_enroll_scratch(void)
{
    rot_flash_erase(&plat, STAGING_SECTOR(0), 6 * ROT_FLASH_SECTOR);
}

static void enroll_finish(void)
{
    static uint8_t vpk[ROT_DSA_PK];
    static rot_enroll_result res;
    const uint8_t *reads[ENROLL_READS];
    rot_enroll_params prm = { (uint16_t)((ROT_STABLE_PAIRS ? ROT_HLP_F_STABLE : 0) | (ROT_SIM_PUF ? ROT_HLP_F_SIM : 0)),
                              PUF_KEY_WINDOW, ROT_T_OFF_MS };
    int rc;

    for (unsigned i = 0; i < ENROLL_READS; i++) {
        reads[i] = plat.flash_xip(plat.ctx, STAGING_SECTOR(i));
    }
    memcpy(vpk, plat.flash_xip(plat.ctx, STAGING_SECTOR(5)), sizeof vpk);
    rc = rot_enroll_run(&plat, reads, ENROLL_READS, vpk, &prm, &res);
    if (rc != 0) {
        printf("{\"ev\":\"enroll_failed\",\"rc\":%d,\"pairs_available\":%u}\n", rc, res.pairs_available);
        erase_enroll_scratch();
        rp2350_scratch_set(SCR_ENROLL, 0);
        return;
    }
    printf("{\"ev\":\"enrolled\",\"device_id\":\"%08x\",\"pairs_available\":%u}\n", (unsigned)res.device_id,
           res.pairs_available);
    printf("ENR1 ");
    for (size_t i = 0; i < sizeof res.enr1; i++) {
        printf("%02x", res.enr1[i]);
        if ((i & 255) == 255) stdio_flush();
    }
    printf("\n");
    erase_enroll_scratch();
    for (unsigned i = 0; i < 6; i++) {
        if (!rot_flash_sector_blank(&plat, STAGING_SECTOR(i))) {
            printf("{\"ev\":\"enroll_scratch_not_blank\",\"sector\":%u}\n", i);
        }
    }
    rp2350_scratch_set(SCR_ENROLL, 0);
    stdio_flush();
    sleep_ms(200);
}

/* This boot's window is read number `n` (1..5). */
static void enroll_capture(unsigned n)
{
    rot_flash_put(&plat, STAGING_SECTOR(n - 1), in.window, ROT_FLASH_SECTOR);
    rot_wipe(in.window, sizeof in.window);
    rp2350_scratch_set(SCR_ENROLL, n + 1);
    printf("{\"ev\":\"enroll_read\",\"n\":%u}\n", n);
    if (n < ENROLL_READS) {
        stdio_flush();
        refresh_or_safe();
        return;
    }
    enroll_finish();
    stdio_flush();
    refresh_or_safe();
}

static void enroll_wait(void)
{
    static char line[ROT_DSA_PK * 2 + 32];
    static uint8_t pk[ROT_FLASH_SECTOR];
    uint32_t next = 0;

    erase_enroll_scratch();
    for (;;) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (now >= next) {
            printf("{\"ev\":\"unenrolled\",\"waiting\":\"ENROLL <vendor_pk_hex>\"}\n");
            next = now + 2000;
        }
        if (read_line(line, sizeof line)) {
            if (!strcmp(line, "REBOOT")) reboot_now();
            if (!strncmp(line, "ENROLL ", 7) && strlen(line + 7) == ROT_DSA_PK * 2) {
                int ok = 1;
                memset(pk, 0xFF, sizeof pk);
                for (unsigned i = 0; i < ROT_DSA_PK; i++) {
                    int hi = hex_nibble(line[7 + 2 * i]), lo = hex_nibble(line[8 + 2 * i]);
                    if (hi < 0 || lo < 0) { ok = 0; break; }
                    pk[i] = (uint8_t)((hi << 4) | lo);
                }
                if (!ok) {
                    printf("{\"ev\":\"enroll_rejected\",\"why\":\"hex\"}\n");
                    continue;
                }
                rot_flash_put(&plat, STAGING_SECTOR(5), pk, ROT_FLASH_SECTOR);
                rp2350_scratch_set(SCR_ENROLL, 1);
                printf("{\"ev\":\"enroll_start\"}\n");
                stdio_flush();
                refresh_or_safe();
            }
        }
        sleep_ms(20);
    }
}

/* ---- main ---------------------------------------------------------- */

int main(void)
{
    uint32_t bits = rp2350_chip_reset_bits();
    uint32_t s0 = rp2350_scratch_get(SCR_MARKER);
    rot_reset_verdict v = rot_reset_classify(bits, s0);
    uint32_t refreshes;
    unsigned enroll_n;

    /* B2: never read the window of a stale boot */
    if (!v.fresh) {
        unsigned n = rp2350_scratch_get(SCR_REFRESHES);
        if (n < REFRESH_MAX_ATTEMPTS) {
            rp2350_scratch_set(SCR_MARKER, rot_reset_marker(v.cause));
            rp2350_scratch_set(SCR_REFRESHES, n + 1);
            rp2350_refresh(ROT_T_OFF_MS);   /* does not return on success */
        }
        stdio_init_all();
        out.image_reason = (int)bits;
        safe_mode(SAFE_REFRESH);
    }

    /* B3: take the window before anything else touches memory, then clear it */
    memcpy(in.window, (const void *)PUF_KEY_WINDOW, sizeof in.window);
    memset((void *)PUF_KEY_WINDOW, 0, PUF_BLOCK_SIZE);

    refreshes = rp2350_scratch_get(SCR_REFRESHES);
    in.reset_cause = v.cause == RC_PSTATE ? v.original : v.cause;
    in.refresh_count = (uint8_t)refreshes;
    in.puf_retry = (uint8_t)rp2350_scratch_get(SCR_PUF_RETRY);
    rp2350_scratch_set(SCR_MARKER, 0);
    rp2350_scratch_set(SCR_REFRESHES, 0);
    if (v.cause == RC_POR) {
        /* a power-on leaves no trustworthy progress behind */
        rp2350_scratch_set(SCR_INSTALL, 0);
        rp2350_scratch_set(SCR_PUF_RETRY, 0);
        rp2350_scratch_set(SCR_ENROLL, 0);
        in.puf_retry = 0;
    }

    stdio_init_all();
    for (uint32_t t = 0; t < ROT_CONSOLE_WAIT_MS && !stdio_usb_connected(); t += 20) {
        sleep_ms(20);
    }
    rp2350_platform_init(&plat);
    rot_rng_init(trng_for_rng, NULL);
    in.die_temp_x10 = (int16_t)rp2350_die_temp_x10();
    in.sim_puf = ROT_SIM_PUF;
    memcpy(in.build_id, ROT_BUILD_ID, 20);

    printf("{\"ev\":\"rot\",\"build\":\"%.20s\",\"cause\":%u,\"refreshes\":%u,\"temp_x10\":%d}\n", ROT_BUILD_ID,
           in.reset_cause, in.refresh_count, in.die_temp_x10);

#if ROT_SELFTEST
    {
        uint64_t cyc[5] = { 0 };
        uint32_t bad = rot_selftest_run(rp2350_mcycle, cyc);
        printf("{\"ev\":\"selftest\",\"failed_mask\":%u,\"cycles\":[%llu,%llu,%llu,%llu,%llu]}\n", (unsigned)bad,
               (unsigned long long)cyc[0], (unsigned long long)cyc[1], (unsigned long long)cyc[2],
               (unsigned long long)cyc[3], (unsigned long long)cyc[4]);
    }
#endif

    /* factory enrollment reads happen before the normal boot logic */
    enroll_n = rp2350_scratch_get(SCR_ENROLL);
    if (enroll_n >= 1 && enroll_n <= ENROLL_READS) {
        enroll_capture(enroll_n);
        safe_mode(SAFE_REFRESH);
    }

    /* install boot-loop guard: attempts per mailbox request, kept across resets */
    {
        rot_mbx_t m;
        if (rot_mailbox_read(&plat, &m) == ROT_MBX_OK && m.type == MBX_INSTALL_REQ) {
            uint32_t g = rp2350_scratch_get(SCR_INSTALL), key = m.seq & 0xFFFFu;
            unsigned attempts = (g >> 16) == key ? (g & 0xFFFFu) : 0;
            in.install_attempts = (uint8_t)(attempts > 255 ? 255 : attempts);
            rp2350_scratch_set(SCR_INSTALL, (key << 16) | (attempts + 1));
            rp2350_wdt_arm(8000);   /* fed once per sector by the install pipeline */
        }
    }

    rot_boot_run(&plat, &in, &out);

    switch (out.action) {
    case BOOT_ENROLL:
        enroll_wait();
        break;
    case BOOT_REFRESH:
        rp2350_scratch_set(SCR_PUF_RETRY, 1);
        rp2350_scratch_set(SCR_MARKER, rot_reset_marker(in.reset_cause));
        rp2350_scratch_set(SCR_REFRESHES, 1);
        rp2350_refresh(ROT_T_OFF_MS);
        safe_mode(SAFE_PUF_MISMATCH);
        break;
    case BOOT_SAFE:
        safe_mode(out.safe_reason);
        break;
    case BOOT_CHAIN:
    default: {
        final_params fp;
        rp2350_scratch_set(SCR_INSTALL, 0);
        rp2350_scratch_set(SCR_PUF_RETRY, 0);
        memset((void *)HANDOFF_BASE, 0, HANDOFF_SIZE);
        memcpy((void *)HANDOFF_BASE, &out.hnd, sizeof out.hnd);
        fp.region_base = XIP_BASE + out.chain_off;
        fp.region_size = out.chain_len;
        fp.watchdog_ms = out.trial ? out.trial_deadline_ms : 0;
        fp.pmp_lock = ROT_PMP_LOCK;
        printf("{\"ev\":\"chain\",\"slot\":%d,\"svn\":%llu,\"floor\":%llu,\"trial\":%d}\n", out.chain_slot,
               (unsigned long long)out.hnd.svn, (unsigned long long)out.hnd.floor, out.trial);
        stdio_flush();
        sleep_ms(20);
        rp2350_final_chain(&fp);
    }
    }
    return 0;
}
