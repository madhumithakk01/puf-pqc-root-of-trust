/*
 * Pulse-oximeter application. Holds no keys: it relays attestation and
 * install requests to the RoT through the mailbox and stages incoming
 * packages. Trial boots run the health self-test before the network starts.
 */

#include <stdio.h>
#include <string.h>

#include "hardware/flash.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "dsp/dsp.h"
#include "health/selftest.h"
#include "proto/app_server.h"
#include "proto/pqw1.h"
#include "rot/rot_flash_map.h"
#include "rot/rot_hev.h"
#include "rot/rot_handoff.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_receipt.h"
#include "rot/rot_util.h"

#define HANDOFF ((const rot_handoff_t *)0x2007C000u)
#define SDA_PIN 4
#define SCL_PIN 5
#define BUS i2c0
#ifndef APP_TRANSPORT_USB
#define APP_TRANSPORT_USB 0
#endif
#define PORT 7000
#define BEACON_PORT 7001

static max30102 dev;
static dsp_t dsp;
static app_server srv;
static struct tcp_pcb *client;
static pqw1_parser parser;
static uint8_t resp[PQW1_MAX_FRAME];
static bool vitals_ok;

/* ---- I2C bus --------------------------------------------------------- */

static int bus_write(void *c, uint8_t a, uint8_t r, const uint8_t *d, size_t n)
{
    uint8_t buf[16];
    (void)c;
    if (n + 1 > sizeof buf) return -1;
    buf[0] = r;
    memcpy(buf + 1, d, n);
    return i2c_write_blocking(BUS, a, buf, n + 1, false) == (int)(n + 1) ? 0 : -1;
}

static int bus_read(void *c, uint8_t a, uint8_t r, uint8_t *d, size_t n)
{
    (void)c;
    if (i2c_write_blocking(BUS, a, &r, 1, true) != 1) return -1;
    return i2c_read_blocking(BUS, a, d, n, false) == (int)n ? 0 : -1;
}

static void bus_delay(void *c, unsigned ms)
{
    (void)c;
    sleep_ms(ms);
}

static const max30102_bus bus = { NULL, bus_write, bus_read, bus_delay };

static void i2c_start(void)
{
    i2c_init(BUS, 400 * 1000);
    gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SDA_PIN);
    gpio_pull_up(SCL_PIN);
}

/* ---- flash: staging and mailbox only --------------------------------- */

static int fl_erase(uint32_t off, uint32_t len)
{
    uint32_t irq = save_and_disable_interrupts();
    flash_range_erase(off, len);
    restore_interrupts(irq);
    return 0;
}

static int fl_prog(uint32_t off, const uint8_t *d, size_t n)
{
    uint8_t page[FLASH_PAGE_SIZE];
    while (n) {
        size_t k = n < sizeof page ? n : sizeof page;
        uint32_t irq;
        memset(page, 0xFF, sizeof page);
        memcpy(page, d, k);
        irq = save_and_disable_interrupts();
        flash_range_program(off, page, sizeof page);
        restore_interrupts(irq);
        off += (uint32_t)k;
        d += k;
        n -= k;
    }
    return 0;
}

static int svc_erase(void *c, uint32_t off, uint32_t len)
{
    (void)c;
    return fl_erase(ROT_REGION_STAGING_OFF + off, len);
}

static int svc_write(void *c, uint32_t off, const uint8_t *d, size_t n)
{
    (void)c;
    /* chunks are page aligned except possibly the last; program page by page */
    if (off & (FLASH_PAGE_SIZE - 1)) return -1;
    return fl_prog(ROT_REGION_STAGING_OFF + off, d, n);
}

static int write_mailbox(const uint8_t *rec, size_t n)
{
    uint32_t off = ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1);
    fl_erase(off, ROT_FLASH_SECTOR);
    return fl_prog(off, rec, n);
}

static int svc_mailbox(void *c, const uint8_t *rec, size_t n)
{
    (void)c;
    return write_mailbox(rec, n);
}

static int svc_receipt(void *c, uint32_t seq, uint8_t *obj)
{
    const uint8_t *p = (const uint8_t *)(XIP_BASE + ROT_DATA_SECTOR_OFF(ROT_SECTOR_RCP1_FIRST + seq % ROT_RCP1_RING));
    (void)c;
    if (memcmp(p, "RCP1", 4) != 0 || rot_get32(p + 4) != seq) return -1;
    memcpy(obj, p, RCP_TOTAL_BYTES);
    return 0;
}

static const rot_handoff_t *svc_handoff(void *c)
{
    (void)c;
    return HANDOFF;
}

static const app_services services = { NULL, svc_erase, svc_write, svc_mailbox, svc_receipt, svc_handoff };

/* ---- trial boot -------------------------------------------------------- */

static uint32_t st_now(void *c) { (void)c; return to_ms_since_boot(get_absolute_time()); }
static void st_delay(void *c, unsigned ms) { (void)c; sleep_ms(ms); }

static void run_trial(void)
{
    selftest_env env = { &dev, &bus, (dsp_variant)APP_DSP_VARIANT, APP_SVN, NULL, st_now, st_delay };
    selftest_result res;
    uint8_t hev[32], rec[ROT_MBX_HDR + 32 + 4];
    size_t n;
    static uint32_t seq = 0x1000;

    i2c_start();
    selftest_run(&env, &res, hev);
    n = rot_mailbox_build(rec, ++seq, MBX_HEALTH_REPORT, hev, 32);
    write_mailbox(rec, n);
    printf("trial: bpm_x10=%u live=%u -> reboot\n", res.golden.bpm_x10, res.live_samples);
    stdio_flush();
    watchdog_reboot(0, 0, 10);
    for (;;) {
    }
}

/* ---- TCP --------------------------------------------------------------- */

static void reboot_soon(void)
{
    sleep_ms(100);
    watchdog_reboot(0, 0, 10);
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)err;
    if (!p) {
        tcp_close(pcb);
        client = NULL;
        return ERR_OK;
    }
    for (struct pbuf *q = p; q; q = q->next) {
        const uint8_t *b = q->payload;
        for (u16_t i = 0; i < q->len; i++) {
            pqw1_frame f;
            pqw1_event e = pqw1_feed(&parser, b[i], &f);
            while (e == PQW1_FRAME || e == PQW1_ERR_CRC || e == PQW1_ERR_LEN) {
                if (e == PQW1_FRAME) {
                    size_t n = app_server_handle(&srv, &f, resp, sizeof resp);
                    if (tcp_write(pcb, resp, (u16_t)(n > 0xFFFF ? 0xFFFF : n), TCP_WRITE_FLAG_COPY) == ERR_OK) {
                        tcp_output(pcb);
                    }
                    if (srv.pending_reboot) {
                        tcp_recved(pcb, p->tot_len);
                        pbuf_free(p);
                        reboot_soon();
                        return ERR_OK;
                    }
                }
                e = pqw1_poll(&parser, &f);
            }
        }
    }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void on_err(void *arg, err_t err)
{
    (void)arg;
    (void)err;
    client = NULL;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !pcb) return ERR_VAL;
    if (client) tcp_abort(client);
    client = pcb;
    pqw1_parser_init(&parser);
    srv.vitals_subscribed = 0;
    tcp_recv(pcb, on_recv);
    tcp_err(pcb, on_err);
    return ERR_OK;
}

static void beacon(struct udp_pcb *pcb)
{
    char msg[96];
    const rot_handoff_t *h = HANDOFF;
    int len = snprintf(msg, sizeof msg, "PQW1 %08x %s %d %.16s %llu", (unsigned)h->device_id,
                       ip4addr_ntoa(netif_ip4_addr(netif_default)), PORT, h->version_str,
                       (unsigned long long)h->svn);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (p) {
        memcpy(p->payload, msg, (size_t)len);
        udp_sendto(pcb, p, IP_ADDR_BROADCAST, BEACON_PORT);
        pbuf_free(p);
    }
}

int main(void)
{
    uint32_t next_vitals = 0, next_beacon = 0;
    struct tcp_pcb *listener;
    struct udp_pcb *ubeacon;

    stdio_init_all();
    if (!rot_handoff_valid(HANDOFF)) {
        printf("no valid boot report from the RoT; refusing to run\n");
        for (;;) sleep_ms(1000);
    }
    printf("app %s (svn %u) device %08x floor %llu%s\n", APP_VERSION_STR, APP_SVN,
           (unsigned)HANDOFF->device_id, (unsigned long long)HANDOFF->floor,
           (HANDOFF->flags & HND_F_TRIAL) ? " TRIAL" : "");

    if (HANDOFF->flags & HND_F_TRIAL) {
        run_trial();   /* before Wi-Fi; does not return */
    }

    i2c_start();
    vitals_ok = max30102_init(&dev, &bus) == MAX30102_OK;
    dsp_init(&dsp, (dsp_variant)APP_DSP_VARIANT);
    app_server_init(&srv, &services, ROT_REGION_STAGING_SIZE, 0x2000);

#if APP_TRANSPORT_USB
    /* USB-line transport: each frame is one "@<base64>" line; '#' lines are diagnostics */
    {
        static char line[2 * PQW1_MAX_FRAME];
        static uint8_t frame[PQW1_MAX_FRAME];
        size_t n = 0;
        printf("# usb transport ready\n");
        for (;;) {
            int c = getchar_timeout_us(10000);
            if (c == PICO_ERROR_TIMEOUT) continue;
            if (c != '\n') {
                if (n + 1 < sizeof line) line[n++] = (char)c;
                continue;
            }
            {
                size_t fl = pqw1_line_decode(line, n, frame, sizeof frame);
                pqw1_parser_init(&parser);
                n = 0;
                for (size_t i = 0; i < fl; i++) {
                    pqw1_frame f;
                    if (pqw1_feed(&parser, frame[i], &f) == PQW1_FRAME) {
                        size_t rl = app_server_handle(&srv, &f, resp, sizeof resp);
                        static char out[2 * PQW1_MAX_FRAME];
                        size_t ol = pqw1_line_encode(resp, rl, out, sizeof out);
                        fwrite(out, 1, ol, stdout);
                        stdio_flush();
                        if (srv.pending_reboot) reboot_soon();
                    }
                }
            }
        }
    }
#endif
    if (cyw43_arch_init()) return 1;
    cyw43_arch_enable_sta_mode();
    while (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("wifi join failed, retrying\n");
    }
    printf("ip %s\n", ip4addr_ntoa(netif_ip4_addr(netif_default)));

    cyw43_arch_lwip_begin();
    {
        struct tcp_pcb *pcb = tcp_new();
        tcp_bind(pcb, IP_ANY_TYPE, PORT);
        listener = tcp_listen(pcb);
        tcp_accept(listener, on_accept);
    }
    ubeacon = udp_new();
    cyw43_arch_lwip_end();

    for (;;) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        uint32_t red[16], ir[16];

        if (vitals_ok) {
            int n = max30102_read_fifo(&dev, red, ir, 16);
            for (int i = 0; i < n; i++) dsp_push(&dsp, red[i], ir[i]);
        }
        if (now >= next_beacon) {
            cyw43_arch_lwip_begin();
            beacon(ubeacon);
            cyw43_arch_lwip_end();
            next_beacon = now + 2000;
        }
        if (client && srv.vitals_subscribed && now >= next_vitals) {
            char js[200];
            dsp_out o;
            int n;
            dsp_result(&dsp, &o);
            n = snprintf(js, sizeof js, "{\"t\":%u,\"bpm_x10\":%u,\"spo2_x10\":%u,\"quality\":%u,\"alerts\":%u,\"replay\":false}",
                         (unsigned)now, o.bpm_x10, o.spo2_x10 == DSP_SPO2_NONE ? 0 : o.spo2_x10, o.quality, o.alerts);
            n = (int)pqw1_encode(resp, sizeof resp, PQW1_R_VITALS, PQW1_FLAG_LAST, 0, (const uint8_t *)js, (uint32_t)n);
            cyw43_arch_lwip_begin();
            if (client && n > 0 && tcp_write(client, resp, (u16_t)n, TCP_WRITE_FLAG_COPY) == ERR_OK) tcp_output(client);
            cyw43_arch_lwip_end();
            next_vitals = now + 100;
        }
        sleep_ms(10);
    }
}
