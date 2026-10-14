/*
 * softdev: the whole device on a laptop.
 *
 * The RoT core (rot_boot_run and the records), the application logic (DSP,
 * self-test, PQW1 server) and a file-backed flash run as one process. A
 * simulated PUF window with per-boot noise replaces the SRAM; the sensor is a
 * virtual MAX30102 that streams the golden trace. Rebooting means going back
 * to the RoT, exactly as on the board: the application only ever leaves
 * requests in the mailbox.
 *
 *   softdev --flash FILE --port 7000 [--puf-id N] [--noise PPM]
 *           [--enroll VENDOR_PK --enr1-out FILE]   factory enrollment of a blank flash
 *           [--trial-mode pass|hang|nosensor]      how the application behaves in a trial
 *           [--beacon HOST]                        UDP beacon target (port 7001)
 *           [--vitals-hz N] [--log FILE]
 *
 * The listening port is printed as "LISTENING <port>" once the first boot is done.
 */

#define _GNU_SOURCE
#include "flash_model.h"

#include "dsp/dsp.h"
#include "golden/golden_trace.h"
#include "health/selftest.h"
#include "proto/app_server.h"
#include "proto/pqw1.h"
#include "puf/puf_sim.h"
#include "rot/rot_boot.h"
#include "rot/rot_crc32.h"
#include "rot/rot_enroll.h"
#include "rot/rot_flash.h"
#include "rot/rot_hev.h"
#include "rot/rot_mailbox.h"
#include "rot/rot_receipts.h"
#include "rot/rot_util.h"

#include "fake_i2c.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef enum { TRIAL_PASS, TRIAL_HANG, TRIAL_NOSENSOR } trial_mode;

static flash_model fm;
static rot_platform plat;
static const char *flash_path;
static FILE *log_file;
static volatile sig_atomic_t stop;
static int listen_fd = -1;
static uint32_t puf_id = 4242;
static uint32_t noise_ppm = 20000;
static uint32_t boot_counter;
static trial_mode tmode = TRIAL_PASS;
static int vitals_hz = 10;
static const char *beacon_host;
static int port = 7000;
static uint8_t reset_cause = RC_POR;
static rot_boot_out boot_out;
static uint32_t mbx_seq;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void rot_log(void *ctx, const char *line)
{
    (void)ctx;
    if (log_file) {
        fprintf(log_file, "rot %s\n", line);
        fflush(log_file);
    }
}

static void save_flash(void)
{
    if (flash_path) {
        flash_model_save(&fm, flash_path);
    }
}

/* ------------------------------------------------------------------ */
/* application services                                               */

static int svc_erase(void *c, uint32_t off, uint32_t len)
{
    (void)c;
    return rot_flash_erase(&plat, ROT_REGION_STAGING_OFF + off, len);
}

static int svc_write(void *c, uint32_t off, const uint8_t *d, size_t n)
{
    (void)c;
    return rot_flash_program(&plat, ROT_REGION_STAGING_OFF + off, d, n);
}

static int svc_mailbox(void *c, const uint8_t *rec, size_t n)
{
    (void)c;
    return rot_flash_put(&plat, ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), rec, n);
}

static int svc_receipt(void *c, uint32_t seq, uint8_t *obj)
{
    (void)c;
    return rot_receipts_read(&plat, seq, obj) == ROT_RCPS_OK ? 0 : -1;
}

static const rot_handoff_t *svc_handoff(void *c)
{
    (void)c;
    return &boot_out.hnd;
}

static const app_services services = { NULL, svc_erase, svc_write, svc_mailbox, svc_receipt, svc_handoff };

/* ------------------------------------------------------------------ */
/* boot                                                               */

static void read_window(uint8_t *w, uint32_t id)
{
    uint8_t noise[8];
    boot_counter++;
    memcpy(noise, "sdv", 3);
    rot_put32(noise + 3, boot_counter);
    noise[7] = (uint8_t)(now_us() & 0xFF);
    puf_sim_response_noisy(id, noise_ppm, noise, sizeof noise, w, ROT_BOOT_WINDOW_BYTES);
}

static int do_enroll(const char *vendor_pk_path, const char *enr1_out)
{
    static uint8_t reads[5][ROT_BOOT_WINDOW_BYTES];
    const uint8_t *rp[5];
    uint8_t vpk[ROT_DSA_PK];
    rot_enroll_params prm = { 0, 0x20070000u, 100 };
    static rot_enroll_result res;
    FILE *f = fopen(vendor_pk_path, "rb");
    int rc;

    if (!f || fread(vpk, 1, sizeof vpk, f) != sizeof vpk) {
        fprintf(stderr, "softdev: cannot read the vendor public key %s\n", vendor_pk_path);
        return -1;
    }
    fclose(f);
    for (int i = 0; i < 5; i++) {
        read_window(reads[i], puf_id);
        rp[i] = reads[i];
    }
    rc = rot_enroll_run(&plat, rp, 5, vpk, &prm, &res);
    if (rc != 0) {
        fprintf(stderr, "softdev: enrollment failed (%d)\n", rc);
        return -1;
    }
    if (enr1_out) {
        f = fopen(enr1_out, "wb");
        if (!f || fwrite(res.enr1, 1, sizeof res.enr1, f) != sizeof res.enr1) return -1;
        fclose(f);
    }
    fprintf(stdout, "ENROLLED device_id=%08x pairs_available=%u\n", res.device_id, res.pairs_available);
    fflush(stdout);
    save_flash();
    return 0;
}

static dsp_variant variant_of_slot(int slot)
{
    const uint8_t *img = fm.mem + ROT_SLOT_OFF(slot);
    const char *ver = (const char *)(img + 24 + 8);   /* APM1 version string */
    if (strncmp(ver, "1.0", 3) == 0) return DSP_V10;
    if (strncmp(ver, "1.2", 3) == 0) return DSP_V12;
    return DSP_V11;
}

/* ------------------------------------------------------------------ */
/* virtual sensor and self-test                                       */

typedef struct {
    fake_t bus;
    uint64_t start_us;
    uint64_t t_ms;
    uint32_t pushed;
} vsensor_t;

static vsensor_t vs;

static uint32_t st_now(void *c)
{
    (void)c;
    return (uint32_t)vs.t_ms;
}

static void st_delay(void *c, unsigned ms)
{
    (void)c;
    /* simulated time: the sensor produces 100 samples per second */
    for (unsigned i = 0; i < ms; i++) {
        vs.t_ms++;
        if (tmode != TRIAL_NOSENSOR && vs.t_ms % 10 == 0) {
            unsigned k = vs.pushed++ % GOLDEN_SAMPLES;
            push(&vs.bus, golden_red[k], golden_ir[k]);
        }
    }
}

static int st_bus_write(void *c, uint8_t a, uint8_t r, const uint8_t *d, size_t n)
{
    (void)c;
    return fk_write(&vs.bus, a, r, d, n);
}

static int st_bus_read(void *c, uint8_t a, uint8_t r, uint8_t *d, size_t n)
{
    (void)c;
    return fk_read(&vs.bus, a, r, d, n);
}

static void st_bus_delay(void *c, unsigned ms)
{
    st_delay(c, ms);
}

/* The trial boot: self-test before any network, then request a reboot. */
static int run_trial(void)
{
    static max30102 dev;
    max30102_bus bus = { NULL, st_bus_write, st_bus_read, st_bus_delay };
    selftest_env env;
    selftest_result res;
    uint8_t hev[32], rec[128];
    size_t n;

    if (tmode == TRIAL_HANG) {
        fprintf(stdout, "TRIAL hang (watchdog will fire)\n");
        fflush(stdout);
        reset_cause = RC_WATCHDOG;      /* the RoT armed the watchdog; nothing feeds it */
        return 0;
    }
    memset(&vs, 0, sizeof vs);
    fake_reset(&vs.bus);
    env.dev = &dev;
    env.bus = &bus;
    env.variant = variant_of_slot(boot_out.chain_slot);
    env.svn = boot_out.hnd.svn;
    env.ctx = NULL;
    env.now_ms = st_now;
    env.delay_ms = st_delay;
    selftest_run(&env, &res, hev);
    n = rot_mailbox_build(rec, ++mbx_seq, MBX_HEALTH_REPORT, hev, 32);
    rot_flash_put(&plat, ROT_DATA_SECTOR_OFF(ROT_SECTOR_MBX1), rec, n);
    fprintf(stdout, "TRIAL reported bpm_x10=%u spo2_x10=%u live=%u\n", res.golden.bpm_x10, res.golden.spo2_x10,
            res.live_samples);
    fflush(stdout);
    reset_cause = RC_PSTATE;
    return 0;
}

/* ------------------------------------------------------------------ */
/* network                                                            */

static int open_listener(int p)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)p);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 4) != 0) {
        perror("softdev: bind/listen");
        exit(1);
    }
    if (p == 0) {
        socklen_t l = sizeof a;
        getsockname(fd, (struct sockaddr *)&a, &l);
        port = ntohs(a.sin_port);
    }
    return fd;
}

static int send_all(int fd, const uint8_t *d, size_t n)
{
    while (n) {
        ssize_t w = send(fd, d, n, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        d += w;
        n -= (size_t)w;
    }
    return 0;
}

static void send_beacon(void)
{
    static int fd = -1;
    struct sockaddr_in a;
    char msg[96];
    int one = 1;

    if (!beacon_host) return;
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(7001);
    inet_pton(AF_INET, beacon_host, &a.sin_addr);
    snprintf(msg, sizeof msg, "PQW1 %08x %s %d %.16s %llu", boot_out.hnd.device_id, "0.0.0.0", port,
             boot_out.hnd.version_str, (unsigned long long)boot_out.hnd.svn);
    sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&a, sizeof a);
}

/* In SAFE mode the only answer is the reason. */
static size_t safe_reply(const pqw1_frame *req, uint8_t *resp, size_t cap)
{
    char js[160];
    int n = snprintf(js, sizeof js, "{\"mode\":\"SAFE\",\"reason\":\"%s\",\"image_reason\":%d}",
                     rot_safe_name(boot_out.safe_reason), boot_out.image_reason);
    return pqw1_encode(resp, cap, PQW1_R_STATUS, PQW1_FLAG_LAST, req->seq, (const uint8_t *)js, (uint32_t)n);
}

/* Serve until a reboot is requested. Returns 1 to reboot, 0 on shutdown. */
static int serve(int safe_mode)
{
    static app_server srv;
    static pqw1_parser parser;
    static uint8_t resp[PQW1_MAX_FRAME];
    int client = -1;
    dsp_t dsp;
    dsp_out out;
    uint64_t next_vitals = 0, next_beacon = 0;
    uint32_t sample = 0;
    dsp_variant v = safe_mode ? DSP_V11 : variant_of_slot(boot_out.chain_slot);

    app_server_init(&srv, &services, ROT_REGION_STAGING_SIZE, mbx_seq);
    dsp_init(&dsp, v);
    pqw1_parser_init(&parser);

    while (!stop) {
        fd_set rs;
        struct timeval tv = { 0, 20000 };
        int maxfd = listen_fd;
        uint64_t t = now_us();

        FD_ZERO(&rs);
        FD_SET(listen_fd, &rs);
        if (client >= 0) {
            FD_SET(client, &rs);
            if (client > maxfd) maxfd = client;
        }
        if (select(maxfd + 1, &rs, NULL, NULL, &tv) < 0 && errno != EINTR) break;

        if (FD_ISSET(listen_fd, &rs)) {
            int c = accept(listen_fd, NULL, NULL);
            if (c >= 0) {
                if (client >= 0) close(client);
                client = c;
                pqw1_parser_init(&parser);
                srv.vitals_subscribed = 0;
            }
        }
        if (client >= 0 && FD_ISSET(client, &rs)) {
            uint8_t b[2048];
            ssize_t n = recv(client, b, sizeof b, 0);
            if (n <= 0) {
                close(client);
                client = -1;
            } else {
                for (ssize_t i = 0; i < n && client >= 0; i++) {
                    pqw1_frame f;
                    pqw1_event e = pqw1_feed(&parser, b[i], &f);
                    while (e == PQW1_FRAME || e == PQW1_ERR_CRC || e == PQW1_ERR_LEN) {
                        if (e == PQW1_FRAME) {
                            size_t rl = safe_mode ? safe_reply(&f, resp, sizeof resp)
                                                  : app_server_handle(&srv, &f, resp, sizeof resp);
                            if (send_all(client, resp, rl) != 0) {
                                close(client);
                                client = -1;
                                break;
                            }
                            if (srv.pending_reboot) {
                                /* the response is out; the "app" now reboots */
                                usleep(50000);
                                close(client);
                                return 1;
                            }
                        }
                        e = pqw1_poll(&parser, &f);
                    }
                }
            }
        }

        if (!safe_mode) {
            if (client >= 0 && srv.vitals_subscribed && vitals_hz > 0 && t >= next_vitals) {
                char js[200];
                uint8_t frame[PQW1_MAX_FRAME];
                int n;
                size_t fl;
                for (int k = 0; k < 100 / vitals_hz; k++) {
                    dsp_push(&dsp, golden_red[sample % GOLDEN_SAMPLES], golden_ir[sample % GOLDEN_SAMPLES]);
                    sample++;
                }
                dsp_result(&dsp, &out);
                n = snprintf(js, sizeof js,
                             "{\"t\":%u,\"ir\":%u,\"bpm_x10\":%u,\"spo2_x10\":%u,\"quality\":%u,\"alerts\":%u,\"replay\":true}",
                             sample, golden_ir[(sample - 1) % GOLDEN_SAMPLES], out.bpm_x10,
                             out.spo2_x10 == DSP_SPO2_NONE ? 0 : out.spo2_x10, out.quality, out.alerts);
                fl = pqw1_encode(frame, sizeof frame, PQW1_R_VITALS, PQW1_FLAG_LAST, 0, (const uint8_t *)js, (uint32_t)n);
                if (send_all(client, frame, fl) != 0) {
                    close(client);
                    client = -1;
                }
                next_vitals = t + 1000000u / (uint64_t)vitals_hz;
            }
            if (t >= next_beacon) {
                send_beacon();
                next_beacon = t + 2000000u;
            }
        }
    }
    if (client >= 0) close(client);
    return 0;
}

int main(int argc, char **argv)
{
    const char *enroll_pk = NULL, *enr1_out = NULL, *logpath = NULL;
    static rot_boot_in in;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--flash") && i + 1 < argc) flash_path = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--puf-id") && i + 1 < argc) puf_id = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--noise") && i + 1 < argc) noise_ppm = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--enroll") && i + 1 < argc) enroll_pk = argv[++i];
        else if (!strcmp(argv[i], "--enr1-out") && i + 1 < argc) enr1_out = argv[++i];
        else if (!strcmp(argv[i], "--beacon") && i + 1 < argc) beacon_host = argv[++i];
        else if (!strcmp(argv[i], "--vitals-hz") && i + 1 < argc) vitals_hz = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logpath = argv[++i];
        else if (!strcmp(argv[i], "--trial-mode") && i + 1 < argc) {
            const char *m = argv[++i];
            tmode = !strcmp(m, "hang") ? TRIAL_HANG : !strcmp(m, "nosensor") ? TRIAL_NOSENSOR : TRIAL_PASS;
        } else {
            fprintf(stderr, "softdev: unknown or incomplete option %s\n", argv[i]);
            return 2;
        }
    }
    if (!flash_path) {
        fprintf(stderr, "softdev: --flash FILE is required\n");
        return 2;
    }

    if (flash_model_init(&fm, ROT_FLASH_TOTAL) != 0) return 1;
    if (access(flash_path, F_OK) == 0) {
        if (flash_model_load(&fm, flash_path) != 0) {
            fprintf(stderr, "softdev: cannot load %s\n", flash_path);
            return 1;
        }
    }
    flash_model_platform(&fm, &plat);
    plat.log = rot_log;
    if (logpath) log_file = fopen(logpath, "w");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (enroll_pk) {
        if (do_enroll(enroll_pk, enr1_out) != 0) return 1;
    }

    listen_fd = open_listener(port);

    while (!stop) {
        int act, retry = 0;

        for (;;) {
            memset(&in, 0, sizeof in);
            read_window(in.window, puf_id);
            in.reset_cause = reset_cause;
            in.puf_retry = (uint8_t)retry;
            in.refresh_count = (uint8_t)(reset_cause == RC_PSTATE ? 1 : 0);
            in.die_temp_x10 = 250;
            memcpy(in.build_id, "softdev-build-000000", 20);
            in.sim_puf = 1;
            rot_boot_run(&plat, &in, &boot_out);
            if (boot_out.action == BOOT_REFRESH && retry == 0) {
                retry = 1;
                continue;
            }
            break;
        }
        act = boot_out.action;
        save_flash();

        if (act == BOOT_ENROLL) {
            fprintf(stdout, "UNENROLLED\n");
            fflush(stdout);
            return 3;
        }
        fprintf(stdout, "BOOT action=%d safe=%s svn=%llu floor=%llu slot=%d trial=%d bits=%u worst=%u\n",
                act, rot_safe_name(boot_out.safe_reason), (unsigned long long)boot_out.hnd.svn,
                (unsigned long long)boot_out.hnd.floor, boot_out.chain_slot, boot_out.trial,
                boot_out.hnd.bits_corrected, boot_out.hnd.worst_block);
        printf("LISTENING %d\n", port);
        fflush(stdout);

        if (act == BOOT_SAFE) {
            if (!serve(1)) break;
            reset_cause = RC_PSTATE;
            continue;
        }
        if (boot_out.trial) {
            run_trial();
            save_flash();
            continue;               /* straight back to the RoT */
        }
        reset_cause = RC_PSTATE;
        if (!serve(0)) break;
        save_flash();
    }

    save_flash();
    if (log_file) fclose(log_file);
    flash_model_free(&fm);
    return 0;
}
