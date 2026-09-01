/*
 * Integrated boot: read the (noisy) simulated PUF, recover key material with
 * the fuzzy extractor, derive the rollback-auth key, and run the secure-boot
 * decision (which authenticates the rollback counter and verifies the firmware
 * signature). Prints a structured result and exits QEMU.
 *
 * Exit code: 0 = booted; 10 + sb_decision = refused.
 */

#include "rt/rt.h"
#include "fixture.h"

#include "puf/puf_sim.h"
#include "fuzzy/fuzzy_extractor.h"
#include "kdf/kdf.h"
#include "rollback/rollback.h"
#include "secure_boot/secure_boot.h"

static const char *decision_name(sb_decision d)
{
    switch (d) {
    case SB_BOOT:                 return "BOOT";
    case SB_REFUSE_MALFORMED:     return "MALFORMED";
    case SB_REFUSE_BAD_SIGNATURE: return "BAD_SIGNATURE";
    case SB_REFUSE_COUNTER:       return "COUNTER";
    case SB_REFUSE_ROLLBACK:      return "ROLLBACK";
    default:                      return "UNKNOWN";
    }
}

int main(void)
{
    uint32_t t0 = rt_instret();

    const uint32_t device_id  = fixture_device_id();
    const uint32_t ber_ppm    = fixture_ber_ppm();
    const size_t   helper_len = fixture_helper_len();
    const fuzzy_params fp = {
        .blocks = fixture_fuzzy_blocks(),
        .rep    = fixture_fuzzy_rep(),
    };

    /* 1. this silicon's PUF read for this power-up */
    static const uint8_t boot_nonce[4] = { 1, 0, 0, 0 };
    uint8_t w[FUZZY_MAX_RESPONSE_BYTES];
    puf_sim_response_noisy(device_id, ber_ppm, boot_nonce, sizeof boot_nonce,
                           w, helper_len);

    /* 2. fuzzy Rep -> key material */
    uint8_t key_material[32];
    int frc = fuzzy_rep(fp, w, helper_len, fixture_helper(), helper_len,
                        key_material, sizeof key_material);

    /* 3. rollback-auth key */
    uint8_t rb_key[ROLLBACK_KEY_BYTES];
    rot_kdf_derive(key_material, sizeof key_material,
                   (const uint8_t *)"rollback-auth-key", 17,
                   rb_key, sizeof rb_key);

    /* 4. secure-boot decision */
    rollback_store rb;
    memcpy(rb.page[0], fixture_rb_page0(), 64);
    memcpy(rb.page[1], fixture_rb_page1(), 64);

    secure_boot_otp otp;
    memcpy(otp.vendor_pubkey, fixture_otp(), SB_PUBKEY_BYTES);

    sb_result r;
    sb_decision d = (frc != 0)
        ? SB_REFUSE_MALFORMED
        : secure_boot_check(&otp, fixture_fw(), fixture_fw_len(), &rb, rb_key, &r);

    uint32_t t1 = rt_instret();

    uart_puts("device_id=");   uart_putu(device_id);            uart_puts("\n");
    uart_puts("decision=");    uart_puts(decision_name(d));      uart_puts("\n");
    uart_puts("fw_version=");  uart_putu((uint32_t)r.fw_version); uart_puts("\n");
    uart_puts("counter=");     uart_putu((uint32_t)r.counter);   uart_puts("\n");
    uart_puts("rollback_rc="); uart_putu((uint32_t)(int32_t)r.rollback_rc); uart_puts("\n");
    uart_puts("boot_instret="); uart_putu(t1 - t0);             uart_puts("\n");
    uart_puts("heap_hwm=");    uart_putu(rt_heap_hwm());         uart_puts("\n");

    if (d == SB_BOOT) {
        uart_puts("RESULT=BOOT\n");
        rt_exit(0);
    }
    uart_puts("RESULT=REFUSE\n");
    rt_exit(10 + (int)d);
    return 0;
}
