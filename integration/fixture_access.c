#include "fixture.h"

static uint32_t rd32(size_t off)
{
    const unsigned char *p = fixture_blob + off;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint32_t fixture_device_id(void)    { return rd32(4); }
uint32_t fixture_ber_ppm(void)      { return rd32(8); }
uint32_t fixture_fuzzy_blocks(void) { return rd32(12); }
uint32_t fixture_fuzzy_rep(void)    { return rd32(16); }
size_t   fixture_helper_len(void)   { return rd32(20); }
size_t   fixture_fw_len(void)       { return rd32(24); }

const uint8_t *fixture_helper(void)
{
    return fixture_blob + 28;
}

const uint8_t *fixture_rb_page0(void)
{
    return fixture_helper() + fixture_helper_len();
}

const uint8_t *fixture_rb_page1(void)
{
    return fixture_rb_page0() + FIXTURE_RB_PAGE_BYTES;
}

const uint8_t *fixture_otp(void)
{
    return fixture_rb_page1() + FIXTURE_RB_PAGE_BYTES;
}

const uint8_t *fixture_fw(void)
{
    return fixture_otp() + FIXTURE_OTP_BYTES;
}
