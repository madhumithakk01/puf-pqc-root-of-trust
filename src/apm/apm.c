#include "apm/apm.h"

#include <string.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

void apm_build(uint8_t out[APM_BYTES], const apm_t *m)
{
    memset(out, 0, APM_BYTES);
    memcpy(out, "APM1", 4);
    put16(out + 4, APM_VERSION);
    put16(out + 6, m->flags);
    memcpy(out + 8, m->version, APM_VERSION_STR_LEN);
    put64(out + 24, m->svn);
    put32(out + 32, APM_BYTES);
    put32(out + 36, m->app_bin_len);
    put16(out + 40, m->golden_bpm_x10);
    put16(out + 42, m->tol_bpm_x10);
    put16(out + 44, m->golden_spo2_x10);
    put16(out + 46, m->tol_spo2_x10);
    put16(out + 48, m->min_live_samples);
    put16(out + 50, m->trial_deadline_ms);
    memcpy(out + 56, m->golden_digest, 32);
    memcpy(out + 88, m->build_id, 20);
}

apm_status apm_parse(const uint8_t *body, size_t body_len,
                     uint64_t sbi_fw_version, apm_t *out)
{
    if (body_len < APM_BYTES) return APM_E_SHORT;
    if (memcmp(body, "APM1", 4) != 0) return APM_E_MAGIC;
    if (get16(body + 4) != APM_VERSION) return APM_E_VERSION;
    if (get32(body + 32) != APM_BYTES) return APM_E_OFFSET;

    uint32_t bin_len = get32(body + 36);
    if (bin_len == 0 || (uint64_t)bin_len != (uint64_t)body_len - APM_BYTES)
        return APM_E_LENGTH;
    if (get64(body + 24) != sbi_fw_version) return APM_E_SVN;

    uint16_t flags = get16(body + 6);
    uint16_t spo2 = get16(body + 44);
    uint16_t deadline = get16(body + 50);
    int has_spo2 = (flags & APM_FLAG_HAS_SPO2) != 0;
    if ((flags & ~APM_FLAG_HAS_SPO2) != 0
        || has_spo2 == (spo2 == APM_SPO2_NONE)
        || deadline == 0 || deadline > APM_MAX_DEADLINE_MS
        || !all_zero(body + 52, 4)
        || !all_zero(body + 108, APM_BYTES - 108))
        return APM_E_FIELDS;

    if (out) {
        out->flags = flags;
        memcpy(out->version, body + 8, APM_VERSION_STR_LEN);
        out->svn = get64(body + 24);
        out->app_bin_len = bin_len;
        out->golden_bpm_x10 = get16(body + 40);
        out->tol_bpm_x10 = get16(body + 42);
        out->golden_spo2_x10 = spo2;
        out->tol_spo2_x10 = get16(body + 46);
        out->min_live_samples = get16(body + 48);
        out->trial_deadline_ms = deadline;
        memcpy(out->golden_digest, body + 56, 32);
        memcpy(out->build_id, body + 88, 20);
    }
    return APM_OK;
}
