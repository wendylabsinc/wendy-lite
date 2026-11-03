/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_pki_clock_observation.h"
#include "wendy_conf.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* Diagnostics must not add blocking atomics to the PKI or clock workers.
 * Targets which cannot promise lock-free access keep this optional API inert;
 * the certificate-time policy is independent of these observations. */
#if ATOMIC_INT_LOCK_FREE == 2 && ATOMIC_BOOL_LOCK_FREE == 2

/* Every payload access is atomic, including unsuccessful sequence reads.
 * Existing identity-lock serialization gives one writer; readers never wait
 * for that lock, spin for a writer, allocate, or initialize a clock anchor. */
_Static_assert(ATOMIC_INT_LOCK_FREE == 2 && ATOMIC_BOOL_LOCK_FREE == 2 &&
               sizeof(uint32_t) == sizeof(unsigned int),
               "Clock observations require lock-free 32-bit atomics");
enum { CLOCK_PRESENT, CLOCK_SECONDS, CLOCK_FLOOR = CLOCK_SECONDS + 2,
       CLOCK_MONO = CLOCK_FLOOR + 2, CLOCK_UNCERTAIN = CLOCK_MONO + 2,
       CLOCK_FOLLOW, CLOCK_GENERATION, PROOF_SECONDS = CLOCK_GENERATION + 2,
       PROOF_MONO = PROOF_SECONDS + 2, PROOF_GENERATION = PROOF_MONO + 2,
       WORDS = PROOF_GENERATION + 2 };
static _Atomic uint32_t sequence, payload[WORDS];
static atomic_bool proof_ever, remote_emitted, console_ready;
static _Atomic unsigned boot_state;
enum { BOOT_EMPTY, BOOT_CAPTURING, BOOT_CAPTURED, BOOT_DELIVERED };
static _Atomic unsigned direct_events;
struct observation {
    bool available, clock_present;
    struct wendy_pki_certificate_time clock;
    time_t proof_seconds;
    int64_t proof_mono;
    uint64_t proof_generation;
};
static void put64(unsigned offset, uint64_t value)
{
    atomic_store(&payload[offset], (uint32_t)value);
    atomic_store(&payload[offset + 1], (uint32_t)(value >> 32));
}
static uint64_t get64(const uint32_t words[WORDS], unsigned offset)
{
    return (uint64_t)words[offset] | (uint64_t)words[offset + 1] << 32;
}
static struct observation snapshot(void)
{
    struct observation out = {0};
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        uint32_t first = atomic_load(&sequence), words[WORDS];
        if (first & 1)
            continue;
        for (unsigned i = 0; i < WORDS; i++)
            words[i] = atomic_load(&payload[i]);
        if (first != atomic_load(&sequence))
            continue;
        out.available = true;
        out.clock_present = words[CLOCK_PRESENT] != 0;
        out.clock.seconds = (time_t)get64(words, CLOCK_SECONDS);
        out.clock.floor = (time_t)get64(words, CLOCK_FLOOR);
        out.clock.monotonic_us = (int64_t)get64(words, CLOCK_MONO);
        out.clock.uncertain = words[CLOCK_UNCERTAIN] != 0;
        out.clock.follow_certainty = words[CLOCK_FOLLOW] != 0;
        out.clock.generation = get64(words, CLOCK_GENERATION);
        out.proof_seconds = (time_t)get64(words, PROOF_SECONDS);
        out.proof_mono = (int64_t)get64(words, PROOF_MONO);
        out.proof_generation = get64(words, PROOF_GENERATION);
        return out;
    }
    return out;
}
void pki_clock_observation_publish_clock(uint64_t generation,
                                         const struct wendy_pki_certificate_time *clock)
{
    if (!clock)
        return;
    atomic_fetch_add(&sequence, 1);
    atomic_store(&payload[CLOCK_PRESENT], clock->seconds > 0 && clock->monotonic_us >= 0);
    put64(CLOCK_SECONDS, (uint64_t)clock->seconds);
    put64(CLOCK_FLOOR, (uint64_t)clock->floor);
    put64(CLOCK_MONO, (uint64_t)clock->monotonic_us);
    atomic_store(&payload[CLOCK_UNCERTAIN], clock->uncertain);
    atomic_store(&payload[CLOCK_FOLLOW], clock->follow_certainty);
    put64(CLOCK_GENERATION, generation);
    atomic_fetch_add(&sequence, 1);
}
void pki_clock_observation_publish_proof(uint64_t generation, time_t seconds, int64_t mono)
{
    atomic_fetch_add(&sequence, 1);
    put64(PROOF_SECONDS, (uint64_t)seconds);
    put64(PROOF_MONO, (uint64_t)mono);
    put64(PROOF_GENERATION, generation);
    if (seconds > 0 && mono >= 0)
        atomic_store(&proof_ever, true);
    atomic_fetch_add(&sequence, 1);
}
void pki_clock_observation_reset(void)
{
    atomic_fetch_add(&sequence, 1);
    for (unsigned i = 0; i < WORDS; i++)
        atomic_store(&payload[i], 0);
    atomic_fetch_add(&sequence, 1);
}
struct pki_clock_observation_raw pki_clock_observation_read_raw(void)
{
    struct timeval tv;
    struct pki_clock_observation_raw out = {0};
    if (!gettimeofday(&tv, NULL) && tv.tv_usec >= 0 && tv.tv_usec < 1000000 &&
        tv.tv_sec <= INT64_MAX / INT64_C(1000000) &&
        tv.tv_sec >= INT64_MIN / INT64_C(1000000)) {
        int64_t seconds_us = (int64_t)tv.tv_sec * INT64_C(1000000);
        if (seconds_us <= INT64_MAX - tv.tv_usec) {
            out.utc_us = seconds_us + tv.tv_usec;
            out.valid = true;
        }
    }
    return out;
}
static const char *raw_text(struct pki_clock_observation_raw raw, char text[24])
{
    if (!raw.valid)
        return "null";
    snprintf(text, 24, "%lld", (long long)raw.utc_us);
    return text;
}
enum { RAW_BEFORE_VALID = 1U << 0, RAW_AFTER_VALID = 1U << 1, ANCHOR_VALID = 1U << 2,
       UNCERTAIN_KNOWN = 1U << 3, UNCERTAIN_VALUE = 1U << 4, FRESH_KNOWN = 1U << 5,
       FRESH_VALUE = 1U << 6, EVER_VALUE = 1U << 7, SNAPSHOT_VALID = 1U << 8 };
struct observation_record {
    int64_t raw_before, raw_after, monotonic_us, certificate_base, anchor_seconds, anchor_monotonic;
    uint64_t generation;
    uint32_t flags;
};
_Static_assert(sizeof(struct observation_record) <= 64, "Boot capture must stay bounded");
/* Written once before BOOT_CAPTURED release-publication; read only after an
 * acquiring CAS wins delivery. This is immutable publication, not a seqlock. */
static struct observation_record boot_record;
static struct observation_record capture(const struct wendy_pki_mesh_identity *identity,
                  struct pki_clock_observation_raw before, struct pki_clock_observation_raw after,
                  uint64_t generation)
{
    struct observation state = snapshot();
    int64_t mono = esp_timer_get_time();
    const struct wendy_pki_certificate_time *clock = identity ? &identity->certificate_time
        : state.available && state.clock_present && state.clock.generation == generation
            ? &state.clock : NULL;
    if (identity)
        generation = identity->config_generation;
    bool anchor = clock && clock->seconds > 0 &&
                  clock->monotonic_us >= 0 && mono >= clock->monotonic_us;
    bool current = state.available && state.proof_seconds > 0 && state.proof_mono >= 0 &&
        mono >= state.proof_mono && mono - state.proof_mono < INT64_C(300000000) &&
        state.proof_generation == generation && wendy_conf_snapshot_current(generation);
    bool uncertain_known = anchor || state.available;
    bool uncertain = anchor ? wendy_pki_certificate_is_uncertain(clock)
        : !(state.proof_seconds > 0 && state.proof_generation == generation);
    struct observation_record out = {.raw_before = before.utc_us, .raw_after = after.utc_us,
        .monotonic_us = mono,
        .certificate_base = anchor ? wendy_pki_certificate_now(clock, mono, time(NULL)) : 0,
        .anchor_seconds = anchor ? clock->seconds : 0,
        .anchor_monotonic = anchor ? clock->monotonic_us : 0, .generation = generation,
        .flags = (before.valid ? RAW_BEFORE_VALID : 0) | (after.valid ? RAW_AFTER_VALID : 0) |
            (anchor ? ANCHOR_VALID : 0) | (uncertain_known ? UNCERTAIN_KNOWN : 0) |
            (uncertain ? UNCERTAIN_VALUE : 0) | (state.available ? FRESH_KNOWN | SNAPSHOT_VALID : 0) |
            (current ? FRESH_VALUE : 0) | (atomic_load(&proof_ever) ? EVER_VALUE : 0)};
    return out;
}
static void emit_record(const char *event, const struct observation_record *record,
                          bool direct, bool already_sufficient)
{
    char a[24], b[24];
    struct pki_clock_observation_raw before = {.utc_us = record->raw_before,
                                               .valid = (record->flags & RAW_BEFORE_VALID) != 0},
                                      after = {.utc_us = record->raw_after,
                                               .valid = (record->flags & RAW_AFTER_VALID) != 0};
    const char *fresh = !(record->flags & FRESH_KNOWN) ? "null"
        : record->flags & FRESH_VALUE ? "true" : "false";
    const char *uncertain = !(record->flags & UNCERTAIN_KNOWN) ? "null"
        : record->flags & UNCERTAIN_VALUE ? "true" : "false";
    int64_t emitted = esp_timer_get_time();
#define OBS_FIELDS \
    "\"event\":\"%s\",\"raw_utc_before_us\":%s,\"raw_utc_after_us\":%s," \
    "\"monotonic_us\":%lld,\"emitted_monotonic_us\":%lld,\"certificate_base_seconds\":%lld," \
    "\"anchor_seconds\":%lld,\"anchor_monotonic_us\":%lld,\"anchor_available\":%s," \
    "\"boot_uncertain\":%s,\"fresh_tsa\":%s,\"tsa_verified_this_boot\":%s," \
    "\"config_generation\":%llu,\"snapshot_available\":%s,\"raw_utc_read_error\":%s"
#define OBS_VALUES event, raw_text(before, a), raw_text(after, b), \
    (long long)record->monotonic_us, (long long)emitted, (long long)record->certificate_base, \
    (long long)record->anchor_seconds, (long long)record->anchor_monotonic, \
    record->flags & ANCHOR_VALID ? "true" : "false", uncertain, fresh, \
    record->flags & EVER_VALUE ? "true" : "false", (unsigned long long)record->generation, \
    record->flags & SNAPSHOT_VALID ? "true" : "false", \
    before.valid && after.valid ? "false" : "true"
    if (direct)
        ESP_LOGI("wendy_pki", "WN_CLOCK_OBS {" OBS_FIELDS
            ",\"source\":\"direct_https_signed_time\",\"status\":\"%s\"}",
            OBS_VALUES, already_sufficient ? "already_sufficient" : "applied");
    else
        ESP_LOGI("wendy_pki", "WN_CLOCK_OBS {" OBS_FIELDS "}", OBS_VALUES);
#undef OBS_VALUES
#undef OBS_FIELDS
}
static void deliver_boot(void)
{
    if (!atomic_load(&console_ready))
        return;
    unsigned expected = BOOT_CAPTURED;
    if (atomic_compare_exchange_strong(&boot_state, &expected, BOOT_DELIVERED))
        emit_record("boot", &boot_record, false, false);
}
void wendy_pki_clock_observe_boot(void)
{
    unsigned expected = BOOT_EMPTY;
    if (!atomic_compare_exchange_strong(&boot_state, &expected, BOOT_CAPTURING))
        return;
    struct pki_clock_observation_raw before = pki_clock_observation_read_raw();
    struct pki_clock_observation_raw after = pki_clock_observation_read_raw();
    boot_record = capture(NULL, before, after, 0);
    atomic_store(&boot_state, BOOT_CAPTURED);
    deliver_boot();
}
void wendy_pki_clock_observe_console_ready(void)
{
    atomic_store(&console_ready, true);
    deliver_boot();
}
void wendy_pki_clock_observe_first_remote(const struct wendy_pki_mesh_identity *identity)
{
    if (!identity || identity->certificate_time.seconds <= 0 ||
        identity->certificate_time.monotonic_us < 0 ||
        esp_timer_get_time() < identity->certificate_time.monotonic_us ||
        !wendy_conf_snapshot_current(identity->config_generation))
        return;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&remote_emitted, &expected, true))
        return;
    struct pki_clock_observation_raw before = pki_clock_observation_read_raw();
    struct pki_clock_observation_raw after = pki_clock_observation_read_raw();
    struct observation_record record = capture(identity, before, after, identity->config_generation);
    emit_record("first_remote_mesh_admission", &record, false, false);
}
void pki_clock_observation_direct_apply(struct pki_clock_observation_raw before,
                                         struct pki_clock_observation_raw after,
                                         uint64_t generation, bool already_sufficient)
{
    unsigned count = atomic_load(&direct_events);
    if (count >= 16)
        return;
    atomic_store(&direct_events, count + 1);
    struct observation_record record = capture(NULL, before, after, generation);
    emit_record("direct_https_time_apply", &record, true, already_sufficient);
}

#else

void wendy_pki_clock_observe_boot(void) {}
void wendy_pki_clock_observe_console_ready(void) {}
void wendy_pki_clock_observe_first_remote(const struct wendy_pki_mesh_identity *identity)
{
    (void)identity;
}
struct pki_clock_observation_raw pki_clock_observation_read_raw(void)
{
    return (struct pki_clock_observation_raw){0};
}
void pki_clock_observation_publish_clock(uint64_t generation,
                                       const struct wendy_pki_certificate_time *clock)
{
    (void)generation;
    (void)clock;
}
void pki_clock_observation_publish_proof(uint64_t generation, time_t seconds, int64_t monotonic_us)
{
    (void)generation;
    (void)seconds;
    (void)monotonic_us;
}
void pki_clock_observation_reset(void) {}
void pki_clock_observation_direct_apply(struct pki_clock_observation_raw before,
                                      struct pki_clock_observation_raw after,
                                      uint64_t generation, bool already_sufficient)
{
    (void)before;
    (void)after;
    (void)generation;
    (void)already_sufficient;
}

#endif
