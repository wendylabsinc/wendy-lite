/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

/* A local certificate-validation clock, never a public-time assertion. */
struct wendy_pki_certificate_time {
    time_t seconds, floor;
    int64_t monotonic_us;
    bool uncertain, follow_certainty;
    uint64_t generation;
};
bool wendy_pki_certificate_generation_uncertain(uint64_t generation);
void wendy_pki_certificate_mark_certain(uint64_t generation);
void wendy_pki_certificate_reset_certainty(void);
static inline bool wendy_pki_certificate_is_uncertain(const struct wendy_pki_certificate_time *clock)
{
    return clock && clock->uncertain && (!clock->follow_certainty ||
        wendy_pki_certificate_generation_uncertain(clock->generation));
}
static inline time_t wendy_pki_certificate_now(const struct wendy_pki_certificate_time *clock,
                                               int64_t monotonic_us, time_t wall)
{
    if (!clock || clock->seconds <= 0 || clock->monotonic_us < 0 ||
        monotonic_us < clock->monotonic_us)
        return 0;
    int64_t elapsed = (monotonic_us - clock->monotonic_us) / INT64_C(1000000);
    if ((int64_t)clock->seconds > INT64_MAX - elapsed)
        return 0;
    time_t now = (time_t)((int64_t)clock->seconds + elapsed);
    return wall > now ? wall : now;
}
static inline bool wendy_pki_certificate_dates(time_t start, time_t end, bool leaf,
                                               time_t now, bool uncertain)
{
    if (start < 0 || end <= start || now <= 0 || end <= now)
        return false;
    if (leaf && (int64_t)end - start > INT64_C(732) * 86400)
        return false;
    if (start <= now)
        return true;
    return leaf && uncertain && (int64_t)start - now <= INT64_C(86400);
}
