/* Exercise the real optional-observer fallback on non-lock-free targets. */
#include <assert.h>
#include <stdatomic.h>
#include <string.h>
#undef ATOMIC_INT_LOCK_FREE
#define ATOMIC_INT_LOCK_FREE 1
#include "../src/wendy_pki_clock_observation.c"

int main(void)
{
    struct wendy_pki_certificate_time clock = {.seconds = 200, .floor = 190,
        .monotonic_us = 1000000, .generation = 7};
    struct wendy_pki_certificate_time original = clock;
    struct wendy_pki_mesh_identity identity = {.config_generation = 7,
        .certificate_time = clock};
    struct wendy_pki_mesh_identity original_identity = identity;
    struct pki_clock_observation_raw raw = {.utc_us = 300000000, .valid = true};
    wendy_pki_clock_observe_boot();
    wendy_pki_clock_observe_console_ready();
    pki_clock_observation_publish_clock(7, &clock);
    pki_clock_observation_publish_clock(0, NULL);
    pki_clock_observation_publish_proof(7, 300, 1000000);
    wendy_pki_clock_observe_first_remote(&identity);
    wendy_pki_clock_observe_first_remote(NULL);
    pki_clock_observation_direct_apply(raw, raw, 7, false);
    pki_clock_observation_reset();
    struct pki_clock_observation_raw unavailable = pki_clock_observation_read_raw();
    assert(!unavailable.valid && unavailable.utc_us == 0);
    assert(!memcmp(&clock, &original, sizeof clock));
    assert(!memcmp(&identity, &original_identity, sizeof identity));
    return 0;
}
