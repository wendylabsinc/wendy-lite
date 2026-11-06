/* Exercise the production observer, including deterministic busy snapshots. */
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int64_t test_mono = 3000000;
static time_t test_wall = 100;
static int raw_error;
static long raw_usec = 123;
static uint64_t current_generation = 7;
int64_t esp_timer_get_time(void) { return test_mono; }
time_t time(time_t *out) { if (out) *out = test_wall; return test_wall; }
int gettimeofday(struct timeval *tv, void *zone)
{
    (void)zone;
    if (raw_error) return -1;
    tv->tv_sec = test_wall; tv->tv_usec = raw_usec;
    return 0;
}
bool wendy_conf_snapshot_current(uint64_t generation) { return generation == current_generation; }
#include "../src/wendy_pki_clock_observation.c"
#include "wendy_pki_internal.h"
#include "wendy_pki_operator.h"
static void *publish_thread(void *unused)
{
    (void)unused;
    for (time_t i = 1; i <= 10000; i++) {
        struct wendy_pki_certificate_time clock = {.seconds = i + 10, .floor = i,
            .monotonic_us = (int64_t)i * 1000000, .generation = 7};
        pki_clock_observation_publish_clock(7, &clock);
    }
    return NULL;
}
static void *capture_boot_thread(void *unused)
{
    (void)unused; wendy_pki_clock_observe_boot(); return NULL;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    struct wendy_pki_mesh_identity identity = {.config_generation = 7,
        .certificate_time = {.seconds = 200, .floor = 190, .monotonic_us = 1000000,
            .uncertain = true, .follow_certainty = true, .generation = 7}};
    struct wendy_pki_mesh_identity original = identity;
    struct pki_clock_observation_raw before = {.utc_us = 100000123, .valid = true},
                                      after = {.utc_us = 300000000, .valid = true};
    if (!strcmp(argv[1], "concurrent")) {
        pthread_t writer; assert(!pthread_create(&writer, NULL, publish_thread, NULL));
        for (unsigned i = 0; i < 20000; i++) {
            struct observation state = snapshot();
            if (state.available && state.clock_present) {
                assert(state.clock.seconds == state.clock.floor + 10);
                assert(state.clock.monotonic_us == (int64_t)state.clock.floor * 1000000);
                assert(state.clock.generation == 7);
            }
        }
        assert(!pthread_join(writer, NULL));
        return 0;
    }
    if (!strcmp(argv[1], "sizes")) {
        printf("{\"connection\":%zu,\"identity\":%zu,\"mesh_peer\":%zu,\"operator_peer\":%zu,\"observer_atomic_payload\":%zu,\"boot_record\":%zu,\"observer_static_declared\":%zu}\n",
            sizeof(wendy_pki_connection), sizeof(identity), sizeof(struct wendy_pki_mesh_peer),
            sizeof(struct wendy_pki_operator_peer), sizeof(payload) + sizeof(sequence),
            sizeof(boot_record), sizeof(payload) + sizeof(sequence) + sizeof(proof_ever) +
            sizeof(remote_emitted) + sizeof(console_ready) + sizeof(boot_state) +
            sizeof(direct_events) + sizeof(boot_record));
        return 0;
    }
    if (!strcmp(argv[1], "publication")) {
        pthread_t capturer; assert(!pthread_create(&capturer, NULL, capture_boot_thread, NULL));
        for (unsigned i = 0; i < 10000; i++) wendy_pki_clock_observe_console_ready();
        assert(!pthread_join(capturer, NULL));
        assert(atomic_load(&boot_state) == BOOT_DELIVERED);
    } else if (!strcmp(argv[1], "ready_first")) {
        wendy_pki_clock_observe_console_ready();
        wendy_pki_clock_observe_boot(); wendy_pki_clock_observe_console_ready();
    } else if (!strcmp(argv[1], "delayed")) {
        wendy_pki_clock_observe_boot();
        assert(atomic_load(&boot_state) == BOOT_CAPTURED);
        test_wall = 900; test_mono += 300000000;
        pki_clock_observation_publish_clock(7, &identity.certificate_time);
        pki_clock_observation_publish_proof(7, 900, test_mono);
        wendy_pki_certificate_mark_certain(7);
        wendy_pki_clock_observe_console_ready(); wendy_pki_clock_observe_console_ready();
    } else if (!strcmp(argv[1], "boot")) {
        wendy_pki_clock_observe_boot(); wendy_pki_clock_observe_boot();
        wendy_pki_clock_observe_console_ready(); wendy_pki_clock_observe_console_ready();
    } else if (!strcmp(argv[1], "remote")) {
        wendy_pki_clock_observe_first_remote(NULL);
        struct wendy_pki_mesh_identity unavailable = {0};
        wendy_pki_clock_observe_first_remote(&unavailable);
        unavailable = identity; unavailable.config_generation = 8;
        wendy_pki_clock_observe_first_remote(&unavailable);
        unavailable = identity; unavailable.certificate_time.monotonic_us = test_mono + 1;
        wendy_pki_clock_observe_first_remote(&unavailable);
        wendy_pki_clock_observe_first_remote(&identity); wendy_pki_clock_observe_first_remote(&identity);
    } else if (!strcmp(argv[1], "floor_zero")) {
        identity.certificate_time.floor = 0; original = identity;
        wendy_pki_clock_observe_first_remote(&identity);
    } else if (!strcmp(argv[1], "no_proof")) {
        identity.certificate_time.uncertain = false;
        original = identity;
        wendy_pki_clock_observe_first_remote(&identity);
    } else if (!strcmp(argv[1], "latches")) {
        wendy_pki_clock_observe_boot();
        wendy_pki_clock_observe_console_ready();
        wendy_pki_clock_observe_first_remote(&identity);
        pki_clock_observation_publish_proof(7, 300, test_mono);
        pki_clock_observation_reset();
        wendy_pki_clock_observe_boot();
        wendy_pki_clock_observe_first_remote(&identity);
        pki_clock_observation_direct_apply(before, after, 7, false);
    } else if (!strcmp(argv[1], "overflow")) {
        test_wall = INT64_MAX / 1000000; raw_usec = 999999;
        wendy_pki_clock_observe_boot(); wendy_pki_clock_observe_console_ready();
    } else if (!strcmp(argv[1], "errors")) {
        raw_error = 1; wendy_pki_clock_observe_boot(); wendy_pki_clock_observe_console_ready();
    } else if (!strcmp(argv[1], "race")) {
        atomic_store(&sequence, 1); wendy_pki_clock_observe_first_remote(&identity);
    } else {
        pki_clock_observation_publish_clock(7, &identity.certificate_time);
        pki_clock_observation_publish_proof(7, 300, test_mono);
        wendy_pki_certificate_mark_certain(7);
        if (!strcmp(argv[1], "stale")) test_mono += INT64_C(300000000);
        if (!strcmp(argv[1], "generation")) current_generation = 8;
        if (!strcmp(argv[1], "reset")) pki_clock_observation_reset();
        bool sufficient = !strcmp(argv[1], "sufficient");
        test_wall = sufficient ? 301 : 300;
        unsigned count = !strcmp(argv[1], "bounded") ? 20 : 1;
        for (unsigned i = 0; i < count; i++)
            pki_clock_observation_direct_apply(before, after, 7, sufficient);
    }
    assert(!memcmp(&identity, &original, sizeof identity));
    return 0;
}
