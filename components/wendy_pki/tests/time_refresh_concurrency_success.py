"""Ordinary management preparation while a background time request waits on WAN.

Execute the production refresh function. Network and already-valid time-reply
effects are substituted; this test covers lock scheduling, not cryptography.
"""
from pathlib import Path
import os
import subprocess
import tempfile

source = (Path(__file__).resolve().parent.parent / 'src/wendy_pki.c').read_text()
start = source.index('static int refresh_time_source(')
body = source.index('{', start)
depth, end = 1, body + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
refresh = source[start:end]

fixture = r'''
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
typedef int nvs_handle_t;
struct wendy_conf_span { const uint8_t *data; size_t size; };
struct wendy_conf_enrollment_data {
    struct wendy_conf_span https_roots, tsa_roots;
    uint64_t generation;
};
struct wendy_pki_stream { int unused; };
struct pki_clock_observation_raw { bool valid; int64_t utc_us; };
static pthread_mutex_t identity_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t mesh_verified_seconds;
static int64_t mesh_verified_monotonic_us;
static uint64_t mesh_verified_generation;
static bool management_prepared, network_unavailable;
static unsigned published;
static void locked(void) {
    int r = pthread_mutex_trylock(&identity_lock);
    if (!r) pthread_mutex_unlock(&identity_lock);
    assert(r != 0);
}
static void *management(void *unused) {
    if (!pthread_mutex_trylock(&identity_lock)) {
        management_prepared = true;
        pthread_mutex_unlock(&identity_lock);
    }
    return NULL;
}
static void esp_fill_random(void *bytes, size_t size) {
    for (size_t i = 0; i < size; i++) ((uint8_t *)bytes)[i] = (uint8_t)i;
}
static size_t wendy_pki_time_request(uint8_t *request, const uint8_t *nonce) {
    *request = *nonce; return 1;
}
static int64_t esp_timer_get_time(void) { return 1000000; }
static bool identity_use_allowed(void) { return true; }
static bool wendy_pki_reset_in_progress(void) { return false; }
static bool wendy_conf_snapshot_current(uint64_t generation) { return generation == 42; }
static int clock_floor(nvs_handle_t h, int64_t *floor) {
    locked(); *floor = 50; return 0;
}
static int wendy_pki_verify_time(const void *response, size_t size, const void *nonce,
                                const void *roots, size_t roots_size, int64_t floor,
                                time_t *when) {
    locked(); *when = 100; return 0;
}
static int set_floor(nvs_handle_t h, time_t when) { locked(); assert(when == 100); return 0; }
static struct pki_clock_observation_raw pki_clock_observation_read_raw(void) {
    locked(); return (struct pki_clock_observation_raw){.valid = true, .utc_us = 100000000};
}
static void wendy_pki_certificate_mark_certain(uint64_t generation) { locked(); }
static void pki_clock_observation_publish_proof(uint64_t generation, time_t seconds,
                                               int64_t monotonic) { locked(); published++; }
static void pki_clock_observation_direct_apply(struct pki_clock_observation_raw before,
        struct pki_clock_observation_raw after, uint64_t generation, bool sufficient) { locked(); }
static int pki_http_post(const char *url, const char *type, const char *bearer,
        const void *request, size_t size, const void *key, size_t key_size,
        struct wendy_conf_span certificate, struct wendy_conf_span roots,
        uint8_t **response, size_t *response_size) {
    /* A normal management request arrives while HTTPS is waiting for bytes. */
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, management, NULL));
    assert(!pthread_join(thread, NULL));
    if (network_unavailable) return -1;
    *response = malloc(1); assert(*response); *response_size = 1;
    return 0;
}
static int mesh_time_exchange(const struct wendy_pki_stream *stream, const uint8_t *request,
        size_t size, uint8_t **response, size_t *response_size, const char magic[4]) {
    assert(0); return -1;
}
static int pki_http_post_stream(const char *url, const char *type, const void *request,
        size_t size, struct wendy_conf_span roots, const struct wendy_pki_stream *stream,
        uint8_t **response, size_t *response_size) { assert(0); return -1; }
'''
extra = ', yield' if 'bool yield_identity' in refresh else ''
main = r'''
static int run_refresh(bool yield) {
    const struct wendy_conf_enrollment_data data = {.generation = 42};
    return refresh_time_source(1, "https://ordinary-time-request", &data, NULL, NULL EXTRA);
}
int main(void) {
    pthread_mutex_lock(&identity_lock);
    assert(!run_refresh(true));
    locked();
    pthread_mutex_unlock(&identity_lock);
    assert(management_prepared);
    assert(published == 1 && mesh_verified_seconds == 100 &&
           mesh_verified_monotonic_us == 1000000 && mesh_verified_generation == 42);
    management_prepared = false;
    network_unavailable = true;
    pthread_mutex_lock(&identity_lock);
    assert(run_refresh(true) == -1);
    locked();
    pthread_mutex_unlock(&identity_lock);
    assert(management_prepared && published == 1);
    management_prepared = false;
    network_unavailable = false;
    pthread_mutex_lock(&identity_lock);
    assert(!run_refresh(false));
    locked();
    pthread_mutex_unlock(&identity_lock);
    assert(!management_prepared && published == 2);
    return 0;
}
'''.replace(' EXTRA', extra)
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.c').write_text(fixture + refresh + main)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', '-Wno-unused-function', '-pthread',
                    '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')],
                   check=True)
    subprocess.run([str(p / 'test')], check=True)
print('management prepares during background WAN wait; clock publication remains serialized: PASS')
