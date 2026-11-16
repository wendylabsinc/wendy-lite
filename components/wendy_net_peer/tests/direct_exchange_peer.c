#include "wendy_net_direct_exchange.h"
#include <psa/crypto.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct fixture {
    struct wn_direct_generation gate;
    struct wn_direct_recovery_record local[5], remote[8];
    struct wn_direct_exchange_config cfg;
    unsigned applied;
};
static int export(void *arg, const uint8_t context[32], uint8_t out[32])
{
    (void)arg;
    (void)context;
    memset(out, 6, 32);
    return 0;
}
static int apply(void *arg)
{
    (*(unsigned *)arg)++;
    return 0;
}
static void setup(struct fixture *f, uint8_t role, bool initial)
{
    memset(f, 0, sizeof *f);
    assert(!wn_direct_generation_init_pending(&f->gate));
    if (!initial) {
        assert(!wn_direct_generation_init(&f->gate, 1, 1, WN_DIRECT_BLE));
        assert(!wn_direct_generation_frozen(&f->gate, 1));
    }
    f->cfg = (struct wn_direct_exchange_config){
        .binding = {.session_id = {1}, .capability = {2}, .identity_digest = {3}, .role = role},
        .gate = &f->gate,
        .token = 10 + role,
        .nonce = {4 + role},
        .remote_records = f->remote,
        .remote_capacity = 8,
        .exporter = export,
        .apply = apply,
        .apply_arg = &f->applied};
    if (!initial) {
        f->cfg.local = (struct wn_direct_recovery_view){
            .namespaces = {{.high_water = 10, .admitted = 5, .grant = 8}, {.grant = 8}},
            .records = f->local,
            .count = 5};
        for (unsigned i = 0; i < 5; i++) {
            f->local[i].id = 2 + i * 2;
            f->local[i].open_complete = true;
            f->local[i].open_digest[0] = (uint8_t)f->local[i].id;
        }
    }
}
/* The optional pipe mode is exercised by the Go driver, not a separate C/C
 * model. Input/output are uint16 lengths followed by actual control wire bytes. */
static int pipe_peer(bool initial)
{
    struct fixture f;
    setup(&f, 1, initial);
    struct wn_direct_exchange p;
    bool started = false;
    for (;;) {
        uint8_t prefix[2], b[533];
        if (fread(prefix, 1, 2, stdin) != 2)
            return started && wn_direct_exchange_active(&p) && f.applied == 1 ? 0 : 1;
        size_t n = (size_t)prefix[0] * 256 + prefix[1];
        if (n > sizeof b || fread(b, 1, n, stdin) != n)
            return 2;
        struct wn_direct_control r;
        if (wn_direct_control_decode(b, n, &r))
            return 3;
        if (!started) {
            if (wn_direct_exchange_participant(&p, &f.cfg, &r))
                return 4;
            started = true;
        } else if (wn_direct_exchange_receive(&p, &r))
            return 5;
        while (wn_direct_exchange_next(&p, &r) == 1) {
            if (wn_direct_control_encode(&r, b, sizeof b, &n) || wn_direct_exchange_accepted(&p))
                return 6;
            prefix[0] = (uint8_t)(n >> 8);
            prefix[1] = (uint8_t)n;
            if (fwrite(prefix, 1, 2, stdout) != 2 || fwrite(b, 1, n, stdout) != n || fflush(stdout))
                return 7;
        }
    }
}
int main(int argc, char **argv)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    return pipe_peer(argc < 2 || strcmp(argv[1], "--pipe-recovery"));
}
