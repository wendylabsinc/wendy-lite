/* Selected-path dates under the local mesh certificate clock. */
#include "wendy_pki_mesh.h"
#include "wendy_pki_operator.h"
#include "wendy_pki_parsed_identity.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint8_t *load(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb"); assert(f);
    assert(!fseek(f, 0, SEEK_END)); long n = ftell(f); assert(n > 0);
    rewind(f); uint8_t *data = malloc((size_t)n); assert(data);
    assert(fread(data, 1, (size_t)n, f) == (size_t)n); fclose(f);
    *size = (size_t)n; return data;
}
int main(int argc, char **argv)
{
    assert(argc == 10);
    const time_t base = 1800000000;
    struct wendy_pki_certificate_time clock = {.seconds = base, .floor = base,
                                               .monotonic_us = 1000000, .uncertain = true};
    assert(wendy_pki_certificate_now(&clock, 6000000, 1) == base + 5);
    assert(wendy_pki_certificate_now(&clock, 6000000, base + 99) == base + 99);
    assert(!wendy_pki_certificate_now(&clock, 999999, base));
    size_t root_n, chain_n;
    uint8_t *root = load(argv[1], &root_n), *wire = load(argv[2], &chain_n);
    mbedtls_x509_crt chain; mbedtls_x509_crt_init(&chain);
    assert(!pki_parse_certificate_bundle(&chain, wire, chain_n, true));
    const uint8_t *der[8]; size_t sizes[8], count = 0;
    for (const mbedtls_x509_crt *c = &chain; c && c->raw.len; c = c->next) {
        assert(count < 8); der[count] = c->raw.p; sizes[count++] = c->raw.len;
    }
    struct wendy_pki_mesh_peer *peer = calloc(1, sizeof *peer); assert(peer);
    struct wendy_pki_operator_peer *operator = calloc(1, sizeof *operator); assert(operator);
    bool is_operator = !strcmp(argv[7], "operator");
    const char *tenant = "2558fd76-afc7-466e-9613-6b715296a526";
    int expected = atoi(argv[3]);
#define VERIFY(at, scope) (is_operator \
    ? wendy_pki_operator_chain_policy(der, sizes, count, root, root_n, scope, at, &clock, operator) \
    : wendy_pki_mesh_chain_policy(der, sizes, count, root, root_n, scope, at, &clock, peer))
    int result = VERIFY(base, tenant);
    assert((result == 0) == (expected == 0));
    if (!result) {
        time_t start = is_operator ? operator->not_before : peer->not_before;
        time_t end = is_operator ? operator->expires : peer->expires;
        assert(start == (time_t)strtoll(argv[4], NULL, 10));
        time_t signing_start = is_operator ? operator->signing_not_before : peer->signing_not_before;
        assert(signing_start == (time_t)strtoll(argv[8], NULL, 10));
        assert(signing_start <= start);
        time_t issuer_start = is_operator ? operator->issuer_not_before : peer->issuer_not_before;
        assert(issuer_start == (time_t)strtoll(argv[9], NULL, 10));
        assert(issuer_start <= start);
        assert(end == (time_t)strtoll(argv[5], NULL, 10));
        assert(VERIFY(end, tenant)); /* Correct wall expiry always wins. */
        assert(VERIFY(base, "2558fd76-afc7-466e-9613-6b715296a527"));
    }
    if (expected == 0 && atoi(argv[6]) != 0) {
        clock.follow_certainty = true;
        clock.generation = 17;
        wendy_pki_certificate_mark_certain(17);
        assert(VERIFY(base, tenant)); /* A live in-flight policy narrows immediately. */
        wendy_pki_certificate_mark_certain(18);
        assert(!VERIFY(base, tenant)); /* Other enrollments confer no certainty. */
        wendy_pki_certificate_reset_certainty();
        clock.follow_certainty = false;
    }
    clock.uncertain = false;
    result = VERIFY(base, tenant);
    assert((result == 0) == (atoi(argv[6]) == 0));
#undef VERIFY
    free(operator); free(peer); mbedtls_x509_crt_free(&chain); free(wire); free(root);
    puts("local certificate clock selected-path controls passed");
    return 0;
}
