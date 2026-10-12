/* Exercise the production legacy LAN/BLE identity policy independently of TLS. */
#include "wendy_operator_auth.h"
#include "wendy_pki_verify.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *load(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    *size = (size_t)length;
    unsigned char *data = malloc(*size);
    assert(data && fread(data, 1, *size, file) == *size);
    fclose(file);
    return data;
}

int main(int argc, char **argv)
{
    assert(argc == 5);
    size_t device_size;
    unsigned char *device = load(argv[2], &device_size);
    struct wendy_operator_auth auth;
    memset(&auth, 0, sizeof auth);
    int initialized = wendy_operator_auth_init(&auth, device, device_size);
    if (!strcmp(argv[1], "init")) {
        assert((initialized == 0) == !strcmp(argv[3], "valid"));
        if (!initialized)
            assert(!strcmp(auth.tenant, argv[4]));
        assert(wendy_operator_auth_init(&auth, device, device_size / 2) != 0);
        assert(wendy_operator_auth_init(&auth, NULL, 0) != 0);
    } else {
        int peer_mode = !strcmp(argv[1], "peer");
        assert((peer_mode || !strcmp(argv[1], "verify")) && initialized == 0);
        size_t peer_size;
        unsigned char *peer = load(argv[3], &peer_size);
        mbedtls_x509_crt certificate;
        mbedtls_x509_crt_init(&certificate);
        assert(!mbedtls_x509_crt_parse_der(&certificate, peer, peer_size));
        enum wendy_peer_role expected_role = !strcmp(argv[4], "operator") ? WENDY_PEER_ROLE_OPERATOR :
            !strcmp(argv[4], "device") ? WENDY_PEER_ROLE_DEVICE : WENDY_PEER_ROLE_NONE;
        if (peer_mode) {
            assert(wendy_peer_auth_role(&certificate, auth.tenant) == expected_role);
            assert(wendy_pki_verify_peer(peer, peer_size, auth.tenant) == expected_role);
            assert(wendy_peer_auth_role(&certificate, "4558fd76-afc7-466e-9613-6b715296a526") == WENDY_PEER_ROLE_NONE);
            assert(wendy_pki_verify_peer(peer, peer_size, "") == WENDY_PEER_ROLE_NONE);
            assert(wendy_pki_verify_peer(NULL, 0, auth.tenant) == WENDY_PEER_ROLE_NONE);
        }
        int valid = peer_mode ? expected_role == WENDY_PEER_ROLE_OPERATOR : !strcmp(argv[4], "valid");
        assert((wendy_operator_auth_check(&certificate, auth.tenant) == 0) == valid);
        assert((wendy_pki_verify_operator(peer, peer_size, auth.tenant) == 0) == valid);
        assert(wendy_operator_auth_check(&certificate, "4558fd76-afc7-466e-9613-6b715296a526") != 0);
        assert(wendy_operator_auth_check(&certificate, "") != 0);
        assert(wendy_operator_auth_check(NULL, auth.tenant) != 0);
        const uint32_t existing[] = {
            0,
            MBEDTLS_X509_BADCERT_EXPIRED,
            MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_BAD_KEY,
            MBEDTLS_X509_BADCERT_FUTURE | MBEDTLS_X509_BADCERT_OTHER,
        };
        for (size_t i = 0; i < sizeof existing / sizeof existing[0]; ++i) {
            auth.role = WENDY_PEER_ROLE_NONE;
            uint32_t flags = existing[i];
            assert(!wendy_operator_auth_verify(&auth, &certificate, 0, &flags));
            assert(flags == (existing[i] | (valid ? 0 : MBEDTLS_X509_BADCERT_OTHER)));
            /* Intermediate verification must retain the TLS library's result. */
            flags = existing[i];
            assert(!wendy_operator_auth_verify(&auth, &certificate, 1, &flags));
            assert(flags == existing[i]);
        }
        if (peer_mode) {
            auth.allow_device = true;
            for (size_t i = 0; i < sizeof existing / sizeof existing[0]; ++i) {
                auth.role = WENDY_PEER_ROLE_NONE;
                uint32_t flags = existing[i];
                assert(!wendy_operator_auth_verify(&auth, &certificate, 0, &flags));
                assert(flags == (existing[i] | (expected_role ? 0 : MBEDTLS_X509_BADCERT_OTHER)));
                if (!flags) assert(auth.role == expected_role);
            }
            if (expected_role) {
                auth.role = expected_role == WENDY_PEER_ROLE_OPERATOR ? WENDY_PEER_ROLE_DEVICE : WENDY_PEER_ROLE_OPERATOR;
                uint32_t flags = 0;
                assert(!wendy_operator_auth_verify(&auth, &certificate, 0, &flags));
                assert(flags & MBEDTLS_X509_BADCERT_OTHER);
            }
        }
        uint32_t flags = MBEDTLS_X509_BADCERT_EXPIRED;
        assert(!wendy_operator_auth_verify(NULL, &certificate, 0, &flags));
        assert(flags == (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_OTHER));
        mbedtls_x509_crt_free(&certificate);
        free(peer);
    }
    free(device);
    return 0;
}
