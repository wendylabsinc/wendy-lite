/* Host TLS adapter for provisioned operator auth and unprovisioned anonymous TLS. */
#include "wendy_operator_auth.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static unsigned char *load(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    *size = (size_t)length;
    unsigned char *data = calloc(1, *size + 1);
    assert(data && fread(data, 1, *size, file) == *size);
    fclose(file);
    return data;
}

int main(int argc, char **argv)
{
    assert(argc == 6);
    int callback = !strcmp(argv[5], "callback") || !strcmp(argv[5], "callback-lan");
    int lan = strstr(argv[5], "-lan") != NULL;
    int unprovisioned = !strcmp(argv[5], "unprovisioned");
    assert(callback || unprovisioned || !strcmp(argv[5], "post-handshake") || !strcmp(argv[5], "post-handshake-lan"));
    signal(SIGPIPE, SIG_IGN);
    size_t key_size, device_size, roots_size;
    unsigned char *key_der = load(argv[1], &key_size);
    unsigned char *device_der = load(argv[2], &device_size);
    unsigned char *roots_pem = load(argv[3], &roots_size);
    struct wendy_operator_auth auth;
    if (!unprovisioned)
        assert(!wendy_operator_auth_init(&auth, device_der, device_size));
    if (!unprovisioned) auth.allow_device = lan;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_pk_context key;
    mbedtls_x509_crt certificate, roots;
    mbedtls_ssl_config config;
    mbedtls_ssl_context tls;
    mbedtls_net_context peer;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    mbedtls_pk_init(&key);
    mbedtls_x509_crt_init(&certificate);
    mbedtls_x509_crt_init(&roots);
    mbedtls_ssl_config_init(&config);
    mbedtls_ssl_init(&tls);
    mbedtls_net_init(&peer);
    assert(!mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, NULL, 0));
    assert(!mbedtls_pk_parse_key(&key, key_der, key_size, NULL, 0,
                                mbedtls_ctr_drbg_random, &random));
    assert(!mbedtls_x509_crt_parse_der(&certificate, device_der, device_size));
    assert(!mbedtls_x509_crt_parse(&roots, roots_pem, roots_size + 1));
    assert(!mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &random);
    mbedtls_ssl_conf_authmode(&config, unprovisioned ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_REQUIRED);
    if (!unprovisioned)
        mbedtls_ssl_conf_ca_chain(&config, &roots, NULL);
    if (callback)
        mbedtls_ssl_conf_verify(&config, wendy_operator_auth_verify, &auth);
    assert(!mbedtls_ssl_conf_own_cert(&config, &certificate, &key));
    assert(!mbedtls_ssl_setup(&tls, &config));
    free(key_der);
    free(device_der);
    free(roots_pem);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(listener, (struct sockaddr *)&address, sizeof address));
    socklen_t address_size = sizeof address;
    assert(!getsockname(listener, (struct sockaddr *)&address, &address_size));
    assert(!listen(listener, 1));
    printf("%d\n", ntohs(address.sin_port));
    fflush(stdout);
    peer.fd = accept(listener, NULL, NULL);
    close(listener);
    assert(peer.fd >= 0);
    struct timeval timeout = {.tv_sec = 4};
    assert(!setsockopt(peer.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout));
    assert(!setsockopt(peer.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout));
    mbedtls_ssl_set_bio(&tls, &peer, mbedtls_net_send, mbedtls_net_recv, NULL);
    int result;
    do {
        result = mbedtls_ssl_handshake(&tls);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    int accepted = !result && (unprovisioned || !mbedtls_ssl_get_verify_result(&tls));
    enum wendy_peer_role role = WENDY_PEER_ROLE_NONE;
    if (accepted && !unprovisioned) {
        role = wendy_peer_auth_role(mbedtls_ssl_get_peer_cert(&tls), auth.tenant);
        if (!callback)
            accepted = role == WENDY_PEER_ROLE_OPERATOR || (lan && role == WENDY_PEER_ROLE_DEVICE);
        else assert(auth.role == role);
    }
    int expected = !strcmp(argv[4], "valid") || !strcmp(argv[4], "valid-device");
    if (accepted) {
        if (!unprovisioned)
            assert(role == (!strcmp(argv[4], "valid-device") ? WENDY_PEER_ROLE_DEVICE : WENDY_PEER_ROLE_OPERATOR));
        const char *ack = unprovisioned ? "setup allowed" : "authenticated";
        assert(mbedtls_ssl_write(&tls, (const unsigned char *)ack, 13) == 13);
    }
    mbedtls_net_free(&peer);
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&config);
    mbedtls_x509_crt_free(&roots);
    mbedtls_x509_crt_free(&certificate);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&random);
    mbedtls_entropy_free(&entropy);
    if (accepted != expected) {
        fprintf(stderr, "expected %s, handshake returned %d\n", argv[4], result);
        return 1;
    }
    return 0;
}
