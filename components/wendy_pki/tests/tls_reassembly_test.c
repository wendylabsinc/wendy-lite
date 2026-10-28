/* SPDX-License-Identifier: Apache-2.0
 * Exercise the common stream record layer without a certificate parser. Real
 * TLS 1.3 crypto/CA interoperability is covered by tls_test_driver.go.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "ssl_misc.h"
#include <assert.h>
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool recycle_mode;
struct recycled {unsigned char *bytes;size_t expected;};
static int recycle_input(void *context,unsigned char *p,size_t size)
{
    struct recycled *saved=context;
    for(size_t i=0;i<size;i++)assert(!p[i]);
    if(size!=saved->expected)return 0;
    assert(!saved->bytes);saved->bytes=p;return 1;
}
struct input
{
    uint8_t *bytes;
    size_t size, offset, calls;
};
static int read_bytes(void *ctx, unsigned char *out, size_t n)
{
    struct input *in = ctx;
    if (++in->calls % 3 == 0)
        return MBEDTLS_ERR_SSL_WANT_READ;
    if (in->offset == in->size)
        return 0;
    if (n > 197)
        n = 197;
    if (n > in->size - in->offset)
        n = in->size - in->offset;
    memcpy(out, in->bytes + in->offset, n);
    in->offset += n;
    return n;
}
static int write_bytes(void *ctx, const unsigned char *in, size_t n)
{
    (void)ctx;
    (void)in;
    return n;
}
static void append_record(struct input *in, const uint8_t *p, size_t n)
{
    assert(n <= 16384);
    uint8_t *out = in->bytes + in->size;
    out[0] = MBEDTLS_SSL_MSG_HANDSHAKE;
    out[1] = 3;
    out[2] = 3;
    out[3] = n >> 8;
    out[4] = n;
    memcpy(out + 5, p, n);
    in->size += 5 + n;
}
static void message(uint8_t *p, size_t n, uint8_t type)
{
    assert(n >= 4 && n <= 32768);
    p[0] = type;
    p[1] = (n - 4) >> 16;
    p[2] = (n - 4) >> 8;
    p[3] = n - 4;
    for (size_t i = 4; i < n; i++)
        p[i] = (uint8_t)(i % 251);
}
static int next(mbedtls_ssl_context *ssl)
{
    int r;
    unsigned calls = 0;
    do
    {
        r = mbedtls_ssl_read_record(ssl, 0);
        assert(++calls < 10000);
    } while (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE);
    return r;
}
static void exercise(size_t first, size_t fragment, size_t following, size_t reserve)
{
    struct input in = {.bytes = calloc(1, 131072)};
    assert(in.bytes);
    uint8_t *a = malloc(first), *b = malloc(following ? following : 1);
    assert(a && b);
    message(a, first, MBEDTLS_SSL_HS_CERTIFICATE);
    if (following)
        message(b, following, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY);
    size_t offset = 0;
    while (first - offset > fragment)
    {
        append_record(&in, a + offset, fragment);
        offset += fragment;
    }
    size_t last = first - offset;
    uint8_t *tail = malloc(last + following);
    assert(tail);
    memcpy(tail, a + offset, last);
    if (following)
        memcpy(tail + last, b, following);
    append_record(&in, tail, last + following);
    free(tail);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    assert(!mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    struct recycled saved={.expected=reserve};
    if(recycle_mode){config.wendy_input_recycle=recycle_input;config.wendy_input_recycle_context=&saved;}
    unsigned char *original = NULL;
    if (reserve) {
        unsigned char *owned = calloc(1, reserve);
        assert(owned); original = owned;
        assert(!mbedtls_ssl_setup_with_preallocated_input(&ssl, &config, &owned, reserve));
        assert(!owned && ssl.in_buf == original && ssl.in_buf_len == reserve);
    } else {
        assert(!mbedtls_ssl_setup(&ssl, &config));
    }
    ssl.tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
    ssl.state = MBEDTLS_SSL_SERVER_CERTIFICATE;
    mbedtls_ssl_set_bio(&ssl, &in, write_bytes, read_bytes, NULL);
    int rc = next(&ssl);
    if (rc)
        fprintf(stderr, "first=%zu fragment=%zu following=%zu rc=%d input=%zu\n", first, fragment,
                following, rc, ssl.in_buf_len);
    assert(rc == 0 && ssl.in_hslen == first && !memcmp(ssl.in_msg, a, first));
    size_t allocated = ssl.in_buf_len;
    if (first == 25352 && !following)
        assert(allocated < 27000);
    if (following)
    {
        assert(!next(&ssl));
        assert(ssl.in_hslen == following && !memcmp(ssl.in_msg, b, following));
    }
    assert(in.offset == in.size);
    if (reserve) assert(ssl.in_buf == original && ssl.in_buf_len == reserve);
    if(recycle_mode){
        /* The fixture has consumed both complete messages; no application
         * pointer, partial record or handshake fragment remains live. */
        ssl.state=MBEDTLS_SSL_HANDSHAKE_OVER;ssl.in_offt=NULL;
        ssl.in_left=ssl.in_msglen=ssl.in_hsfraglen=ssl.in_hslen=0;
        mbedtls_ssl_compact_input_buffer(&ssl);
        assert(ssl.in_buf_len==2048 && saved.bytes==original);
    }
    mbedtls_ssl_free(&ssl);
    free(saved.bytes);
    mbedtls_ssl_config_free(&config);
    free(a);
    free(b);
    free(in.bytes);
    printf("reassembly first=%zu fragment=%zu following=%zu allocated=%zu passed\n", first,
           fragment, following, allocated);
}
static void rejection(bool oversized)
{
    struct input in = {.bytes = calloc(1, 32768)};
    assert(in.bytes);
    uint8_t body[16384];
    message(body, sizeof body, MBEDTLS_SSL_HS_CERTIFICATE);
    size_t declared = oversized ? 32769 : 25352;
    body[1] = (declared - 4) >> 16;
    body[2] = (declared - 4) >> 8;
    body[3] = declared - 4;
    append_record(&in, body, sizeof body);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    assert(!mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    assert(!mbedtls_ssl_setup(&ssl, &config));
    ssl.tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
    ssl.state = MBEDTLS_SSL_SERVER_CERTIFICATE;
    mbedtls_ssl_set_bio(&ssl, &in, write_bytes, read_bytes, NULL);
    int r = next(&ssl);
    assert(r == (oversized ? MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL : MBEDTLS_ERR_SSL_CONN_EOF));
    if (oversized)
        assert(ssl.in_buf_len < 20000);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    free(in.bytes);
}
int main(int argc, char **argv)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    if (argc==2 && !strcmp(argv[1],"--normal-recycle")) {
        recycle_mode=true;exercise(25352,512,7000,32768);
        puts("input compaction returns zeroized storage without changing record bytes");return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--normal-preallocated")) {
        exercise(25352, 16384, 0, 26624);
        exercise(25352, 512, 7000, 32768);
        exercise(6000, 512, 14000, 24576);
        puts("preallocated input ownership and in-place reassembly passed");
        return 0;
    }
    exercise(25352, 16384, 0, 0);
    exercise(25352, 16384, 7000, 0);
    exercise(32768, 16383, 16000, 0);
    exercise(6000, 512, 14000, 0);
    exercise(32768, 512, 0, 0);
    rejection(true);
    rejection(false);
}
