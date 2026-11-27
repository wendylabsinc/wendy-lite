#include "wendy_pki_est.h"

#include <assert.h>
#include <string.h>

/* Certs-only SignedData with a synthetic three-byte certificate. The parser
 * handles its framing; certificate contents are checked by the X.509 layer. */
static const char body[] = "MCgGCSqGSIb3DQEHAqAbM \r\nBkCAQExADALBgkqhkiG9w0BBwGgAzABADEA";
static const char legacy[] = "MCYGCSqGSIb3DQEHAjAZA \r\ngEBMQAwCwYJKoZIhvcNAQcBoAMwAQAxAA==";

static void test_splits(const char *encoded)
{
    size_t bytes = strlen(encoded);
    for (size_t width = 1; width <= bytes; width++) {
        struct pki_est_stream stream = {0};
        for (size_t offset = 0; offset < bytes; offset += width) {
            size_t length = bytes - offset < width ? bytes - offset : width;
            assert(!pki_est_feed(&stream, (const uint8_t *)encoded + offset, length));
        }
        assert(pki_est_complete(&stream));
        assert(stream.count == 1 && stream.certs[0].size == 3);
        assert(!memcmp(stream.certs[0].der, (const uint8_t[]){0x30, 1, 0}, 3));
        assert(pki_est_feed(&stream, (const uint8_t *)"AAAA", 4));
        assert(!pki_est_complete(&stream));
        pki_est_free(&stream);
    }
}

static void test_url(void)
{
    static const char tenant[] = "12345678-1234-1234-1234-123456789abc";
    static const char csr[] = "https://csr.dev.pki.wendy.sh/v1/12345678-1234-1234-1234-123456789abc";
    char out[321];
    assert(!pki_est_url(out, sizeof out, "", csr, tenant, true));
    assert(!strcmp(out, "https://est.dev.pki.wendy.sh/.well-known/est/12345678-1234-1234-1234-123456789abc/cacerts"
                        "?chain_algorithm=ECDSA_P256&full_chain=true"));
    assert(!pki_est_url(out, sizeof out, "https://custom.example/est/cacerts?mode=private", csr, tenant, true));
    assert(!strcmp(out, "https://custom.example/est/cacerts?mode=private&chain_algorithm=ECDSA_P256&full_chain=true"));
    assert(pki_est_url(out, sizeof out, "", "https://csr.custom.example/v1/unrelated", tenant, false));
}

int main(void)
{
    test_splits(body);
    test_splits(legacy);
    struct pki_est_stream truncated = {0};
    assert(!pki_est_feed(&truncated, (const uint8_t *)body, 30));
    assert(!pki_est_complete(&truncated));
    pki_est_free(&truncated);
    test_url();
    return 0;
}
