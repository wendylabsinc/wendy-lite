/* Host-only generator. The arguments contain ephemeral test credentials. */
#include "wendy_mesh_protocol.h"
#include "wendy_pki_mesh.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void* load(const char* path, size_t* size)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END))
    {
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 1 || n > 65536 || fseek(f, 0, SEEK_SET))
    {
        fclose(f);
        return NULL;
    }
    uint8_t* out = calloc(1, (size_t)n + 1);
    if (!out)
    {
        fclose(f);
        return NULL;
    }
    if (fread(out, 1, n, f) != (size_t)n)
    {
        free(out);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = n;
    return out;
}
static int number(const char* text, uint64_t* out)
{
    if (!text || !*text)
        return -1;
    uint64_t value = 0;
    for (const char* p = text; *p; p++)
    {
        unsigned c = *p - '0';
        if (c > 9 || value > (UINT64_MAX - c) / 10)
            return -1;
        value = value * 10 + c;
    }
    *out = value;
    return 0;
}
int main(int argc, char** argv)
{
    if (argc != 10)
        return 2;
    size_t keysize = 0, certsize = 0, sigsize = 0, encoded = 0;
    uint8_t *keyder = load(argv[1], &keysize), *pem = load(argv[2], &certsize), signature[80],
            hash[32];
    char body[768], principal[106], signature64[113];
    struct wm_manifest m = { .agent_port = 5054 };
    uint64_t seq, issued, expires;
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int result = 1;
    if (!keyder || !pem || wendy_pki_crypto_init() || wm_uuid_parse(argv[4], m.device)
        || wm_principal(argv[3], argv[4], principal) < 0 || number(argv[5], &m.revision)
        || number(argv[6], &m.router_id) || number(argv[7], &seq) || seq > 65535
        || number(argv[8], &issued) || issued > INT64_MAX / 1000 || number(argv[9], &expires)
        || expires > INT64_MAX / 1000)
        goto done;
    m.seqno = seq;
    m.issued = issued * 1000;
    m.expires = expires * 1000;
    int n = wm_manifest_write(&m, body, sizeof body);
    if (n < 0 || mbedtls_pk_parse_key(&key, keyder, keysize, NULL, 0)
        || mbedtls_x509_crt_parse(&chain, pem, certsize + 1)
        || mbedtls_pk_check_pair(&chain.pk, &key) || wendy_pki_mesh_digest(principal, body, n, hash)
        || mbedtls_pk_sign(
            &key, MBEDTLS_MD_SHA256, hash, sizeof hash, signature, sizeof signature, &sigsize)
        || mbedtls_base64_encode(
            (unsigned char*)signature64, sizeof signature64, &encoded, signature, sigsize))
        goto done;
    printf("{\"tenant\":\"%s\",\"device\":\"%s\",\"manifest\":{\"principal\":\"%s\",\"body\":%s,"
           "\"signature\":\"%s\"},\"bundle\":[",
        argv[3], argv[4], principal, body, signature64);
    unsigned count = 0;
    for (mbedtls_x509_crt* cert = &chain; cert && cert->raw.len; cert = cert->next)
    {
        size_t cap = 4 * ((cert->raw.len + 2) / 3) + 1;
        char* base64 = malloc(cap);
        if (!base64)
            goto done;
        int r = mbedtls_base64_encode(
            (unsigned char*)base64, cap, &encoded, cert->raw.p, cert->raw.len);
        if (r)
        {
            free(base64);
            goto done;
        }
        printf("%s\"%s\"", count++ ? "," : "", base64);
        free(base64);
    }
    printf("]}\n");
    result = 0;
done:
    if (keyder)
    {
        memset(keyder, 0, keysize);
        free(keyder);
    }
    free(pem);
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&chain);
    return result;
}
