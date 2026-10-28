#include "wendy_operator_auth.h"
#include "wendy_pki_crypto.h"
#include "wendy_peer_identity.h"
#include "wendy_pki_operator.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"

static int certificate_tenant(const mbedtls_x509_crt *crt, const char *kind,
                              unsigned char tenant[36])
{
    int count = 0;
    if (!crt || crt->MBEDTLS_PRIVATE(ca_istrue)) return -1;
    for (const mbedtls_x509_sequence *a = &crt->subject_alt_names;
         a && a->buf.p; a = a->next) {
        mbedtls_x509_subject_alternative_name san;
        if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san) ||
            san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) continue;
        const mbedtls_x509_buf *uri = &san.san.unstructured_name;
        if (!strcmp(kind,"operator")) {
            /* Primary subjects are opaque URI text, not enrolled-device path
             * segments. Share the bounded manifest grammar without copying
             * a principal into each live TLS connection. */
            if(wendy_pki_operator_principal((const char *)uri->p,uri->len,NULL))return -1;
            memcpy(tenant,uri->p+sizeof(wendy_identity_prefix)-1,36);
        } else if (!wendy_peer_identity(uri->p, uri->len, kind, tenant)) return -1;
        count++;
    }
    return count == 1 ? 0 : -1;
}

int wendy_operator_auth_init(struct wendy_operator_auth *auth,
                             const uint8_t *device_der, size_t size)
{
    if (!auth) return -1;
    memset(auth, 0, sizeof *auth);
    if (!device_der || !size || size > 65536 || wendy_pki_crypto_init()) return -1;
    /* esp-pqc stores the ML-DSA public key inline in this structure. Keep it
     * off the smaller legacy BLE task stack while extracting the tenant. */
    mbedtls_x509_crt *device = mbedtls_calloc(1, sizeof *device);
    if (!device) return -1;
    mbedtls_x509_crt_init(device);
    unsigned char tenant[36];
    int result = -1;
    if (!mbedtls_x509_crt_parse_der(device, device_der, size) &&
        device->raw.len == size && !certificate_tenant(device, "device", tenant)) {
        memcpy(auth->tenant, tenant, sizeof tenant);
        result = 0;
    }
    mbedtls_x509_crt_free(device);
    mbedtls_free(device);
    return result;
}

enum wendy_peer_role wendy_peer_auth_role(const mbedtls_x509_crt *crt,
                                          const char *tenant)
{
    unsigned char peer_tenant[36];
    if (!tenant || !wendy_identity_uuid((const unsigned char *)tenant, strlen(tenant)))
        return WENDY_PEER_ROLE_NONE;
    enum wendy_peer_role role;
    if (!certificate_tenant(crt, "operator", peer_tenant))
        role = WENDY_PEER_ROLE_OPERATOR;
    else if (!certificate_tenant(crt, "device", peer_tenant))
        role = WENDY_PEER_ROLE_DEVICE;
    else
        return WENDY_PEER_ROLE_NONE;
    if (memcmp(peer_tenant, tenant, sizeof peer_tenant)) return WENDY_PEER_ROLE_NONE;
    for (const mbedtls_x509_sequence *eku = &crt->ext_key_usage;
         eku && eku->buf.p; eku = eku->next) {
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_CLIENT_AUTH, &eku->buf) == 0) return role;
    }
    return WENDY_PEER_ROLE_NONE;
}

int wendy_operator_auth_check(const mbedtls_x509_crt *crt, const char *tenant)
{
    return wendy_peer_auth_role(crt, tenant) == WENDY_PEER_ROLE_OPERATOR ? 0 : -1;
}

int wendy_operator_auth_verify(void *ctx, mbedtls_x509_crt *crt,
                               int depth, uint32_t *flags)
{
    struct wendy_operator_auth *auth = ctx;
    if (!flags) return -1;
    if (depth == 0) {
        enum wendy_peer_role role = auth ? wendy_peer_auth_role(crt, auth->tenant)
                                        : WENDY_PEER_ROLE_NONE;
        if (!auth || role == WENDY_PEER_ROLE_NONE ||
            (role == WENDY_PEER_ROLE_DEVICE && !auth->allow_device) ||
            (auth->role != WENDY_PEER_ROLE_NONE && role != auth->role)) {
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
        } else if (!*flags) {
            auth->role = role;
        }
    }
    return 0;
}
