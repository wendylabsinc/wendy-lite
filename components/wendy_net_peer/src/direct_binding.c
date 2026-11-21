#include "wendy_net_direct_binding.h"
#include <psa/crypto.h>
#include <string.h>

static const char context_domain[] = "wendy/direct/attachment-context/1";
static const char proof_domain[] = "wendy/direct/attachment-proof/1";

int wn_direct_attachment_context(const struct wn_direct_attachment *a, uint8_t out[32])
{
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (!a || !a->generation || !a->attachment_id || a->mode > 1)
        return -1;
    /* Include the terminating domain NUL; no C struct layout reaches the wire. */
    uint8_t input[sizeof(context_domain) + 141];
    size_t n = 0;
#define APPEND(v, len)                                                                             \
    do {                                                                                           \
        memcpy(input + n, (v), (len));                                                             \
        n += (len);                                                                                \
    } while (0)
    APPEND(context_domain, sizeof(context_domain));
    APPEND(a->session_id, 32);
    for (int shift = 56; shift >= 0; shift -= 8)
        input[n++] = (uint8_t)(a->generation >> shift);
    input[n++] = a->mode;
    for (int shift = 24; shift >= 0; shift -= 8)
        input[n++] = (uint8_t)(a->attachment_id >> shift);
    APPEND(a->coordinator_nonce, 16);
    APPEND(a->participant_nonce, 16);
    APPEND(a->identity_digest, 32);
    APPEND(a->snapshot_digest, 32);
#undef APPEND
    size_t actual = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, input, n, out, 32, &actual) != PSA_SUCCESS ||
        actual != 32) {
        memset(out, 0, 32);
        return -1;
    }
    return 0;
}

static int mac(const uint8_t key[32], const uint8_t exporter[32], const uint8_t context[32],
               uint8_t role, uint8_t *out, const uint8_t *proof, size_t size)
{
    if (!key || !exporter || !context || role > 1)
        return -1;
    uint8_t input[sizeof(proof_domain) + 65];
    memcpy(input, proof_domain, sizeof(proof_domain));
    input[sizeof(proof_domain)] = role;
    memcpy(input + sizeof(proof_domain) + 1, exporter, 32);
    memcpy(input + sizeof(proof_domain) + 33, context, 32);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attributes,
                            out ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE);
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status = psa_import_key(&attributes, key, 32, &id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS)
        return -1;
    if (out) {
        size_t actual = 0;
        status = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input, sizeof(input), out, 32,
                                 &actual);
        if (status == PSA_SUCCESS && actual != 32)
            status = PSA_ERROR_GENERIC_ERROR;
    } else {
        /* The crypto library performs constant-time comparison. */
        status =
            psa_mac_verify(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input, sizeof(input), proof, size);
    }
    psa_status_t destroyed = psa_destroy_key(id);
    return status == PSA_SUCCESS && destroyed == PSA_SUCCESS ? 0 : -1;
}

int wn_direct_attachment_proof(const uint8_t key[32], const uint8_t exporter[32],
                               const uint8_t context[32], uint8_t role, uint8_t out[32])
{
    if (!out)
        return -1;
    int result = mac(key, exporter, context, role, out, NULL, 0);
    if (result)
        memset(out, 0, 32);
    return result;
}
int wn_direct_attachment_verify(const uint8_t key[32], const uint8_t exporter[32],
                                const uint8_t context[32], uint8_t role, const uint8_t *proof,
                                size_t size)
{
    if (!proof || size != 32)
        return -1;
    return mac(key, exporter, context, role, NULL, proof, size);
}

static int nonzero(const uint8_t *p, size_t n)
{
    uint8_t value = 0;
    for (size_t i = 0; i < n; i++)
        value |= p[i];
    return value != 0;
}
static int promoted_context(const uint8_t attachment[32], uint32_t flow_id,
                            const uint8_t open_digest[32], const uint8_t coordinator_nonce[16],
                            const uint8_t participant_nonce[16], uint8_t out[32])
{
    static const char domain[] = "wendy/direct/promoted-flow/1";
    if (!out)
        return -1;
    memset(out, 0, 32);
    if (!flow_id || !open_digest || !coordinator_nonce || !participant_nonce ||
        !nonzero(open_digest, 32) || !nonzero(coordinator_nonce, 16) ||
        !nonzero(participant_nonce, 16))
        return -1;
    uint8_t input[sizeof(domain) + 100];
    size_t n = sizeof(domain), actual = 0;
    memcpy(input, domain, sizeof(domain));
    memcpy(input + n, attachment, 32);
    n += 32;
    for (int shift = 24; shift >= 0; shift -= 8)
        input[n++] = (uint8_t)(flow_id >> shift);
    memcpy(input + n, open_digest, 32);
    n += 32;
    memcpy(input + n, coordinator_nonce, 16);
    n += 16;
    memcpy(input + n, participant_nonce, 16);
    n += 16;
    if (psa_hash_compute(PSA_ALG_SHA_256, input, n, out, 32, &actual) != PSA_SUCCESS ||
        actual != 32) {
        memset(out, 0, 32);
        return -1;
    }
    return 0;
}

int wn_direct_promoted_flow_context(const struct wn_direct_attachment *a, uint32_t flow_id,
                                    const uint8_t open_digest[32],
                                    const uint8_t coordinator_nonce[16],
                                    const uint8_t participant_nonce[16], uint8_t out[32])
{
    if (!out)
        return -1;
    memset(out, 0, 32);
    uint8_t attachment[32];
    if (!a || a->mode != 1 || !nonzero(a->session_id, 32) || !nonzero(a->identity_digest, 32) ||
        !nonzero(a->snapshot_digest, 32) || wn_direct_attachment_context(a, attachment))
        return -1;
    return promoted_context(attachment, flow_id, open_digest, coordinator_nonce, participant_nonce,
                            out);
}

/* Each flight has exact size. In particular READY reads only one byte, leaving
 * coalesced raw application data with the owning transport adapter. */
enum {
    PB_SEND_HELLO = 1,
    PB_RECV_HELLO,
    PB_SEND_RESPONSE,
    PB_RECV_RESPONSE,
    PB_SEND_COMMIT,
    PB_RECV_COMMIT,
    PB_SEND_READY,
    PB_RECV_READY,
    PB_DONE
};
static int pb_fail(struct wn_direct_promoted_binding *b)
{
    b->failed = 1;
    return -1;
}
static void pb_state(struct wn_direct_promoted_binding *b, uint8_t state, size_t size)
{
    b->state = state;
    b->offset = 0;
    b->size = size;
}
static void pb_hello(const struct wn_direct_promoted_binding *b, uint8_t out[64])
{
    memcpy(out, "WDP1", 4);
    memcpy(out + 4, b->scratch.initial.hello, 40);
    for (int i = 0; i < 4; i++)
        out[44 + i] = (uint8_t)(b->flow_id >> (24 - i * 8));
    memcpy(out + 48, b->scratch.initial.nonce, 16);
}
static int pb_derive(struct wn_direct_promoted_binding *b, const uint8_t remote[16])
{
    const uint8_t *n0 = b->role ? remote : b->scratch.initial.nonce,
                  *n1 = b->role ? b->scratch.initial.nonce : remote;
    if (promoted_context(b->attachment_context, b->flow_id, b->open_digest, n0, n1,
                         b->scratch.derived.context) ||
        b->exporter(b->export_arg, WN_DIRECT_PROMOTED_EXPORT_LABEL, b->scratch.derived.context,
                    b->scratch.derived.exported))
        return pb_fail(b);
    return 0;
}
int wn_direct_promoted_init(struct wn_direct_promoted_binding *b,
                            const struct wn_direct_attachment *a, uint32_t id,
                            const uint8_t open[32], const uint8_t capability[32], uint8_t role,
                            const uint8_t nonce[16], int initiator,
                            int (*exporter)(void *, const char *, const uint8_t[32], uint8_t[32]),
                            void *arg)
{
    if (!b)
        return -1;
    memset(b, 0, sizeof(*b));
    b->failed = 1;
    if (!a || a->mode != 1 || !id || !open || !nonzero(open, 32) || !capability ||
        !nonzero(capability, 32) || role > 1 || !nonce || !nonzero(nonce, 16) || !exporter ||
        !nonzero(a->session_id, 32) || !nonzero(a->identity_digest, 32) ||
        !nonzero(a->snapshot_digest, 32) || wn_direct_attachment_context(a, b->attachment_context))
        return -1;
    memcpy(b->scratch.initial.hello, a->session_id, 32);
    for (int i = 0; i < 8; i++)
        b->scratch.initial.hello[32 + i] = (uint8_t)(a->generation >> (56 - i * 8));
    b->flow_id = id;
    b->role = role;
    b->initiator = !!initiator;
    memcpy(b->capability, capability, 32);
    memcpy(b->open_digest, open, 32);
    memcpy(b->scratch.initial.nonce, nonce, 16);
    b->exporter = exporter;
    b->export_arg = arg;
    b->failed = 0;
    pb_state(b, initiator ? PB_SEND_HELLO : PB_RECV_HELLO, 64);
    if (initiator)
        pb_hello(b, b->wire);
    return 0;
}
static int pb_sending(const struct wn_direct_promoted_binding *b)
{
    return b->state == PB_SEND_HELLO || b->state == PB_SEND_RESPONSE ||
           b->state == PB_SEND_COMMIT || b->state == PB_SEND_READY;
}
int wn_direct_promoted_output(struct wn_direct_promoted_binding *b, const uint8_t **p, size_t *size)
{
    if (!p || !size)
        return -1;
    *p = NULL;
    *size = 0;
    if (!b || b->failed)
        return -1;
    if (!pb_sending(b))
        return 0;
    /* Exposure to a writer is already ambiguous, even if its write fails. */
    if (b->state == PB_SEND_COMMIT)
        b->commit_possible = 1;
    *p = b->wire + b->offset;
    *size = b->size - b->offset;
    return 1;
}
int wn_direct_promoted_sent(struct wn_direct_promoted_binding *b, size_t size)
{
    if (!b || b->failed)
        return -1;
    if (!pb_sending(b) || size > b->size - b->offset)
        return pb_fail(b);
    if (b->state == PB_SEND_COMMIT && size)
        b->commit_possible = 1;
    b->offset += size;
    if (b->offset < b->size)
        return 0;
    switch (b->state) {
    case PB_SEND_HELLO:
        pb_state(b, PB_RECV_RESPONSE, 48);
        break;
    case PB_SEND_RESPONSE:
        pb_state(b, PB_RECV_COMMIT, 32);
        break;
    case PB_SEND_COMMIT:
        pb_state(b, PB_RECV_READY, 1);
        break;
    case PB_SEND_READY:
        pb_state(b, PB_DONE, 0);
        b->done = 1;
        break;
    default:
        return pb_fail(b);
    }
    return 0;
}
int wn_direct_promoted_input(struct wn_direct_promoted_binding *b, const uint8_t *p, size_t size,
                             size_t *used)
{
    if (!used)
        return -1;
    *used = 0;
    if (!b || b->failed)
        return -1;
    if (b->done || pb_sending(b))
        return 0;
    if (!p && size)
        return pb_fail(b);
    size_t n = b->size - b->offset;
    if (n > size)
        n = size;
    if (n)
        memcpy(b->wire + b->offset, p, n);
    b->offset += n;
    *used = n;
    if (b->offset < b->size)
        return 0;
    switch (b->state) {
    case PB_RECV_HELLO: {
        uint8_t expected[64], nonce[16];
        pb_hello(b, expected);
        memcpy(nonce, b->scratch.initial.nonce, 16);
        if (memcmp(expected, b->wire, 48) || pb_derive(b, b->wire + 48))
            return pb_fail(b);
        memcpy(b->wire, nonce, 16);
        if (wn_direct_attachment_proof(b->capability, b->scratch.derived.exported,
                                       b->scratch.derived.context, b->role, b->wire + 16))
            return pb_fail(b);
        pb_state(b, PB_SEND_RESPONSE, 48);
        break;
    }
    case PB_RECV_RESPONSE:
        if (pb_derive(b, b->wire) ||
            wn_direct_attachment_verify(b->capability, b->scratch.derived.exported,
                                        b->scratch.derived.context, 1 - b->role, b->wire + 16, 32))
            return pb_fail(b);
        if (wn_direct_attachment_proof(b->capability, b->scratch.derived.exported,
                                       b->scratch.derived.context, b->role, b->wire))
            return pb_fail(b);
        pb_state(b, PB_SEND_COMMIT, 32);
        break;
    case PB_RECV_COMMIT:
        if (wn_direct_attachment_verify(b->capability, b->scratch.derived.exported,
                                        b->scratch.derived.context, 1 - b->role, b->wire, 32))
            return pb_fail(b);
        b->commit_possible = 1;
        b->wire[0] = 1;
        pb_state(b, PB_SEND_READY, 1);
        break;
    case PB_RECV_READY:
        if (b->wire[0] != 1)
            return pb_fail(b);
        b->done = 1;
        pb_state(b, PB_DONE, 0);
        break;
    default:
        return pb_fail(b);
    }
    return 0;
}
