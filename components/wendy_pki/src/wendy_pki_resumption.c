#include "wendy_pki_internal.h"
#include "wendy_pki_resumption.h"
#include "wendy_pki_issuers.h"
#include "wendy_pki_session_store.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_certificate_policy.h"
#include "wendy_peer_identity.h"
#include "wendy_operator_auth.h"
#include "esp_timer.h"
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <stdio.h>
#if ESP_PLATFORM
#include "esp_log.h"
#define TICKET_LOG(...) ESP_LOGI("wendy_pki", __VA_ARGS__)
#else
#define TICKET_LOG(...) ((void)0)
#endif

#if !defined(ESP_PLATFORM) || CONFIG_WENDY_PKI_BLE_RESUMPTION

#define CARRIER_ALPN "wendy-local-mesh-ble/2"
#define TICKET_LIFETIME_US INT64_C(600000000)
#define TICKET_STATE_MAX 16384
/* Opaque Wendy handles are 32 bytes. Large stateless peer tickets must not
 * crowd issuer hints out of Lite's bounded ClientHello record. */
#define CLIENT_TICKET_MAX 256

/* Encoded state is private, RAM-only, and never goes on the wire. The opaque
 * 256-bit handle is useful only alongside TLS's proof of the resumption PSK. */
struct saved_session {
    struct wendy_pki_mesh_peer peer;
    int64_t authentication_deadline;
    uint32_t tls_size;
    uint16_t alpn_size;
    uint8_t alpn[255];
    uint8_t tls[];
};
struct pki_resumption {
    uint8_t scope[32];
    struct wendy_pki_mesh_peer peer;
    int64_t authentication_deadline;
    bool candidate, client_started;
    uint16_t alpn_size;
    uint8_t alpn[256];
    const char *protocols[14];
    size_t protocol_lengths[14];
};
static struct pki_session_store sessions = PKI_SESSION_STORE_INITIALIZER;
static pthread_mutex_t configuration_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t validation_time(const wendy_pki_connection *c)
{
    return c->mesh_certificate_policy
        ? wendy_pki_certificate_now(&c->certificate_time, esp_timer_get_time(), time(NULL))
        : time(NULL);
}
static bool valid_peer(const wendy_pki_connection *c, const struct wendy_pki_mesh_peer *p,
                        int64_t deadline)
{
    time_t now = validation_time(c);
    bool uncertain = c->mesh_certificate_policy &&
                      wendy_pki_certificate_is_uncertain(&c->certificate_time);
    return !wendy_pki_reset_in_progress() && now > 0 && c->device_expires > now &&
           deadline > esp_timer_get_time() && p->spki_size &&
           p->spki_size <= sizeof p->spki && p->device[36] == 0 &&
           wendy_identity_uuid((const unsigned char *)p->device, 36) &&
           strcmp(p->device, c->mesh_device) &&
           wendy_pki_certificate_dates(p->signing_not_before, p->expires, true, now, uncertain) &&
           p->issuer_not_before <= now;
}

/* Called only after TLS Finished has been verified. Reusing a ticket does not
 * run the library's certificate callback, so copied full-path time bounds must
 * be checked again under this connection's current clock policy. */
static int snapshot_peer(wendy_pki_connection *c)
{
    struct pki_resumption *r = c->resumption;
    if (c->authenticated_peer) {
        if (!valid_peer(c, c->authenticated_peer, c->session_deadline_us)) return -1;
        r->peer = *c->authenticated_peer;
        r->authentication_deadline = c->session_deadline_us;
        r->candidate = true;
        return 0;
    }
    if (c->ssl.MBEDTLS_PRIVATE(wendy_tls13_resumed))
        return r->candidate && valid_peer(c, &r->peer, r->authentication_deadline) ? 0 : -1;
    const mbedtls_x509_crt *leaf = mbedtls_ssl_get_peer_cert(&c->ssl);
    if (!leaf || mbedtls_ssl_get_verify_result(&c->ssl) ||
        wendy_pki_certificate_policy(leaf, false) ||
        wendy_peer_auth_role(leaf, c->mesh_tenant) != WENDY_PEER_ROLE_DEVICE ||
        !leaf->pk_raw.p || !leaf->pk_raw.len || leaf->pk_raw.len > sizeof r->peer.spki)
        return -1;
    char prefix[70];
    snprintf(prefix, sizeof prefix, "spiffe://wendy.sh/tenant/%s/device/", c->mesh_tenant);
    struct wendy_pki_mesh_peer peer = {
        .not_before = c->operator_not_before,
        .signing_not_before = c->operator_signing_not_before,
        .issuer_not_before = c->operator_issuer_not_before,
        .expires = c->operator_expires,
        .spki_size = leaf->pk_raw.len};
    unsigned count = 0;
    for (const mbedtls_x509_sequence *a = &leaf->subject_alt_names; a && a->buf.p; a = a->next) {
        mbedtls_x509_subject_alternative_name san;
        if (mbedtls_x509_parse_subject_alt_name(&a->buf, &san) ||
            san.type != MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER)
            continue;
        if (san.san.unstructured_name.len != 105 ||
            memcmp(san.san.unstructured_name.p, prefix, 69))
            return -1;
        memcpy(peer.device, san.san.unstructured_name.p + 69, 36);
        count++;
    }
    time_t now = validation_time(c);
    time_t expires = c->device_expires < peer.expires ? c->device_expires : peer.expires;
    int64_t mono = esp_timer_get_time();
    if (count != 1 || now <= 0 || expires <= now || mono < 0 ||
        (int64_t)(expires - now) > (INT64_MAX - mono) / INT64_C(1000000))
        return -1;
    int64_t deadline = mono + (int64_t)(expires - now) * INT64_C(1000000);
    if (c->session_deadline_us && c->session_deadline_us < deadline)
        deadline = c->session_deadline_us;
    memcpy(peer.spki, leaf->pk_raw.p, leaf->pk_raw.len);
    if (!valid_peer(c, &peer, deadline))
        return -1;
    r->peer = peer;
    r->authentication_deadline = deadline;
    r->candidate = true;
    return 0;
}

struct session_serialization {
    const struct pki_resumption *resumption;
    const mbedtls_ssl_session *session;
    const char *alpn;
    size_t alpn_size, tls_size;
};
static int serialize_session(void *context, void *bytes, size_t size)
{
    const struct session_serialization *input = context;
    struct saved_session *saved = bytes;
    if (size != sizeof *saved + input->tls_size ||
        !input->alpn_size || input->alpn_size > sizeof saved->alpn) return -1;
    saved->peer = input->resumption->peer;
    saved->authentication_deadline = input->resumption->authentication_deadline;
    saved->alpn_size = (uint16_t)input->alpn_size;
    memcpy(saved->alpn, input->alpn, input->alpn_size);
    saved->tls_size = (uint32_t)input->tls_size;
    size_t written = 0;
    int result = mbedtls_ssl_session_save(input->session, saved->tls, input->tls_size, &written);
    return result || written != input->tls_size ? -1 : 0;
}

static int write_ticket(void *context, const mbedtls_ssl_session *session,
                         unsigned char *start, const unsigned char *end,
                         size_t *size, uint32_t *lifetime)
{
    wendy_pki_connection *c = context;
    *size = 0;
    if (end < start || (size_t)(end - start) < 32 || !c->resumption ||
        psa_generate_random(start, 32) != PSA_SUCCESS)
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    *size = 32;
    *lifetime = 600;
    /* Cache pressure must not break a successfully authenticated connection.
     * An uncached random handle simply misses on the next connection. */
    size_t tls_size = 0;
    int result = mbedtls_ssl_session_save(session, NULL, 0, &tls_size);
    if (result != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL || !tls_size ||
        tls_size > TICKET_STATE_MAX - sizeof(struct saved_session) || snapshot_peer(c))
        return 0;
    size_t total = sizeof(struct saved_session) + tls_size;
    size_t alpn_size = c->ssl.MBEDTLS_PRIVATE(wendy_alpn_chosen_length);
    const char *alpn = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    if (!alpn || !alpn_size || alpn_size > 255) return 0;
    struct session_serialization input = {c->resumption, session, alpn, alpn_size, tls_size};
    int64_t now = esp_timer_get_time();
    int64_t expires = now <= INT64_MAX - TICKET_LIFETIME_US ? now + TICKET_LIFETIME_US : now;
    if (c->resumption->authentication_deadline < expires)
        expires = c->resumption->authentication_deadline;
    pthread_mutex_lock(&configuration_lock);
    (void)pki_session_store_write(&sessions, c->resumption->scope, start,
                                  total, now, expires, serialize_session, &input);
    pthread_mutex_unlock(&configuration_lock);
    return 0;
}
struct server_session_load {
    wendy_pki_connection *connection;
    mbedtls_ssl_session *session;
    const char *protocol;
    size_t protocol_size;
};
static int load_server_session(void *context, const void *bytes, size_t size)
{
    struct server_session_load *load = context;
    wendy_pki_connection *c = load->connection;
    const struct saved_session *saved = bytes;
    /* valid_peer reads connection-local policy, clock state and the reset
     * atomic; it neither acquires identity/configuration locks nor enters the cache. */
    if (size < sizeof *saved || saved->tls_size != size - sizeof *saved ||
        !saved->alpn_size || saved->alpn_size > sizeof saved->alpn ||
        saved->alpn_size != load->protocol_size ||
        memcmp(saved->alpn, load->protocol, saved->alpn_size) ||
        !valid_peer(c, &saved->peer, saved->authentication_deadline)) return -1;
    if (mbedtls_ssl_session_load(load->session, saved->tls, saved->tls_size)) return -1;
    c->resumption->peer = saved->peer;
    c->resumption->authentication_deadline = saved->authentication_deadline;
    c->resumption->alpn_size = saved->alpn_size;
    memcpy(c->resumption->alpn, saved->alpn, saved->alpn_size);
    return 0;
}
static int parse_ticket(void *context, mbedtls_ssl_session *session,
                         unsigned char *ticket, size_t ticket_size)
{
    wendy_pki_connection *c = context;
    const char *protocol = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    if (!c->resumption || ticket_size != 32 || !protocol || strcmp(protocol, CARRIER_ALPN) ||
        pki_issuer_recovery_active(&pki_issuer_process_recovery, esp_timer_get_time()))
        return MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
    /* Mbed TLS parses the PSK before calling our certificate/issuer selector.
     * Predict that selector's exact binary ALPN now, so a valid alias ticket
     * neither falsely misses against the temporary canonical choice nor
     * resumes under a different alias. The ordinary selector still runs. */
    size_t protocol_size = c->ssl.MBEDTLS_PRIVATE(wendy_alpn_chosen_length);
    bool leaf;
    size_t selected = pki_tls_server_issuer_alias(c, &leaf);
    if (selected) {
        protocol = c->issuers->hint;
        protocol_size = selected;
    }
    c->resumption->candidate = false;
    struct server_session_load load = {.connection=c, .session=session,
        .protocol=protocol, .protocol_size=protocol_size};
    pthread_mutex_lock(&configuration_lock);
    int found = pki_session_store_visit(&sessions, c->resumption->scope, ticket,
        esp_timer_get_time(), TICKET_STATE_MAX, load_server_session, &load);
    pthread_mutex_unlock(&configuration_lock);
    if (found != 1) return MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
    c->resumption->candidate = true;
    return 0;
}

void pki_resumption_prepare(wendy_pki_connection *c, const char *protocol)
{
    /* Only the device carrier protocol is eligible. The client supplies its
     * expected enrolled peer separately before its first handshake step. */
    if (!c || !c->stream.ble_carrier || c->resumption || !protocol || strcmp(protocol, CARRIER_ALPN) ||
        !c->allocation_scope.owner || !c->public_chain || !c->public_chain->count ||
        c->public_chain->count > 8 || !c->public_chain->load_trust)
        return;
    struct {
        uint8_t domain[32], roots[32], peer_issuers[32], chain[8][32];
        char tenant[37], device[37];
        uint64_t generation;
        uint8_t count;
    } binding = {0};
    bool server = c->config.MBEDTLS_PRIVATE(endpoint) == MBEDTLS_SSL_IS_SERVER;
    memcpy(binding.domain, server ? "wendy BLE device server tickets/1"
                                  : "wendy BLE device client tickets/1", 32);
    memcpy(binding.roots, c->public_chain->trust_hash, 32);
    if (c->lite_issuer_size &&
        wendy_pki_sha256(c->lite_issuer_der, c->lite_issuer_size, binding.peer_issuers))
        return;
    memcpy(binding.chain, c->public_chain->hashes, c->public_chain->count * 32);
    memcpy(binding.tenant, c->mesh_tenant, 37);
    memcpy(binding.device, c->mesh_device, 37);
    binding.generation = c->certificate_time.generation;
    binding.count = (uint8_t)c->public_chain->count;
    struct pki_resumption *r = pki_owned_calloc(1, sizeof *r);
    if (!r) {
        TICKET_LOG("BLE ticket cache unavailable: metadata allocation failed");
        return;
    }
    if (wendy_pki_sha256((const uint8_t *)&binding, sizeof binding, r->scope)) {
        pki_owned_free(r);
        return;
    }
    pthread_mutex_lock(&configuration_lock);
    if (sessions.owner != c->allocation_scope.owner) {
        pki_session_store_clear(&sessions);
        size_t limit = c->allocation_scope.placement == WENDY_NET_MEMORY_EXTERNAL ? 65536 : 16384;
        (void)pki_session_store_configure(&sessions, c->allocation_scope.owner,
                                          c->allocation_scope.placement, limit);
    }
    pthread_mutex_unlock(&configuration_lock);
    c->resumption = r;
    TICKET_LOG("BLE ticket cache ready: role=%s", server ? "server" : "client");
    mbedtls_ssl_conf_tls13_key_exchange_modes(&c->config,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL |
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
    if (server) {
        mbedtls_ssl_conf_session_tickets_cb(&c->config, write_ticket, parse_ticket, c);
        mbedtls_ssl_conf_new_session_tickets(&c->config, 1);
    } else {
        mbedtls_ssl_conf_session_tickets(&c->config, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
    }
}
void pki_resumption_before_step(wendy_pki_connection *c)
{
    if (!c->resumption || c->ssl.MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET)
        return;
    const char *chosen = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    /* Issuer-hint aliases share the canonical NUL-terminated application
     * prefix. Operator router and application protocols never qualify. */
    if (!chosen || strcmp(chosen, CARRIER_ALPN) || snapshot_peer(c))
        mbedtls_ssl_conf_new_session_tickets(&c->config, 0);
}
int pki_resumption_finish(wendy_pki_connection *c, const char *expected, const char *protocol)
{
    if (!c->ssl.MBEDTLS_PRIVATE(wendy_tls13_resumed))
        return 0;
    struct pki_resumption *r = c->resumption;
    const char *chosen = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    if (!r || !r->candidate || !protocol || strcmp(protocol, CARRIER_ALPN) ||
        !chosen || strcmp(chosen, CARRIER_ALPN) ||
        !r->alpn_size || r->alpn_size != c->ssl.MBEDTLS_PRIVATE(wendy_alpn_chosen_length) ||
        memcmp(r->alpn, chosen, r->alpn_size) ||
        (expected && strcmp(expected, r->peer.device)) ||
        !valid_peer(c, &r->peer, r->authentication_deadline))
        return -1;
    /* The verified resumption peer already has connection lifetime. Reuse it
     * instead of allocating a second maximum-size SPKI after Finished, when
     * the retained app window and handshake state are both still resident. */
    if (c->authenticated_peer && c->authenticated_peer != &r->peer)
        pki_owned_free(c->authenticated_peer);
    c->authenticated_peer = &r->peer;
    memcpy(c->mesh_peer, r->peer.device, 37);
    c->peer_role = WENDY_PEER_ROLE_DEVICE;
    c->operator_not_before = r->peer.not_before;
    c->operator_signing_not_before = r->peer.signing_not_before;
    c->operator_issuer_not_before = r->peer.issuer_not_before;
    c->operator_expires = r->peer.expires;
    c->session_deadline_us = r->authentication_deadline;
    if (pki_limit_session(c, validation_time(c), esp_timer_get_time()))
        return -1;
    return 1;
}
struct client_session_load {
    struct pki_resumption *resumption;
    mbedtls_ssl_session *session;
    const char *expected, *skip;
    size_t size;
    int tls_result;
};
/* Called with the cache lock held. Only decode and copy into owned objects:
 * identity policy and TLS installation happen after releasing the cache lock. */
static int load_client_session(void *context, const void *bytes, size_t size)
{
    struct client_session_load *load = context;
    const struct saved_session *saved = bytes;
    load->size = size;
    load->skip = "cached state invalid";
    if (size < sizeof *saved || saved->tls_size != size - sizeof *saved ||
        !saved->alpn_size || saved->alpn_size > sizeof saved->alpn ||
        saved->peer.device[36] || strcmp(load->expected, saved->peer.device)) return -1;
    load->skip = "TLS session load";
    load->tls_result = mbedtls_ssl_session_load(load->session, saved->tls, saved->tls_size);
    if (load->tls_result) return -1;
    struct pki_resumption *r = load->resumption;
    r->peer = saved->peer;
    r->authentication_deadline = saved->authentication_deadline;
    r->alpn_size = saved->alpn_size;
    memcpy(r->alpn, saved->alpn, saved->alpn_size);
    return 0;
}
void pki_resumption_client_start(wendy_pki_connection *c, const char *expected)
{
    struct pki_resumption *r = c->resumption;
    if (!r || r->client_started ||
        c->config.MBEDTLS_PRIVATE(endpoint) != MBEDTLS_SSL_IS_CLIENT) return;
    r->client_started = true;
    if (pki_issuer_recovery_active(&pki_issuer_process_recovery, esp_timer_get_time()))
        return;
    if (!expected || !wendy_identity_uuid((const unsigned char *)expected, strlen(expected))) {
        TICKET_LOG("BLE ticket not offered: expected peer UUID unavailable");
        return;
    }
    uint8_t key[32];
    if (wendy_pki_sha256((const uint8_t *)expected, 36, key)) return;
    mbedtls_ssl_session session;
    mbedtls_ssl_session_init(&session);
    struct client_session_load load = {.resumption=r, .session=&session,
        .expected=expected, .skip="cache miss or oversize"};
    pthread_mutex_lock(&configuration_lock);
    int found = pki_session_store_visit(&sessions, r->scope, key, esp_timer_get_time(),
        TICKET_STATE_MAX, load_client_session, &load);
    pthread_mutex_unlock(&configuration_lock);
    const char *skip = load.skip;
    int tls_result = load.tls_result;
    if (found != 1) goto done;
    skip = "cached authentication no longer valid";
    if (!valid_peer(c, &r->peer, r->authentication_deadline)) goto done;
    const char *const *offered = c->config.MBEDTLS_PRIVATE(alpn_list);
    const size_t *lengths = c->config.MBEDTLS_PRIVATE(wendy_alpn_lengths);
    bool present = false, canonical = false;
    unsigned offer_count = 0;
    for (unsigned i = 0; offered && offered[i]; i++) {
        if (++offer_count > 13) goto done;
        size_t n = lengths ? lengths[i] : strlen(offered[i]);
        if (n == strlen(CARRIER_ALPN) && !memcmp(offered[i], CARRIER_ALPN, n)) canonical = true;
        if (n == r->alpn_size && !memcmp(offered[i], r->alpn, n)) present = true;
    }
    /* An authenticated alias describes the server's possession of our own
     * issuer chain. The ticket scope binds that chain, trust, identity and
     * generation. Failure to allocate optional local issuer hints does not
     * invalidate this offer. Without those hints we advertise no cached CAs
     * and omit no client certificates if the server declines the PSK; ordinary
     * full-path verification still applies. Explicit issuer recovery retains
     * its canonical-only policy. */
    static const uint8_t alias_prefix[] = CARRIER_ALPN "\0WCI\1";
    bool restore_alias = !present && canonical && !c->issuers &&
        !pki_issuer_recovery_active(&pki_issuer_process_recovery, esp_timer_get_time()) &&
        r->alpn_size > sizeof alias_prefix - 1 &&
        r->alpn_size <= sizeof alias_prefix - 1 + PKI_ISSUER_CHAIN_MAX * 16 &&
        (r->alpn_size - (sizeof alias_prefix - 1)) % 16 == 0 &&
        !memcmp(r->alpn, alias_prefix, sizeof alias_prefix - 1);
    skip = "cached ALPN not offered";
    if (!present && !restore_alias) {
        TICKET_LOG("BLE ticket ALPN unavailable: cached_bytes=%u offers=%u issuers=%u chain=%u recovery=%u",
                   (unsigned)r->alpn_size, offer_count, (unsigned)(c->issuers != NULL),
                   c->issuers ? c->issuers->chain_count : 0,
                   (unsigned)pki_issuer_recovery_active(&pki_issuer_process_recovery,
                                                        esp_timer_get_time()));
        goto done;
    }
    skip = "TLS session install";
    tls_result = mbedtls_ssl_set_session(&c->ssl, &session);
    if (tls_result) goto done;
    /* Keep the previously negotiated binary alias stable as CA knowledge
     * warms. Keep the canonical
     * fallback and inventory hints, but not competing carrier aliases. */
    unsigned count = 0;
    if (restore_alias) {
        r->protocols[count] = (const char *)r->alpn;
        r->protocol_lengths[count++] = r->alpn_size;
    }
    for (unsigned i = 0; offered && offered[i]; i++) {
        size_t n = lengths ? lengths[i] : strlen(offered[i]);
        if (strcmp(offered[i], CARRIER_ALPN) || n == strlen(CARRIER_ALPN) ||
            (n == r->alpn_size && !memcmp(offered[i], r->alpn, n))) {
            if (count >= 13) goto done; /* bounded by issuer offer list */
            r->protocols[count] = offered[i];
            r->protocol_lengths[count++] = n;
        }
    }
    r->protocols[count] = NULL;
    c->config.MBEDTLS_PRIVATE(alpn_list) = r->protocols;
    c->config.MBEDTLS_PRIVATE(wendy_alpn_lengths) = r->protocol_lengths;
    r->candidate = true;
    TICKET_LOG("BLE ticket offered: bytes=%u peer=%s", (unsigned)session.MBEDTLS_PRIVATE(ticket_len), r->peer.device);
    skip = NULL;
done:
    if (skip) TICKET_LOG("BLE ticket not offered: reason=%s cache=%d state=%u tls=%d peer=%s",
                         skip, found, (unsigned)load.size, tls_result, expected);
    mbedtls_ssl_session_free(&session);
}

/* Called after the TLS library authenticates a post-handshake ticket. Ticket
 * receipt is not app data and must never surface as a failed application read. */
void pki_resumption_received_ticket(wendy_pki_connection *c)
{
    struct pki_resumption *r = c->resumption;
    if (!r || c->config.MBEDTLS_PRIVATE(endpoint) != MBEDTLS_SSL_IS_CLIENT ||
        !c->authenticated_peer || snapshot_peer(c)) return;
    mbedtls_ssl_session session;
    mbedtls_ssl_session_init(&session);
    size_t total = 0, tls_size = 0;
    uint8_t key[32];
    const char *alpn = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    size_t alpn_size = c->ssl.MBEDTLS_PRIVATE(wendy_alpn_chosen_length);
    if (!alpn || strcmp(alpn, CARRIER_ALPN) || !alpn_size || alpn_size > 255 ||
        wendy_pki_sha256((const uint8_t *)r->peer.device, 36, key) ||
        mbedtls_ssl_get_session(&c->ssl, &session) || !session.MBEDTLS_PRIVATE(ticket_len) ||
        session.MBEDTLS_PRIVATE(ticket_len) > CLIENT_TICKET_MAX ||
        !session.MBEDTLS_PRIVATE(ticket_lifetime) ||
        mbedtls_ssl_session_save(&session, NULL, 0, &tls_size) != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ||
        !tls_size || tls_size > TICKET_STATE_MAX - sizeof(struct saved_session)) goto done;
    total = sizeof(struct saved_session) + tls_size;
    struct session_serialization input = {r, &session, alpn, alpn_size, tls_size};
    uint32_t seconds = session.MBEDTLS_PRIVATE(ticket_lifetime);
    if (seconds > 600) seconds = 600;
    int64_t now = esp_timer_get_time(), duration = (int64_t)seconds * 1000000;
    int64_t expires = now <= INT64_MAX - duration ? now + duration : now;
    if (r->authentication_deadline < expires) expires = r->authentication_deadline;
    pthread_mutex_lock(&configuration_lock);
    int stored = pki_session_store_write(&sessions, r->scope, key, total, now, expires,
                                         serialize_session, &input);
    pthread_mutex_unlock(&configuration_lock);
    TICKET_LOG("BLE client ticket received: bytes=%u state=%u cached=%u peer=%s",
               (unsigned)session.MBEDTLS_PRIVATE(ticket_len), (unsigned)total,
               (unsigned)(stored == 0), r->peer.device);
    (void)stored;
done:
    mbedtls_ssl_session_free(&session);
}

bool pki_resumption_share_authenticated_peer(wendy_pki_connection *c,
                                             const struct wendy_pki_mesh_peer *peer)
{
    if (!c || !peer || !c->resumption ||
        (c->authenticated_peer && c->authenticated_peer != &c->resumption->peer))
        return false;
    c->resumption->peer = *peer;
    c->authenticated_peer = &c->resumption->peer;
    return true;
}

void pki_resumption_close(wendy_pki_connection *c)
{
    if (c->resumption) {
        if (c->authenticated_peer == &c->resumption->peer)
            c->authenticated_peer = NULL;
        mbedtls_platform_zeroize(c->resumption, sizeof *c->resumption);
        pki_owned_free(c->resumption);
        c->resumption = NULL;
    }
}
void pki_resumption_clear(void)
{
    pthread_mutex_lock(&configuration_lock);
    pki_session_store_clear(&sessions);
    sessions.owner = NULL;
    pthread_mutex_unlock(&configuration_lock);
}

void wendy_pki_net_forget_sessions(void)
{
    pki_resumption_clear();
}

#else
bool pki_resumption_share_authenticated_peer(wendy_pki_connection *c,
                                             const struct wendy_pki_mesh_peer *peer)
{ (void)c; (void)peer; return false; }
void pki_resumption_client_start(wendy_pki_connection *c, const char *peer) { (void)c; (void)peer; }
void pki_resumption_received_ticket(wendy_pki_connection *c) { (void)c; }
void pki_resumption_prepare(wendy_pki_connection *c, const char *protocol)
{ (void)c; (void)protocol; }
void pki_resumption_before_step(wendy_pki_connection *c) { (void)c; }
int pki_resumption_finish(wendy_pki_connection *c, const char *expected, const char *protocol)
{ (void)expected; (void)protocol; return c->ssl.MBEDTLS_PRIVATE(wendy_tls13_resumed) ? -1 : 0; }
void pki_resumption_close(wendy_pki_connection *c) { (void)c; }
void pki_resumption_clear(void) {}
void wendy_pki_net_forget_sessions(void) {}
#endif
