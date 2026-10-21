#include "wendy_mesh_directory.h"
#include "wendy_pki_crypto.h"
#include <mbedtls/base64.h>
#include <limits.h>
#include <string.h>

bool wm_identity_request_due(struct wm_identity_requests* requests,
    const uint8_t device[16], int64_t now_us)
{
    if (!requests || !device || now_us < 0 || now_us > INT64_MAX - INT64_C(5000000))
        return false;
    unsigned available = WENDY_MESH_ORIGINS_MAX;
    for (unsigned i = 0; i < WENDY_MESH_ORIGINS_MAX; i++)
    {
        if (!memcmp(requests->slots[i].device, device, 16))
        {
            if (requests->slots[i].retry_after_us > now_us)
                return false;
            available = i;
            break;
        }
        if (available == WENDY_MESH_ORIGINS_MAX && requests->slots[i].retry_after_us <= now_us)
            available = i;
    }
    if (available == WENDY_MESH_ORIGINS_MAX)
        return false;
    memcpy(requests->slots[available].device, device, 16);
    requests->slots[available].retry_after_us = now_us + INT64_C(5000000);
    return true;
}

int wm_directory_bind(
    struct wm_directory* d, struct wm_epoch* epoch, const struct wendy_pki_mesh_identity* identity)
{
    uint8_t uuid[16];
    if (!d || !epoch || !identity || wm_uuid_parse(identity->tenant, uuid)
        || wm_uuid_parse(identity->device, uuid) || identity->verified_seconds <= 0
        || identity->verified_seconds > (INT64_MAX - 125000) / 1000
        || identity->verified_monotonic_us < 0
        || identity->verified_monotonic_us > INT64_MAX - INT64_C(125000000))
        return -1;
    if (!epoch->bound || strcmp(epoch->tenant, identity->tenant)
        || strcmp(epoch->device, identity->device)
        || memcmp(epoch->trust_hash, identity->trust_hash, 32))
    {
        memset(d, 0, sizeof *d);
        memcpy(epoch->tenant, identity->tenant, sizeof epoch->tenant);
        memcpy(epoch->device, identity->device, sizeof epoch->device);
        memcpy(epoch->trust_hash, identity->trust_hash, 32);
        epoch->ready_after_us = identity->verified_monotonic_us + INT64_C(125000000);
        epoch->clock_unix_ms = (int64_t)identity->verified_seconds * 1000;
        epoch->clock_monotonic_us = identity->verified_monotonic_us;
        epoch->bound = true;
    }
    else
    {
        /* A delayed TSA reply must not move the proof clock backwards. A
         * forward correction can shorten existing leases, never extend them. */
        int64_t previous = wm_epoch_time(epoch, identity->verified_monotonic_us);
        if (previous <= 0)
            return -1;
        int64_t fresh = (int64_t)identity->verified_seconds * 1000;
        epoch->clock_unix_ms = fresh > previous ? fresh : previous;
        epoch->clock_monotonic_us = identity->verified_monotonic_us;
        for (unsigned i = 0; i < d->count; i++)
        {
            int64_t remaining = d->origins[i].expires_unix_ms - epoch->clock_unix_ms;
            if (remaining <= 0)
                d->origins[i].expires_us = 0;
            else if (remaining <= 120000)
            {
                int64_t deadline = identity->verified_monotonic_us + remaining * 1000;
                if (deadline < d->origins[i].expires_us)
                    d->origins[i].expires_us = deadline;
            }
        }
    }
    return 0;
}
bool wm_epoch_ready(const struct wm_epoch* epoch, int64_t now_us)
{
    return epoch && epoch->bound && now_us >= epoch->ready_after_us;
}
int64_t wm_epoch_time(const struct wm_epoch* epoch, int64_t now_us)
{
    if (!epoch || !epoch->bound || now_us < epoch->clock_monotonic_us)
        return 0;
    int64_t elapsed = (now_us - epoch->clock_monotonic_us) / 1000;
    return epoch->clock_unix_ms > INT64_MAX - elapsed ? 0 : epoch->clock_unix_ms + elapsed;
}

int wm_directory_add(struct wm_directory* d, const struct wendy_pki_mesh_peer* peer)
{
    uint8_t device[16];
    if (!d || !peer || wm_uuid_parse(peer->device, device) || !peer->spki_size
        || peer->spki_size > sizeof peer->spki)
        return -1;
    for (unsigned i = 0; i < d->count; i++)
        if (!memcmp(device, d->origins[i].device, 16))
        {
            /* A new certified key must not retain an old key's active proof. */
            if (peer->expires < d->origins[i].peer.expires
                || d->origins[i].peer.spki_size != peer->spki_size
                || memcmp(d->origins[i].peer.spki, peer->spki, peer->spki_size))
                d->origins[i].expires_us = 0;
            d->origins[i].peer = *peer;
            return 0;
        }
    if (d->count == WENDY_MESH_ORIGINS_MAX)
        return 1;
    struct wm_origin* o = &d->origins[d->count++];
    memset(o, 0, sizeof *o);
    o->peer = *peer;
    memcpy(o->device, device, 16);
    return 0;
}
int wm_directory_apply(struct wm_directory* d, const char* tenant, const struct wm_json* doc,
    unsigned envelope, int64_t now, int64_t now_us)
{
    static const char* const fields[] = { "principal", "body", "signature", NULL };
    char principal[106], signature64[113];
    uint8_t device[16], signature[80], hash[32];
    size_t sigsize = 0;
    struct wm_manifest m;
    int body = wm_json_member(doc, envelope, "body");
    if (!d || now <= 0 || now > INT64_MAX - 120000 || now_us < 0
        || now_us > INT64_MAX - INT64_C(120000000) || body < 0
        || !wm_json_fields(doc, envelope, fields) || wm_manifest_parse(doc, body, &m)
        || wm_json_string(
               doc, wm_json_member(doc, envelope, "principal"), principal, sizeof principal)
            < 0
        || wm_principal_device(principal, tenant, device) || memcmp(device, m.device, 16)
        || wm_json_string(
               doc, wm_json_member(doc, envelope, "signature"), signature64, sizeof signature64)
            < 0
        || mbedtls_base64_decode(signature, sizeof signature, &sigsize,
            (const unsigned char*)signature64, strlen(signature64))
        || m.issued > now + 5000)
        return -1;
    if (m.expires <= now)
        return 1;
    struct wm_origin* o = NULL;
    for (unsigned i = 0; i < d->count; i++)
        if (!memcmp(d->origins[i].device, device, 16))
        {
            o = &d->origins[i];
            break;
        }
    if (!o)
        return WM_DIRECTORY_IDENTITY_NEEDED;
    if (m.expires / 1000 > o->peer.expires
        || (m.expires / 1000 == o->peer.expires && m.expires % 1000))
        return -1;
    if (m.revision < o->revision)
        return 1;
    const struct wm_token* t = &doc->tokens[body];
    const char* raw = doc->text + t->start;
    size_t size = t->end - t->start;
    if (size > WENDY_MESH_MANIFEST_MAX
        || wendy_pki_mesh_verify(&o->peer, principal, raw, size, signature, sigsize)
        || wendy_pki_sha256((const uint8_t*)raw, size, hash))
        return -1;
    if (m.revision == o->revision)
        return memcmp(hash, o->body_hash, 32) ? -1 : 0;
    o->revision = m.revision;
    memcpy(o->body_hash, hash, 32);
    o->router_id = m.router_id;
    o->seqno = m.seqno;
    o->expires_unix_ms = m.expires;
    o->expires_us = m.withdraw ? 0 : now_us + (m.expires - now) * INT64_C(1000);
    return 0;
}
bool wm_directory_address(const struct wm_directory* d, const uint8_t address[16], int64_t now_us)
{
    if (!d || !address || now_us < 0)
        return false;
    uint8_t expected[16];
    unsigned owners = 0;
    for (unsigned i = 0; i < d->count; i++)
        if (d->origins[i].expires_us > now_us)
        {
            wm_address(d->origins[i].device, expected);
            if (!memcmp(expected, address, 16))
                owners++;
        }
    return owners == 1;
}

unsigned wm_directory_members(const struct wm_directory* d, int64_t now_us,
    struct wendy_mesh_member* members, unsigned capacity)
{
    if (!d || !members || now_us < 0) return 0;
    unsigned count = 0;
    for (unsigned i = 0; i < d->count && count < capacity; i++) {
        const struct wm_origin* origin = &d->origins[i];
        if (!origin->revision || origin->expires_us <= now_us) continue;
        uint8_t address[16];
        wm_address(origin->device, address);
        if (!wm_directory_address(d, address, now_us)) continue;
        wm_uuid_format(origin->device, members[count].device);
        int64_t remaining = (origin->expires_us - now_us - 1) / 1000000 + 1;
        members[count].lease_seconds = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
        count++;
    }
    return count;
}
