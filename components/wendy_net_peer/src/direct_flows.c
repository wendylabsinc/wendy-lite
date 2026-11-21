#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "wendy_net_direct_flows.h"
#include <mbedtls/private/sha256.h>
#include <string.h>
#include <unistd.h>

static bool packet_snapshot(const struct wn_direct_snapshot *s)
{
    return !(s->acked | s->offered | s->tail | s->remote_limit | s->consumed | s->received |
             s->limit | s->send_final | s->receive_final) &&
           !s->send_finished && !s->receive_finished;
}
int wn_direct_request_digest(struct wn_direct_request r, uint8_t out[32])
{
    if (!out)
        return WN_DIRECT_BOUNDS;
    memset(out, 0, 32);
    struct wn_direct_frame f = {.kind = WN_DIRECT_OPEN,
                                .attachment_id = 1,
                                .flow_id = 1,
                                .service = r.service,
                                .port = r.port,
                                .datagram_size = r.datagram_size};
    size_t n;
    if (wn_direct_frame_size(&f, &n))
        return WN_DIRECT_BOUNDS;
    uint8_t bytes[5] = {r.service, (uint8_t)(r.port >> 8), (uint8_t)r.port,
                        (uint8_t)(r.datagram_size >> 8), (uint8_t)r.datagram_size};
    static const uint8_t domain[] = "wendy/direct/open/1";
    mbedtls_sha256_context h;
    mbedtls_sha256_init(&h);
    int err = mbedtls_sha256_starts(&h, 0);
    if (!err)
        err = mbedtls_sha256_update(&h, domain, sizeof domain);
    if (!err)
        err = mbedtls_sha256_update(&h, bytes, sizeof bytes);
    if (!err)
        err = mbedtls_sha256_finish(&h, out);
    mbedtls_sha256_free(&h);
    if (err)
        memset(out, 0, 32);
    return err ? WN_DIRECT_BOUNDS : 0;
}
struct wn_direct_flow *wn_direct_flows_find(struct wn_direct_flows *m, uint32_t id)
{
    if (!m || !id)
        return NULL;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++)
        if (m->flows[i].id == id)
            return &m->flows[i];
    return NULL;
}
int wn_direct_flows_open(struct wn_direct_flows *m, uint32_t id, struct wn_direct_open_entry *out)
{
    if (!m || !out || !id)
        return WN_DIRECT_BOUNDS;
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f)
        return id <= m->opens[id & 1].high_water ? WN_DIRECT_RETIRED : WN_DIRECT_BOUNDS;
    *out = f->open;
    return 0;
}
static int complete_open(struct wn_direct_flows *m, uint32_t id, uint16_t result)
{
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f)
        return WN_DIRECT_RETIRED;
    if (f->open.complete && f->open.result != result)
        return WN_DIRECT_BOUNDS;
    f->open.complete = true;
    f->open.result = result;
    return 0;
}
static int close_open(struct wn_direct_flows *m, uint32_t id, bool remote, bool *retired)
{
    *retired = false;
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f) {
        *retired = id && id <= m->opens[id & 1].high_water;
        return *retired ? 0 : WN_DIRECT_BOUNDS;
    }
    if (!f->open.complete)
        return WN_DIRECT_BOUNDS;
    if (remote)
        f->open.remote_closed = true;
    else
        f->open.local_closed = true;
    *retired = f->open.local_closed && f->open.remote_closed;
    return 0;
}
static struct wn_direct_flow *unused(struct wn_direct_flows *m)
{
    for (size_t i = 0; i < (size_t)2 * m->slots; i++)
        if (!m->flows[i].id)
            return &m->flows[i];
    return NULL;
}
static void release(struct wn_direct_flow *f)
{
    f->binding = NULL;
    if (f->packet_io.close) {
        f->packet_io.close(f->packet_io.context);
        f->packet_io = (struct wn_direct_packet_io){0};
    }
    if (f->packet) {
        wn_direct_packet_close(f->packet);
        f->packet = NULL;
    }
    if (f->upper.close) {
        f->upper.close(f->upper.context);
        f->upper = (struct wn_direct_upper){0};
    }
    if (f->socket.fd >= 0) {
        close(f->socket.fd);
        f->socket.fd = -1;
    }
    if (f->has_lane) {
        wn_direct_close(&f->sender.buffer);
        wn_direct_close(&f->receiver.buffer);
        f->has_lane = false;
    }
}
/* The actor owns these buffers. Keep recycled chunks available for every
 * admitted receiver's progress floor; existing wire credit is never revoked. */
static bool can_reserve_receive(const struct wn_direct_flows *m, const struct wn_direct_flow *owner,
                                uint64_t bytes)
{
    uint64_t free = (uint64_t)m->rx->available * WN_DIRECT_CHUNK;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++) {
        const struct wn_direct_flow *f = &m->flows[i];
        if (f == owner || !f->has_lane || f->reset || f->promoted)
            continue;
        const struct wn_direct_receiver *r = &f->receiver;
        if (r->finished && r->buffer.end == r->final)
            continue;
        uint64_t held = r->buffer.limit - r->buffer.start / WN_DIRECT_CHUNK * WN_DIRECT_CHUNK;
        if (held < m->initial) {
            uint64_t deficit = m->initial - held;
            if (deficit > free)
                return false;
            free -= deficit;
        }
    }
    return bytes <= free;
}
static uint64_t transmit_available(const struct wn_direct_flows *m,
                                   const struct wn_direct_flow *owner)
{
    uint64_t free = (uint64_t)m->tx->available * WN_DIRECT_CHUNK;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++) {
        const struct wn_direct_flow *f = &m->flows[i];
        if (f == owner || !f->has_lane || f->reset || f->promoted || f->sender.finished)
            continue;
        const struct wn_direct_buffer *b = &f->sender.buffer;
        uint64_t held = b->limit - b->start / WN_DIRECT_CHUNK * WN_DIRECT_CHUNK;
        if (held < m->initial) {
            uint64_t deficit = m->initial - held;
            if (deficit > free)
                return 0;
            free -= deficit;
        }
    }
    return free;
}
uint64_t wn_direct_flows_send_capacity(const struct wn_direct_flows *m,
                                       const struct wn_direct_flow *f)
{
    if (!m || !f || !f->has_lane || f->reset || f->sender.finished)
        return 0;
    const struct wn_direct_buffer *b = &f->sender.buffer;
    uint64_t pending = b->end - b->start;
    if (pending >= m->window)
        return 0;
    uint64_t capacity = b->limit - b->end + transmit_available(m, f);
    return capacity < m->window - pending ? capacity : m->window - pending;
}
static int make_lane(struct wn_direct_flows *m, struct wn_direct_flow *f, int64_t now)
{
    if (f->request.service == WN_DIRECT_UDP) {
        if ((!m->datagram_limit || f->request.datagram_size > m->datagram_limit))
            return WN_DIRECT_BOUNDS;
        for (size_t i = 0; i < m->packet_count; i++)
            if (!m->packets[i].used && m->packets[i].capacity >= f->request.datagram_size) {
                int opened = wn_direct_packet_open(&m->packets[i], f->id, f->request.datagram_size,
                                                   m->packet_generation, m->alias);
                if (opened)
                    return opened;
                f->packet = &m->packets[i];
                return 0;
            }
        return WN_DIRECT_CAPACITY;
    }
    wn_direct_buffer_init(&f->sender.buffer, m->tx);
    wn_direct_buffer_init(&f->receiver.buffer, m->rx);
    /* A replayed OPEN after promotion needs no direct receive-credit grant. */
    if (!m->upper_control &&
        (!can_reserve_receive(m, f, m->initial) || transmit_available(m, f) < m->initial))
        return WN_DIRECT_CAPACITY;
    int err = m->upper_control ? 0 : wn_direct_reserve(&f->receiver.buffer, m->initial);
    if (err)
        return err;
    f->has_lane = true;
    if (wn_direct_lane_init(&f->lane, f->id, &f->sender, &f->receiver, now)) {
        release(f);
        return WN_DIRECT_BOUNDS;
    }
    return 0;
}
int wn_direct_flows_init(struct wn_direct_flows *m, uint8_t role, uint16_t slots,
                         struct wn_direct_flow *flows,
                         struct wn_direct_recovery_record *expected, uint32_t *retired,
                         struct wn_direct_pool *tx, struct wn_direct_pool *rx, uint64_t window,
                         uint64_t initial)
{
    if (!m || role > 1 || !slots || slots > 32767 || !flows || !expected || !retired ||
        !tx || !rx || !tx->slots || !rx->slots || !window || !initial || initial > window ||
        initial % WN_DIRECT_CHUNK || window % WN_DIRECT_CHUNK)
        return WN_DIRECT_BOUNDS;
    *m = (struct wn_direct_flows){.role = role,
                                  .slots = slots,
                                  .flows = flows,
                                  .expected = expected,
                                  .retired = retired,
                                  .tx = tx,
                                  .rx = rx,
                                  .window = window,
                                  .initial = initial,
                                  .next_id = 2 - role,
                                  .credit_pending = true};
    memset(flows, 0, (size_t)2 * slots * sizeof *flows);
    for (size_t i = 0; i < (size_t)2 * slots; i++)
        flows[i].socket.fd = -1;
    if (wn_direct_opens_init(&m->opens[0], slots, true) ||
        wn_direct_opens_init(&m->opens[1], slots, false))
        return WN_DIRECT_BOUNDS;
    return wn_direct_opens_grant(&m->opens[1 - role], slots);
}
int wn_direct_flows_enable_datagrams(struct wn_direct_flows *m, struct wn_direct_packet *packets,
                                     size_t count)
{
    if (!m || m->closed || m->alias || m->count || m->packets || m->packet_generation || !packets ||
        !count || count > (size_t)2 * m->slots)
        return WN_DIRECT_BOUNDS;
    for (size_t i = 0; i < count; i++)
        if ((!packets[i].storage && !packets[i].allocate) || !packets[i].capacity ||
            packets[i].used)
            return WN_DIRECT_BOUNDS;
    m->packets = packets;
    m->packet_count = count;
    return 0;
}
int wn_direct_flows_set_datagram_limit(struct wn_direct_flows *m, uint16_t maximum)
{
    if (!m || m->closed || m->alias || m->count || m->packet_generation ||
        (maximum && !m->packets))
        return WN_DIRECT_BOUNDS;
    m->datagram_limit = maximum;
    return 0;
}
int wn_direct_flows_bind(struct wn_direct_flows *m, uint32_t alias)
{
    if (!m || m->closed || m->upper_control || m->alias || !alias)
        return WN_DIRECT_BOUNDS;
    if (m->packet_generation == UINT64_MAX)
        return WN_DIRECT_BOUNDS;
    m->packet_generation++;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++)
        if (m->flows[i].packet &&
            wn_direct_packet_bind(m->flows[i].packet, m->packet_generation, alias))
            return WN_DIRECT_BOUNDS;
    m->alias = alias;
    m->credit_pending = true;
    m->datagram_limit_pending = true;
    m->peer_datagram_known = false;
    m->peer_datagram_limit = 0;
    return 0;
}
void wn_direct_flows_suspend(struct wn_direct_flows *m)
{
    if (m) {
        m->alias = 0;
        m->pending = (struct wn_direct_frame){0};
        m->pending_lane = false;
        for (size_t i = 0; i < (size_t)2 * m->slots; i++)
            if (m->flows[i].packet)
                wn_direct_packet_suspend(m->flows[i].packet);
    }
}
void wn_direct_flows_close(struct wn_direct_flows *m)
{
    if (!m)
        return;
    m->closed = true;
    wn_direct_flows_suspend(m);
    for (size_t i = 0; i < (size_t)2 * m->slots; i++)
        if (m->flows[i].id) {
            release(&m->flows[i]);
            m->flows[i].id = 0;
        }
    m->count = m->expected_count = m->retired_count = 0;
}
int wn_direct_flows_begin(struct wn_direct_flows *m, struct wn_direct_request r, int64_t now,
                          uint32_t *id)
{
    if (!id)
        return WN_DIRECT_BOUNDS;
    *id = 0;
    if (!m || !m->alias || m->closed || m->upper_control || !m->next_id || now < 0 ||
        (r.service == WN_DIRECT_UDP && !m->packets))
        return WN_DIRECT_BOUNDS;
    if (r.service == WN_DIRECT_UDP) {
        if (!m->peer_datagram_known)
            return WN_DIRECT_CAPACITY;
        if (!m->datagram_limit || !m->peer_datagram_limit)
            return WN_DIRECT_BOUNDS;
        if (r.datagram_size > m->datagram_limit)
            r.datagram_size = m->datagram_limit;
        if (r.datagram_size > m->peer_datagram_limit)
            r.datagram_size = m->peer_datagram_limit;
    }
    uint8_t digest[32];
    if (wn_direct_request_digest(r, digest))
        return WN_DIRECT_BOUNDS;
    struct wn_direct_flow *f = unused(m);
    if (!f)
        return WN_DIRECT_CAPACITY;
    *f = (struct wn_direct_flow){.id = m->next_id, .request = r, .socket = {.fd = -1}};
    int err = make_lane(m, f, now);
    if (!err)
        err = wn_direct_opens_admit(&m->opens[m->role], f->id);
    if (err) {
        release(f);
        f->id = 0;
        return err;
    }
    memcpy(f->open.digest, digest, 32);
    *id = f->id;
    m->next_id = m->next_id > UINT32_MAX - 2 ? 0 : m->next_id + 2;
    m->count++;
    f->open_pending = true;
    return 0;
}
int wn_direct_flows_complete(struct wn_direct_flows *m, uint32_t id, uint16_t result)
{
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f || m->closed || (id & 1) == m->role)
        return WN_DIRECT_BOUNDS;
    if (f->reset)
        return WN_DIRECT_RETIRED;
    if (!result && !f->has_lane && !f->packet)
        return WN_DIRECT_CAPACITY;
    int err = complete_open(m, id, result);
    if (err)
        return err;
    f->result_pending = true;
    if (result) {
        release(f);
        f->close_pending = true;
    }
    return 0;
}
int wn_direct_flows_socket(struct wn_direct_flows *m, uint32_t id, int fd)
{
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    struct wn_direct_open_entry e;
    if (!f || m->closed || f->reset || (!f->has_lane && !f->packet) || f->packet_io.read ||
        f->socket.fd >= 0 || wn_direct_flows_open(m, id, &e) || !e.complete ||
        e.result)
        return WN_DIRECT_BOUNDS;
    return wn_direct_socket_init(&f->socket, fd);
}
static void reset_flow(struct wn_direct_flows *m, struct wn_direct_flow *f, uint16_t code,
                       bool send)
{
    if (!f->reset) {
        f->reset = true;
        f->reset_code = code;
        release(f);
    }
    f->reset_pending |= send;
    f->close_pending = true;
    struct wn_direct_open_entry e;
    if (!wn_direct_flows_open(m, f->id, &e) && !e.complete &&
        (f->id & 1) != m->role) {
        (void)complete_open(m, f->id, WN_DIRECT_CANCELLED);
        f->result_pending = true;
    }
}
int wn_direct_flows_reset(struct wn_direct_flows *m, uint32_t id, uint16_t code)
{
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f || m->closed || !code)
        return WN_DIRECT_BOUNDS;
    reset_flow(m, f, code, true);
    return 0;
}
static void retire_flow(struct wn_direct_flows *m, struct wn_direct_flow *f)
{
    release(f);
    m->opens[f->id & 1].free++;
    f->id = 0;
    m->count--;
    struct wn_direct_opens *r = &m->opens[1 - m->role];
    if (r->admitted <= UINT64_MAX - r->free && !wn_direct_opens_grant(r, r->admitted + r->free))
        m->credit_pending = !m->upper_control;
}
static bool upper_again(int n)
{
    return n == -2 || n == -3;
}
static uint8_t upper_wait(int n)
{
    return n == -2 ? 1 : n == -3 ? 2 : 0;
}
static int upper_poll(struct wn_direct_flows *m, struct wn_direct_flow *f)
{
    int progress = 0;
    size_t n = 0;
    struct wn_direct_buffer *tx = &f->sender.buffer, *rx = &f->receiver.buffer;
    size_t capacity = f->upper_pending ? f->upper_pending : WN_DIRECT_CHUNK;
    if (wn_direct_copy(tx, tx->start, m->scratch, capacity, &n))
        return -1;
    if (n) {
        /* TLS WANT retries retain the exact chunk length/content, even if the local
         * app appends more data before the next actor turn. Shared scratch has one
         * stable address and is repopulated before each serialized TLS call. */
        f->upper_pending = n;
        int wrote = f->upper.write(f->upper.context, m->scratch, n);
        f->upper_write_wait = upper_wait(wrote);
        if (wrote > 0) {
            if ((size_t)wrote > n || wn_direct_release(tx, tx->start + (uint64_t)wrote))
                return -1;
            f->upper_pending = 0;
            progress = 1;
        } else if (!upper_again(wrote))
            return -1;
    } else if (f->sender.finished && !f->upper_write_closed) {
        int r = f->upper.shutdown_write(f->upper.context);
        f->upper_write_wait = upper_wait(r);
        if (!r) {
            f->upper_write_closed = true;
            progress = 1;
        } else if (!upper_again(r))
            return -1;
    }
    /* Descriptorless BIO adapters explicitly report buffered input. Once a
     * read wants input, do not reserve another chunk until input/EOF arrives.
     * Adapters with a real fd still need read() to discover socket readiness. */
    bool idle = f->upper_read_wait == 1 && f->upper.pending &&
                !f->upper.pending(f->upper.context) &&
                (!f->upper.fd || f->upper.fd(f->upper.context) < 0);
    /* Reconciliation may establish FIN before its retained suffix arrives.
     * Keep reading that suffix on the upper stream until the final offset. */
    if ((!f->receiver.finished || rx->end < f->receiver.final) && !idle) {
        uint64_t pending = rx->end - rx->start;
        if (pending < m->window) {
            size_t room = (size_t)(m->window - pending);
            if (room > WN_DIRECT_CHUNK)
                room = WN_DIRECT_CHUNK;
            if (rx->end > UINT64_MAX - room)
                return -1;
            int reserved = wn_direct_reserve(rx, rx->end + room);
            if (reserved && reserved != WN_DIRECT_CAPACITY)
                return -1;
            if (!reserved) {
                int got = f->upper.read(f->upper.context, m->scratch, room);
                f->upper_read_wait = upper_wait(got);
                if (got > 0) {
                    if ((size_t)got > room ||
                        wn_direct_receive(&f->receiver, m->scratch, (size_t)got))
                        return -1;
                    progress = 1;
                } else if (!got) {
                    if (wn_direct_receive_finish(&f->receiver, rx->end))
                        return -1;
                    progress = 1;
                } else if (!upper_again(got))
                    return -1;
            }
        }
    }
    /* Promoted streams use TLS flow control; their unused local RX storage is
     * no longer a BLE receive-credit promise. Preserve all retained bytes. */
    if (wn_direct_trim(rx) || wn_direct_trim(tx))
        return -1;
    if (f->upper_write_closed && f->receiver.finished && rx->start == rx->end) {
        struct wn_direct_open_entry e;
        if (wn_direct_flows_open(m, f->id, &e))
            return -1;
        if (!e.local_closed)
            f->close_pending = true;
    }
    return progress;
}
int wn_direct_flows_poll(struct wn_direct_flows *m)
{
    if (!m || m->closed)
        return WN_DIRECT_BOUNDS;
    int progress = 0;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++) {
        struct wn_direct_flow *f = &m->flows[i];
        if (!f->id || f->reset)
            continue;
        if (f->packet) {
            int local = f->packet_io.read   ? wn_direct_packet_poll_io(f->packet, &f->packet_io)
                        : f->socket.fd >= 0 ? wn_direct_packet_poll(f->packet, &f->socket)
                                            : 0;
            int upper = f->promoted ? wn_direct_packet_upper_poll(f->packet, &f->upper) : 0;
            if (local < 0 || upper < 0) {
                reset_flow(m, f, WN_DIRECT_IO, true);
                progress = 1;
            } else if (local || upper)
                progress = 1;
            continue;
        }
        if (!f->has_lane)
            continue;
        int rd = 0, wr = 0;
        if (f->socket.fd >= 0) {
            uint64_t pending = f->sender.buffer.end - f->sender.buffer.start;
            rd = wn_direct_socket_read(&f->socket, &f->sender,
                                       pending + wn_direct_flows_send_capacity(m, f));
            wr = wn_direct_socket_write(&f->socket, &f->receiver);
        }
        int upper = f->promoted ? upper_poll(m, f) : 0;
        if (rd < 0 || wr < 0 || upper < 0) {
            reset_flow(m, f, WN_DIRECT_IO, true);
            progress = 1;
        } else if (rd || wr || upper)
            progress = 1;
    }
    return progress;
}
int wn_direct_flows_receive(struct wn_direct_flows *m, const struct wn_direct_frame *in,
                            int64_t now, uint32_t *fresh_id)
{
    if (!fresh_id)
        return WN_DIRECT_BOUNDS;
    *fresh_id = 0;
    size_t size;
    if (!m || m->closed || !m->alias || !in || in->attachment_id != m->alias || now < 0 ||
        wn_direct_frame_size(in, &size))
        return WN_DIRECT_BOUNDS;
    if (m->upper_control && (in->kind == WN_DIRECT_DATA || in->kind == WN_DIRECT_STATE ||
                             in->kind == WN_DIRECT_FIN || in->kind == WN_DIRECT_DATAGRAM))
        return WN_DIRECT_BOUNDS;
    uint32_t id = in->flow_id;
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    struct wn_direct_open_entry e;
    switch (in->kind) {
    case WN_DIRECT_EPOCH_IDLE:
        if (!m->upper_control)
            return WN_DIRECT_BOUNDS;
        m->peer_idle = true;
        return 0;
    case WN_DIRECT_DATAGRAM_LIMIT:
        if (m->upper_control ||
            (m->peer_datagram_known && m->peer_datagram_limit != in->datagram_size))
            return WN_DIRECT_BOUNDS;
        m->peer_datagram_known = true;
        m->peer_datagram_limit = in->datagram_size;
        return 0;
    case WN_DIRECT_OPEN_CREDIT:
        return wn_direct_opens_peer_grant(&m->opens[m->role], in->value);
    case WN_DIRECT_OPEN: {
        if ((id & 1) == m->role)
            return WN_DIRECT_BOUNDS;
        struct wn_direct_request r = {in->service, in->port, in->datagram_size};
        uint8_t digest[32];
        if (wn_direct_request_digest(r, digest))
            return WN_DIRECT_BOUNDS;
        for (unsigned i = 0; i < m->expected_count; i++)
            if (m->expected[i].id == id) {
                if (memcmp(m->expected[i].open_digest, digest, 32) ||
                    (r.service == WN_DIRECT_UDP && !packet_snapshot(&m->expected[i].flow)))
                    return WN_DIRECT_BOUNDS;
            }
        if (m->upper_control && !f) {
            bool expected = false;
            for (unsigned i = 0; i < m->expected_count; i++)
                if (m->expected[i].id == id)
                    expected = true;
            if (!expected)
                return WN_DIRECT_BOUNDS;
        }
        if (f) {
            if (memcmp(f->open.digest, digest, 32))
                return WN_DIRECT_BOUNDS;
            f->result_pending |= f->open.complete;
            return 0;
        }
        f = unused(m);
        if (!f)
            return WN_DIRECT_CAPACITY;
        int err = wn_direct_opens_admit(&m->opens[id & 1], id);
        if (err)
            return err;
        *f = (struct wn_direct_flow){.id = id, .request = r, .socket = {.fd = -1}};
        memcpy(f->open.digest, digest, 32);
        m->count++;
        for (unsigned i = 0; i < m->expected_count; i++)
            if (m->expected[i].id == id) {
                struct wn_direct_recovery_record replay = m->expected[i];
                if (memcmp(replay.open_digest, digest, 32))
                    return WN_DIRECT_BOUNDS;
                m->expected[i] = m->expected[--m->expected_count];
                if (replay.reset) {
                    reset_flow(m, f, replay.reset_code, false);
                    return 0;
                }
                break;
            }
        uint16_t code = WN_DIRECT_NO_CAPACITY;
        if (r.service == WN_DIRECT_UDP && !m->packets)
            code = WN_DIRECT_UNSUPPORTED;
        else if (!make_lane(m, f, now)) {
            *fresh_id = id;
            return 0;
        }
        return wn_direct_flows_complete(m, id, code);
    }
    case WN_DIRECT_STATE:
        for (unsigned i = 0; i < in->state_count; i++) {
            struct wn_direct_state_entry state = in->states[i];
            f = wn_direct_flows_find(m, state.flow_id);
            if (!f || wn_direct_flows_open(m, state.flow_id, &e))
                return WN_DIRECT_BOUNDS;
            if (f->reset)
                continue;
            if (!e.complete || e.result || !f->has_lane || wn_direct_lane_state(&f->lane, state))
                return WN_DIRECT_BOUNDS;
        }
        return 0;
    case WN_DIRECT_CLOSE_ACK: {
        bool retired = false;
        int err = close_open(m, id, true, &retired);
        if (!err && retired && f)
            retire_flow(m, f);
        return err;
    }
    default:
        break;
    }
    if (!f || wn_direct_flows_open(m, id, &e))
        return WN_DIRECT_BOUNDS;
    switch (in->kind) {
    case WN_DIRECT_OPEN_RESULT: {
        if ((id & 1) != m->role)
            return WN_DIRECT_BOUNDS;
        int err = complete_open(m, id, in->code);
        if (err)
            return err;
        if (in->code) {
            release(f);
            f->close_pending = true;
        }
        return 0;
    }
    case WN_DIRECT_RESET:
        reset_flow(m, f, in->code, false);
        return 0;
    case WN_DIRECT_DATAGRAM:
        if (f->reset)
            return 0;
        if (!e.complete || e.result || !f->packet)
            return WN_DIRECT_BOUNDS;
        return wn_direct_packet_receive(f->packet, m->packet_generation, in) ? WN_DIRECT_BOUNDS : 0;
    case WN_DIRECT_DATA:
    case WN_DIRECT_FIN:
        if (f->reset)
            return 0;
        if (!e.complete || e.result || !f->has_lane)
            return WN_DIRECT_BOUNDS;
        return wn_direct_lane_receive(&f->lane, in, now);
    default:
        return WN_DIRECT_BOUNDS;
    }
}
static int output(struct wn_direct_flows *m, struct wn_direct_frame f, struct wn_direct_frame *out)
{
    m->pending = f;
    *out = f;
    return 1;
}
int wn_direct_flows_prepare(struct wn_direct_flows *m, int64_t now, struct wn_direct_frame *out)
{
    if (!m || !out || m->closed || !m->alias || now < 0)
        return WN_DIRECT_BOUNDS;
    *out = (struct wn_direct_frame){0};
    if (m->pending.kind) {
        *out = m->pending;
        return 1;
    }
    struct wn_direct_frame frame = {.attachment_id = m->alias};
    if (m->upper_control && !m->idle_sent && wn_direct_flows_quiescent(m)) {
        frame.kind = WN_DIRECT_EPOCH_IDLE;
        return output(m, frame, out);
    }
    if (m->datagram_limit_pending) {
        frame.kind = WN_DIRECT_DATAGRAM_LIMIT;
        frame.datagram_size = m->datagram_limit;
        return output(m, frame, out);
    }
    if (m->credit_pending) {
        frame.kind = WN_DIRECT_OPEN_CREDIT;
        frame.value = m->opens[1 - m->role].grant;
        return output(m, frame, out);
    }
    if (m->retired_count) {
        frame.kind = WN_DIRECT_CLOSE_ACK;
        frame.flow_id = m->retired[0];
        return output(m, frame, out);
    }
    // Ascending OPEN order is independent of the fair payload cursor.
    struct wn_direct_flow *opening = NULL;
    for (size_t i = 0; i < (size_t)2 * m->slots; i++)
        if (m->flows[i].id && m->flows[i].open_pending &&
            (!opening || m->flows[i].id < opening->id))
            opening = &m->flows[i];
    if (opening) {
        frame.kind = WN_DIRECT_OPEN;
        frame.flow_id = opening->id;
        frame.service = opening->request.service;
        frame.port = opening->request.port;
        frame.datagram_size = opening->request.datagram_size;
        return output(m, frame, out);
    }
    // Fixed slots provide round-robin scheduling without allocating/sorting IDs.
    for (size_t scan = 0; scan < (size_t)2 * m->slots; scan++) {
        size_t index = (m->cursor + scan) % ((size_t)2 * m->slots);
        struct wn_direct_flow *f = &m->flows[index];
        struct wn_direct_open_entry e;
        if (!f->id)
            continue;
        if (wn_direct_flows_open(m, f->id, &e))
            return WN_DIRECT_BOUNDS;
        // An idle lane clears its output. Start each candidate with a fresh envelope
        // so a later control frame retains the current attachment identity.
        frame = (struct wn_direct_frame){.attachment_id = m->alias, .flow_id = f->id};
        if (f->result_pending) {
            frame.kind = WN_DIRECT_OPEN_RESULT;
            frame.code = e.result;
        } else if (f->reset_pending) {
            frame.kind = WN_DIRECT_RESET;
            frame.code = f->reset_code;
        } else if (f->close_pending && e.complete)
            frame.kind = WN_DIRECT_CLOSE_ACK;
        else {
            if (m->upper_control || !e.complete || e.result || f->reset ||
                (!f->has_lane && !f->packet) || e.local_closed)
                continue;
            if (f->packet) {
                int ready = wn_direct_datagram_prepare(&f->packet->tx, &frame);
                if (ready < 0)
                    return WN_DIRECT_BOUNDS;
                if (!ready)
                    continue;
                return output(m, frame, out);
            }
            struct wn_direct_snapshot snap = wn_direct_snapshot(&f->sender, &f->receiver);
            if (snap.send_finished && snap.receive_finished && snap.acked == snap.send_final &&
                snap.consumed == snap.receive_final && f->lane.fin_ack && !f->lane.ack.pending) {
                f->close_pending = true;
                frame.kind = WN_DIRECT_CLOSE_ACK;
            } else {
                if ((!snap.receive_finished || snap.received < snap.receive_final) &&
                    snap.received && snap.limit - snap.received <= m->window / 2) {
                    if (snap.consumed > UINT64_MAX - m->window)
                        return WN_DIRECT_BOUNDS;
                    /* The small admission minimum is not the busy receive-window target. */
                    uint64_t aim = snap.consumed + m->window;
                    if (snap.receive_finished && aim > snap.receive_final)
                        aim = snap.receive_final;
                    if (aim > snap.limit) {
                        uint64_t limit =
                            aim - snap.limit > WN_DIRECT_CHUNK ? snap.limit + WN_DIRECT_CHUNK : aim;
                        if (limit <= UINT64_MAX - (WN_DIRECT_CHUNK - 1) &&
                            can_reserve_receive(m, f,
                                                (limit + WN_DIRECT_CHUNK - 1) / WN_DIRECT_CHUNK *
                                                        WN_DIRECT_CHUNK -
                                                    f->receiver.buffer.limit))
                            (void)wn_direct_lane_grant(&f->lane, limit, now);
                    }
                }
                int ready = wn_direct_lane_prepare(&f->lane, m->alias, now, m->scratch,
                                                   sizeof m->scratch, &frame);
                if (ready < 0)
                    return ready;
                if (!ready)
                    continue;
                m->pending_lane = true;
            }
        }
        return output(m, frame, out);
    }
    return 0;
}
int wn_direct_flows_accepted(struct wn_direct_flows *m)
{
    if (!m || !m->pending.kind)
        return WN_DIRECT_BOUNDS;
    struct wn_direct_frame p = m->pending;
    m->pending = (struct wn_direct_frame){0};
    if (p.kind == WN_DIRECT_EPOCH_IDLE) {
        m->idle_sent = true;
        return 0;
    }
    if (p.kind == WN_DIRECT_DATAGRAM_LIMIT) {
        m->datagram_limit_pending = false;
        return 0;
    }
    if (p.kind == WN_DIRECT_OPEN_CREDIT) {
        m->credit_pending = m->opens[1 - m->role].grant != p.value;
        return 0;
    }
    for (unsigned i = 0; i < m->retired_count; i++)
        if (m->retired[i] == p.flow_id) {
            m->retired[i] = m->retired[--m->retired_count];
            return 0;
        }
    uint32_t id = m->pending_lane && p.kind == WN_DIRECT_STATE ? p.states[0].flow_id : p.flow_id;
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    if (!f) {
        struct wn_direct_open_entry e;
        return wn_direct_flows_open(m, id, &e) == WN_DIRECT_RETIRED
                   ? 0
                   : WN_DIRECT_BOUNDS;
    }
    m->cursor = (uint32_t)(f - m->flows + 1) % ((uint32_t)2 * m->slots);
    if (m->pending_lane) {
        m->pending_lane = false;
        return wn_direct_lane_accepted(&f->lane);
    }
    switch (p.kind) {
    case WN_DIRECT_DATAGRAM:
        if (f->reset)
            return 0;
        return !f->packet || wn_direct_datagram_accepted(&f->packet->tx, m->packet_generation,
                                                         p.value, p.fragment_offset)
                   ? WN_DIRECT_BOUNDS
                   : 0;
    case WN_DIRECT_OPEN:
        f->open_pending = false;
        return 0;
    case WN_DIRECT_OPEN_RESULT:
        f->result_pending = false;
        return 0;
    case WN_DIRECT_RESET:
        f->reset_pending = false;
        return 0;
    case WN_DIRECT_CLOSE_ACK: {
        bool retired;
        f->close_pending = false;
        int err = close_open(m, id, false, &retired);
        if (!err && retired)
            retire_flow(m, f);
        return err;
    }
    default:
        return WN_DIRECT_BOUNDS;
    }
}
int wn_direct_flows_snapshot(struct wn_direct_flows *m, struct wn_direct_recovery_record *records,
                             size_t capacity, struct wn_direct_recovery_view *out)
{
    if (!m || m->closed || m->upper_control || !out || !records || capacity < m->count)
        return WN_DIRECT_BOUNDS;
    *out = (struct wn_direct_recovery_view){.records = records, .count = m->count};
    for (unsigned i = 0; i < 2; i++)
        out->namespaces[i] = (struct wn_direct_namespace_checkpoint){
            m->opens[i].high_water, m->opens[i].admitted, m->opens[i].grant};
    uint32_t after = 0;
    for (unsigned n = 0; n < m->count; n++) {
        struct wn_direct_flow *f = NULL;
        for (size_t i = 0; i < (size_t)2 * m->slots; i++)
            if (m->flows[i].id > after && (!f || m->flows[i].id < f->id))
                f = &m->flows[i];
        if (!f)
            return WN_DIRECT_BOUNDS;
        struct wn_direct_open_entry e;
        if (wn_direct_flows_open(m, f->id, &e))
            return WN_DIRECT_BOUNDS;
        struct wn_direct_recovery_record *r = &records[n];
        *r = (struct wn_direct_recovery_record){.id = f->id,
                                                .result = e.result,
                                                .open_complete = e.complete,
                                                .local_closed = e.local_closed,
                                                .remote_closed = e.remote_closed,
                                                .reset = f->reset,
                                                .reset_code = f->reset_code};
        memcpy(r->open_digest, e.digest, 32);
        if (!f->reset && (!e.complete || !e.result) && f->has_lane)
            r->flow = wn_direct_snapshot(&f->sender, &f->receiver);
        after = f->id;
    }
    return wn_direct_recovery_view_valid(out) ? 0 : WN_DIRECT_BOUNDS;
}
static const struct wn_direct_recovery_record *record(const struct wn_direct_recovery_view *v,
                                                      uint32_t id)
{
    for (size_t i = 0; i < v->count; i++)
        if (v->records[i].id == id)
            return &v->records[i];
    return NULL;
}
int wn_direct_flows_recover(struct wn_direct_flows *m, const struct wn_direct_recovery_view *remote,
                            int64_t now, struct wn_direct_recovery_record *local,
                            size_t local_capacity, struct wn_direct_recovery_step *plan,
                            size_t plan_capacity)
{
    if (!m || m->closed || m->alias || !remote || (remote->count && !remote->records) || now < 0 ||
        remote->count > (size_t)2 * m->slots)
        return WN_DIRECT_BOUNDS;
    for (size_t i = 0; i < remote->count; i++) {
        struct wn_direct_flow *f = wn_direct_flows_find(m, remote->records[i].id);
        if (f && f->request.service == WN_DIRECT_UDP && !packet_snapshot(&remote->records[i].flow))
            return WN_DIRECT_BOUNDS;
    }
    struct wn_direct_recovery_view view;
    size_t count;
    if (wn_direct_flows_snapshot(m, local, local_capacity, &view) ||
        wn_direct_recovery_plan(&view, remote, m->role, plan, plan_capacity, &count))
        return WN_DIRECT_BOUNDS;
    m->expected_count = m->retired_count = 0;
    for (size_t i = 0; i < count; i++) {
        struct wn_direct_recovery_step *step = &plan[i];
        const struct wn_direct_recovery_record *r = record(remote, step->id);
        if (step->action == WN_DIRECT_RECEIVE_OPEN) {
            if (!r || m->expected_count >= (uint32_t)2 * m->slots)
                goto fail;
            m->expected[m->expected_count++] = *r;
            continue;
        }
        if (step->action == WN_DIRECT_CONFIRM_RETIRED) {
            if (m->retired_count >= (uint32_t)2 * m->slots)
                goto fail;
            m->retired[m->retired_count++] = step->id;
            continue;
        }
        struct wn_direct_flow *f = wn_direct_flows_find(m, step->id);
        struct wn_direct_open_entry e;
        if (!f || wn_direct_flows_open(m, step->id, &e))
            goto fail;
        f->open_pending = f->result_pending = f->reset_pending = false;
        f->close_pending = e.local_closed || f->reset || (e.complete && e.result);
        switch (step->action) {
        case WN_DIRECT_RETIRE: {
            bool retired;
            if (close_open(m, step->id, true, &retired) ||
                !retired)
                goto fail;
            retire_flow(m, f);
            break;
        }
        case WN_DIRECT_REPLAY_OPEN:
            f->open_pending = true;
            f->reset_pending = f->reset;
            break;
        case WN_DIRECT_RESUME:
        case WN_DIRECT_RESET_FLOW:
            if (step->open_complete &&
                complete_open(m, step->id, step->result))
                goto fail;
            if (step->action == WN_DIRECT_RESET_FLOW) {
                reset_flow(m, f, step->reset_code, true);
                break;
            }
            if (step->open_complete && step->result) {
                f->close_pending = true;
                release(f);
            } else if (f->has_lane && (!r || wn_direct_lane_reattach(&f->lane, &r->flow, now)))
                goto fail;
            if ((step->id & 1) != m->role && step->open_complete && r && !r->open_complete)
                f->result_pending = true;
            break;
        default:
            goto fail;
        }
    }
    if (wn_direct_opens_peer_grant(&m->opens[m->role], remote->namespaces[m->role].grant))
        goto fail;
    m->credit_pending = true;
    return 0;
fail:
    wn_direct_flows_close(m);
    return WN_DIRECT_BOUNDS;
}
bool wn_direct_flows_quiescent(const struct wn_direct_flows *m)
{
    return m && !m->count && !m->expected_count && !m->retired_count && !m->pending.kind &&
           !m->datagram_limit_pending;
}

int wn_direct_flows_bind_promoted(struct wn_direct_flows *m, uint32_t alias)
{
    if (!m || m->closed || m->upper_control || m->alias || !alias)
        return WN_DIRECT_BOUNDS;
    /* The authenticated control attachment commits an irreversible promotion:
     * direct DATA is now forbidden. Keep all payload, but release unused grants
     * before per-flow TLS handshakes need their peak memory. */
    for (size_t i = 0; i < (size_t)2 * m->slots; i++) {
        struct wn_direct_flow *f = &m->flows[i];
        if (f->has_lane &&
            (wn_direct_trim(&f->sender.buffer) || wn_direct_trim(&f->receiver.buffer)))
            return WN_DIRECT_BOUNDS;
    }
    m->alias = alias;
    m->upper_control = true;
    m->credit_pending = false;
    m->datagram_limit_pending = false;
    return 0;
}
int wn_direct_flows_promote(struct wn_direct_flows *m, uint32_t id,
                            const struct wn_direct_upper *upper)
{
    if (!m || m->closed || !m->upper_control || !upper || !upper->read || !upper->write ||
        !upper->close)
        return WN_DIRECT_BOUNDS;
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    struct wn_direct_open_entry e;
    if (!f || f->promoted || f->reset || (!f->has_lane && !f->packet) ||
        wn_direct_flows_open(m, id, &e) || !e.complete || e.result ||
        e.local_closed || e.remote_closed)
        return WN_DIRECT_BOUNDS;
    if (f->packet) {
        if (wn_direct_packet_promote(f->packet))
            return WN_DIRECT_BOUNDS;
        f->upper = *upper;
        f->promoted = true;
        return 0;
    }
    if (!upper->shutdown_write)
        return WN_DIRECT_BOUNDS;
    if (wn_direct_trim(&f->sender.buffer) || wn_direct_trim(&f->receiver.buffer))
        return WN_DIRECT_BOUNDS;
    f->upper = *upper;
    f->promoted = true;
    return 0;
}

int wn_direct_flows_packet_io(struct wn_direct_flows *m, uint32_t id,
                              const struct wn_direct_packet_io *io)
{
    struct wn_direct_flow *f = wn_direct_flows_find(m, id);
    struct wn_direct_open_entry e;
    if (!f || m->closed || f->reset || !f->packet || f->socket.fd >= 0 || f->packet_io.read ||
        !io || !io->read || !io->write || !io->close ||
        wn_direct_flows_open(m, id, &e) || !e.complete || e.result)
        return WN_DIRECT_BOUNDS;
    f->packet_io = *io;
    return 0;
}

bool wn_direct_flows_retirement_ready(const struct wn_direct_flows *m)
{
    return m && !m->closed && m->upper_control && m->idle_sent &&
           m->peer_idle && wn_direct_flows_quiescent(m);
}
