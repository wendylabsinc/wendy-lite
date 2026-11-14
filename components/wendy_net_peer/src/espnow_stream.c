/* SPDX-License-Identifier: Apache-2.0 */
#include "espnow_stream.h"
#include "wendy_net_nan_protocol.h"
#include <limits.h>
#include <string.h>

/* Frame: magic[4] version type flags window dst[4] src[4] seq[4] ack[4] data.
 * "flags" is the requested service in SYN and FIN_ACK in FIN, otherwise zero.
 * Sequence numbers count segments, starting at zero in each direction.
 * "ack" is cumulative: the next segment expected from the peer. "window" is
 * how many segments from "ack" on the sender of the frame can still buffer. */
enum { SYN_SENT, SYN_RECEIVED, OPEN, CLOSING, DEAD };
#define FIN_ACK 1
struct segment {
    uint16_t size, offset;
    uint8_t bytes[];
};
struct wnes_conn {
    struct wnes *owner;
    uint8_t mac[6], state, service;
    bool incoming, taken, released, peer_fin, fin_acked, ack_due, ack_now, resend, armed;
    uint32_t local_id, peer_id;
    uint32_t snd_una, snd_sent, snd_nxt; /* acknowledged <= transmitted <= queued */
    uint32_t rcv_read, rcv_nxt;          /* consumed by the owner <= received in order */
    uint8_t peer_window, advertised, pending_acks, dup_acks;
    unsigned retries;
    int64_t rto, rto_at, ack_at, heard, deadline;
    struct segment *tx[WNES_WINDOW_MAX], *rx[WNES_WINDOW_MAX];
};
struct wnes {
    struct wnes_config config;
    bool busy;
    uint8_t accepting;
    unsigned capacity, segments, peak;
    uint8_t *frame;
    struct wnes_conn *conns[];
};

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
int wnes_advert_write(const uint8_t tenant[16], const uint8_t device[16], const uint8_t mesh[8],
                      uint8_t flags, uint8_t out[WNES_ADVERT_SIZE])
{
    if (!out || wn_nan_presence_write(tenant, device, mesh, true, out + 7) != WN_NAN_PRESENCE_SIZE)
        return -1;
    memcpy(out, WNES_MAGIC, 4);
    out[4] = WNES_VERSION;
    out[5] = WNES_ADVERT;
    out[6] = flags;
    return WNES_ADVERT_SIZE;
}
bool wnes_advert_read(const uint8_t tenant[16], const uint8_t mesh[8], const void *frame,
                      size_t size, uint8_t device[16], uint8_t *flags)
{
    const uint8_t *f = frame;
    struct wn_nan_hint hint;
    if (!f || !device || !flags || size < WNES_ADVERT_SIZE || memcmp(f, WNES_MAGIC, 4) ||
        f[4] != WNES_VERSION || f[5] != WNES_ADVERT ||
        !wn_nan_presence_read(tenant, mesh, f + 7, size - 7, &hint))
        return false;
    memcpy(device, hint.device, 16);
    *flags = f[6];
    return true;
}
void wnes_defaults(struct wnes_config *k)
{
    k->frame_bytes = 1024;
    k->window = 8;
    k->backlog = 2;
    k->retries = 6;
    /* ponytail: fixed base timeout, no round-trip estimator. Fine for one
     * radio hop of a few ms; add SRTT/RTTVAR if a slower PHY rate is used. */
    k->rto_us = 100000;
    k->rto_max_us = 2000000;
    k->ack_delay_us = 20000;
    k->idle_us = 30000000;
    k->connect_us = 5000000;
    k->linger_us = 2000000;
}

static struct segment *segment_new(struct wnes *m, size_t bytes)
{
    struct segment *s = m->config.alloc(sizeof *s + bytes);
    if (s) {
        s->size = s->offset = 0;
        if (++m->segments > m->peak)
            m->peak = m->segments;
    }
    return s;
}
static void segment_free(struct wnes *m, struct segment **s)
{
    if (*s) {
        m->config.free(*s);
        *s = NULL;
        m->segments--;
    }
}
static void drop_received(struct wnes_conn *c)
{
    for (unsigned i = 0; i < WNES_WINDOW_MAX; i++)
        segment_free(c->owner, &c->rx[i]);
}
static void fail(struct wnes_conn *c)
{
    c->state = DEAD;
    drop_received(c);
    for (unsigned i = 0; i < WNES_WINDOW_MAX; i++)
        segment_free(c->owner, &c->tx[i]);
}
static void conn_free(struct wnes_conn *c)
{
    struct wnes *m = c->owner;
    fail(c);
    for (unsigned i = 0; i < m->capacity; i++)
        if (m->conns[i] == c)
            m->conns[i] = NULL;
    m->config.free(c);
}
/* The owner still holds a taken, unreleased stream: it must observe failure. */
static void retire(struct wnes_conn *c)
{
    if (c->released || !c->taken)
        conn_free(c);
    else
        fail(c);
}
static struct wnes_conn *conn_new(struct wnes *m, const uint8_t mac[6], int64_t now)
{
    unsigned slot = 0;
    while (slot < m->capacity && m->conns[slot])
        slot++;
    struct wnes_conn *c = slot < m->capacity ? m->config.alloc(sizeof *c) : NULL;
    if (!c)
        return NULL;
    memset(c, 0, sizeof *c);
    c->owner = m;
    memcpy(c->mac, mac, 6);
    for (bool unique = false; !unique;) {
        c->local_id = m->config.random();
        unique = c->local_id != 0;
        for (unsigned i = 0; i < m->capacity; i++)
            if (m->conns[i] && m->conns[i]->local_id == c->local_id)
                unique = false;
    }
    c->peer_window = m->config.window;
    c->heard = now;
    c->deadline = now + m->config.connect_us;
    m->conns[slot] = c;
    return c;
}
static uint8_t *header(struct wnes *m, uint8_t type, uint8_t flags, uint8_t window, uint32_t dst,
                       uint32_t src, uint32_t seq, uint32_t ack)
{
    uint8_t *f = m->frame;
    memcpy(f, WNES_MAGIC, 4);
    f[4] = WNES_VERSION;
    f[5] = type;
    f[6] = flags;
    f[7] = window;
    put32(f + 8, dst);
    put32(f + 12, src);
    put32(f + 16, seq);
    put32(f + 20, ack);
    return f;
}
static int emit(struct wnes_conn *c, uint8_t type, uint8_t flags, uint32_t seq,
                const struct segment *data)
{
    struct wnes *m = c->owner;
    uint8_t window = (uint8_t)(m->config.window - (c->rcv_nxt - c->rcv_read));
    uint8_t *f = header(m, type, flags, window, c->peer_id, c->local_id, seq, c->rcv_nxt);
    size_t size = WNES_HEADER;
    if (data) {
        memcpy(f + size, data->bytes, data->size);
        size += data->size;
    }
    if (m->config.send(m->config.context, c->mac, f, size)) {
        m->busy = true;
        return -1;
    }
    c->advertised = window;
    if (type == WNES_DATA || type == WNES_ACK) {
        c->ack_due = c->ack_now = false;
        c->pending_acks = 0;
    }
    return 0;
}
/* One small reply to a frame for a stream that does not exist here, so a
 * restarted or refusing peer is noticed without waiting for a timeout. */
static void reset(struct wnes *m, const uint8_t mac[6], uint32_t dst, uint32_t src)
{
    (void)m->config.send(m->config.context, mac, header(m, WNES_RST, 0, 0, dst, src, 0, 0),
                         WNES_HEADER);
}

struct wnes *wnes_open(const struct wnes_config *k, unsigned max_streams)
{
    if (!k || !max_streams || max_streams > 64 || k->frame_bytes < WNES_FRAME_MIN ||
        k->frame_bytes > WNES_FRAME_MAX || !k->window || k->window > WNES_WINDOW_MAX ||
        !k->alloc || !k->free || !k->send || !k->random || k->rto_us <= 0 ||
        k->rto_max_us < k->rto_us || k->ack_delay_us < 0 || k->idle_us <= 0 || k->connect_us <= 0 ||
        k->linger_us < 0)
        return NULL;
    struct wnes *m = k->alloc(sizeof *m + max_streams * sizeof m->conns[0]);
    if (!m)
        return NULL;
    memset(m, 0, sizeof *m + max_streams * sizeof m->conns[0]);
    m->config = *k;
    m->capacity = max_streams;
    m->frame = k->alloc(k->frame_bytes);
    if (!m->frame) {
        k->free(m);
        return NULL;
    }
    return m;
}
void wnes_close(struct wnes *m)
{
    if (!m)
        return;
    for (unsigned i = 0; i < m->capacity; i++)
        if (m->conns[i])
            conn_free(m->conns[i]);
    m->config.free(m->frame);
    m->config.free(m);
}
void wnes_accepting(struct wnes *m, uint8_t services)
{
    if (m)
        m->accepting = services;
}
struct wnes_conn *wnes_connect(struct wnes *m, const uint8_t mac[6], uint8_t service, int64_t now)
{
    struct wnes_conn *c = m && mac && service < 8 ? conn_new(m, mac, now) : NULL;
    if (c) {
        c->service = service;
        c->taken = true;
        c->state = SYN_SENT;
        c->resend = true; /* The first SYN leaves on the next tick. */
    }
    return c;
}
struct wnes_conn *wnes_accept(struct wnes *m, uint8_t mac[6], uint8_t *service)
{
    for (unsigned i = 0; m && i < m->capacity; i++) {
        struct wnes_conn *c = m->conns[i];
        if (c && c->incoming && !c->taken && c->state == OPEN) {
            c->taken = true;
            memcpy(mac, c->mac, 6);
            *service = c->service;
            return c;
        }
    }
    return NULL;
}
bool wnes_uses(const struct wnes *m, const uint8_t mac[6])
{
    for (unsigned i = 0; m && i < m->capacity; i++)
        if (m->conns[i] && !memcmp(m->conns[i]->mac, mac, 6))
            return true;
    return false;
}
unsigned wnes_segments(const struct wnes *m, unsigned *peak)
{
    if (peak)
        *peak = m->peak;
    return m->segments;
}
bool wnes_drained(const struct wnes_conn *c)
{
    return !c || c->snd_una == c->snd_nxt;
}

static void acknowledge(struct wnes_conn *c, uint32_t ack, bool pure, uint8_t window)
{
    uint32_t acked = ack - c->snd_una;
    if (acked && acked <= c->snd_sent - c->snd_una) {
        while (c->snd_una != ack)
            segment_free(c->owner, &c->tx[c->snd_una++ % WNES_WINDOW_MAX]);
        c->armed = false; /* Restart the retransmission timer for the new head. */
        c->dup_acks = 0;
    } else if (!acked && pure && c->snd_sent != c->snd_una && window == c->peer_window &&
               c->dup_acks < UINT8_MAX && ++c->dup_acks == 2)
        c->resend = true; /* The peer holds later segments: resend the gap now. */
    if (!c->peer_window && window && c->snd_sent != c->snd_una)
        c->resend = true; /* Reopened window: the probe it refused goes first. */
    c->peer_window = window;
}
static void receive(struct wnes_conn *c, uint32_t seq, const uint8_t *data, size_t size,
                    int64_t now)
{
    struct wnes *m = c->owner;
    struct segment **slot = &c->rx[seq % WNES_WINDOW_MAX], *s;
    if (!size || c->peer_fin || c->state != OPEN)
        return;
    /* Old, duplicate or beyond the window: restate what is expected. */
    if (seq - c->rcv_read >= m->config.window || *slot) {
        c->ack_now = true;
        return;
    }
    if (!(s = segment_new(m, size)))
        return;
    memcpy(s->bytes, data, size);
    s->size = (uint16_t)size;
    *slot = s;
    if (seq == c->rcv_nxt)
        while (c->rcv_nxt - c->rcv_read < m->config.window && c->rx[c->rcv_nxt % WNES_WINDOW_MAX])
            c->rcv_nxt++;
    else
        c->ack_now = true;
    if (!c->ack_due) {
        c->ack_due = true;
        c->ack_at = now + m->config.ack_delay_us;
    }
    if (++c->pending_acks >= 2)
        c->ack_now = true;
}
void wnes_input(struct wnes *m, const uint8_t mac[6], const void *frame, size_t size, int64_t now)
{
    const uint8_t *f = frame;
    if (!m || !mac || !f || size < WNES_HEADER || size > WNES_FRAME_MAX ||
        memcmp(f, WNES_MAGIC, 4) || f[4] != WNES_VERSION)
        return;
    uint8_t type = f[5];
    uint32_t dst = get32(f + 8), src = get32(f + 12), seq = get32(f + 16), ack = get32(f + 20);
    struct wnes_conn *c = NULL;
    if (type == WNES_SYN) {
        unsigned waiting = 0;
        if (dst || !src)
            return;
        for (unsigned i = 0; i < m->capacity; i++) {
            struct wnes_conn *x = m->conns[i];
            if (x && x->incoming && x->peer_id == src && !memcmp(x->mac, mac, 6))
                c = x;
            if (x && x->incoming && !x->taken)
                waiting++;
        }
        if (!c) {
            if (f[6] >= 8 || !(m->accepting & (1u << f[6])) || waiting >= m->config.backlog ||
                !(c = conn_new(m, mac, now))) {
                reset(m, mac, src, 0);
                return;
            }
            c->service = f[6];
            c->incoming = true;
            c->state = SYN_RECEIVED;
            c->peer_id = src;
            c->peer_window = f[7];
        }
        if (c->state == SYN_RECEIVED || c->state == OPEN)
            (void)emit(c, WNES_SYNACK, 0, 0, NULL);
        return;
    }
    for (unsigned i = 0; i < m->capacity && !c; i++)
        if (m->conns[i] && m->conns[i]->local_id == dst && !memcmp(m->conns[i]->mac, mac, 6))
            c = m->conns[i];
    if (!c || !dst) {
        if (type != WNES_RST && src)
            reset(m, mac, src, dst);
        return;
    }
    if (c->state == DEAD)
        return;
    if (c->state == SYN_SENT) {
        if (type == WNES_RST)
            retire(c);
        else if (type == WNES_SYNACK && src) {
            c->peer_id = src;
            c->peer_window = f[7];
            c->state = OPEN;
            c->armed = false;
            c->retries = 0;
            c->heard = now;
            c->ack_now = true; /* Confirms the stream to the accepting side. */
        }
        return;
    }
    if (c->peer_id != src)
        return;
    if (type == WNES_RST) {
        retire(c);
        return;
    }
    c->heard = now;
    c->retries = 0;
    if (type == WNES_SYNACK) {
        c->ack_now = true; /* Our confirmation was lost. */
        return;
    }
    if (type != WNES_DATA && type != WNES_ACK && type != WNES_FIN)
        return; /* Unknown types are ignored, leaving room for later additions. */
    if (c->state == SYN_RECEIVED) {
        c->state = OPEN;
        c->armed = false;
    }
    acknowledge(c, ack, type == WNES_ACK, f[7]);
    if (type == WNES_DATA)
        receive(c, seq, f + WNES_HEADER, size - WNES_HEADER, now);
    else if (type == WNES_FIN && (f[6] & FIN_ACK)) {
        if (c->state == CLOSING && c->snd_una == c->snd_nxt)
            c->fin_acked = true;
    } else if (type == WNES_FIN && seq == c->rcv_nxt) {
        c->peer_fin = true;
        (void)emit(c, WNES_FIN, FIN_ACK, c->snd_nxt, NULL);
    }
}

static int64_t service(struct wnes_conn *c, int64_t now)
{
    struct wnes *m = c->owner;
    const struct wnes_config *k = &m->config;
    size_t mss = (size_t)k->frame_bytes - WNES_HEADER;
    if (c->state == DEAD) {
        if (c->released)
            conn_free(c);
        return INT64_MAX;
    }
    bool bounded = c->state != OPEN; /* Connecting and closing have a hard deadline. */
    int64_t expires = bounded ? c->deadline : c->heard + k->idle_us;
    if (now >= expires || (c->state == CLOSING && c->fin_acked)) {
        retire(c);
        return INT64_MAX;
    }
    bool fin = c->state == CLOSING && c->snd_una == c->snd_nxt;
    bool timer = c->state == SYN_SENT || c->state == SYN_RECEIVED || c->snd_una != c->snd_nxt || fin;
    if (!timer)
        c->armed = false;
    else if (!c->armed) {
        c->armed = true;
        c->rto = k->rto_us;
        c->rto_at = now + c->rto;
        c->resend |= fin; /* First FIN. Data and SYN have their own first send. */
    } else if (now >= c->rto_at) {
        /* Any valid frame from the peer clears the count, so a live peer with
         * a closed window is probed at the capped interval, never abandoned. */
        if (++c->retries > k->retries) {
            retire(c);
            return INT64_MAX;
        }
        c->resend = true;
        c->rto = c->rto * 2 < k->rto_max_us ? c->rto * 2 : k->rto_max_us;
        c->rto_at = now + c->rto;
    }
    if (c->resend) {
        c->resend = false;
        if (c->state == SYN_SENT)
            (void)emit(c, WNES_SYN, c->service, 0, NULL);
        else if (c->state == SYN_RECEIVED)
            (void)emit(c, WNES_SYNACK, 0, 0, NULL);
        else if (c->snd_una != c->snd_nxt) {
            if (!emit(c, WNES_DATA, 0, c->snd_una, c->tx[c->snd_una % WNES_WINDOW_MAX]) &&
                c->snd_sent == c->snd_una)
                c->snd_sent++; /* Zero-window probe. */
        } else if (fin)
            (void)emit(c, WNES_FIN, 0, c->snd_nxt, NULL);
    }
    if (c->state == OPEN || c->state == CLOSING)
        while (c->snd_sent != c->snd_nxt && c->snd_sent - c->snd_una < c->peer_window) {
            const struct segment *s = c->tx[c->snd_sent % WNES_WINDOW_MAX];
            /* Hold a partial segment while earlier data is unacknowledged, so
             * small writes share a frame instead of each taking airtime. */
            if (s->size < mss && c->snd_sent != c->snd_una && c->state == OPEN)
                break;
            if (emit(c, WNES_DATA, 0, c->snd_sent, s))
                break;
            c->snd_sent++;
        }
    if (c->state == OPEN && (c->ack_now || (c->ack_due && now >= c->ack_at)))
        (void)emit(c, WNES_ACK, 0, c->snd_sent, NULL);
    if (c->armed && c->rto_at < expires)
        expires = c->rto_at;
    if (c->ack_due && c->ack_at < expires)
        expires = c->ack_at;
    return expires;
}
int64_t wnes_tick(struct wnes *m, int64_t now)
{
    int64_t next = INT64_MAX;
    if (!m)
        return next;
    m->busy = false;
    for (unsigned i = 0; i < m->capacity; i++)
        if (m->conns[i]) {
            int64_t at = service(m->conns[i], now);
            if (at < next)
                next = at;
        }
    /* The radio refused a frame: look again shortly instead of spinning. */
    return m->busy && next > now + 2000 ? now + 2000 : next;
}

ssize_t wnes_read(void *context, void *out, size_t size)
{
    struct wnes_conn *c = context;
    if (!c || c->state == DEAD)
        return -1;
    if (c->rcv_read == c->rcv_nxt)
        return c->peer_fin ? 0 : -2;
    if (!size)
        return -2;
    struct segment **slot = &c->rx[c->rcv_read % WNES_WINDOW_MAX], *s = *slot;
    size_t n = (size_t)s->size - s->offset;
    if (n > size)
        n = size;
    memcpy(out, s->bytes + s->offset, n);
    s->offset += (uint16_t)n;
    if (s->offset == s->size) {
        segment_free(c->owner, slot);
        c->rcv_read++;
        if (!c->advertised)
            c->ack_now = true; /* Reopen a window the peer was told is closed. */
    }
    return (ssize_t)n;
}
ssize_t wnes_write(void *context, const void *data, size_t size)
{
    struct wnes_conn *c = context;
    if (!c || c->state == DEAD || c->state == CLOSING)
        return -1;
    if (c->state != OPEN)
        return -3;
    struct wnes *m = c->owner;
    size_t mss = (size_t)m->config.frame_bytes - WNES_HEADER, done = 0;
    while (done < size) {
        /* Append to the newest segment only while it has never been sent. */
        struct segment *s =
            c->snd_nxt != c->snd_sent ? c->tx[(c->snd_nxt - 1) % WNES_WINDOW_MAX] : NULL;
        if (!s || s->size == mss) {
            if (c->snd_nxt - c->snd_una >= m->config.window || !(s = segment_new(m, mss)))
                break;
            c->tx[c->snd_nxt++ % WNES_WINDOW_MAX] = s;
        }
        size_t n = mss - s->size < size - done ? mss - s->size : size - done;
        memcpy(s->bytes + s->size, (const uint8_t *)data + done, n);
        s->size += (uint16_t)n;
        done += n;
    }
    return done ? (ssize_t)done : -3;
}
void wnes_release(struct wnes_conn *c, int64_t now)
{
    if (!c || c->released)
        return;
    c->released = true;
    drop_received(c);
    if (c->state == OPEN && !c->peer_fin) {
        c->state = CLOSING;
        c->deadline = now + c->owner->config.linger_us;
    } else
        conn_free(c);
}
