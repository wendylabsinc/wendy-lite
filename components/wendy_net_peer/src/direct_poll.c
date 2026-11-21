#include "wendy_net_direct_poll.h"
#include <limits.h>
static int64_t earlier(int64_t a, int64_t b)
{
    return b > 0 && b < a ? b : a;
}
int64_t wn_direct_registry_pollfds(struct wn_direct_registry *r, fd_set *rd, fd_set *wr,
                                   int *maximum, int64_t deadline)
{
    for (struct wn_direct_peer *p = r->peers; p; p = p->next) {
        struct wn_direct_session *s = &p->session;
        if (s->closed)
            continue;
        deadline = earlier(deadline, s->security_deadline);
        deadline = earlier(deadline, s->outage_deadline);
        deadline = earlier(deadline, s->promotion_deadline);
        if (wn_direct_session_frozen(s)) {
            deadline = earlier(deadline, s->setup_deadline);
            continue;
        }
        for (unsigned i = 0; i < 2u * p->flows.slots; i++) {
            struct wn_direct_flow *f = &p->flows.flows[i];
            if (!f->id || f->reset)
                continue;
            if (f->packet) {
                if (f->packet_io.pending && f->packet_io.pending(f->packet_io.context))
                    deadline = 0;
                if (f->promoted) {
                    int upper = f->upper.fd ? f->upper.fd(f->upper.context) : -1;
                    unsigned want =
                        (f->packet->read_wait ? f->packet->read_wait : 1) |
                        (f->packet->tx.active ? (f->packet->write_wait ? f->packet->write_wait : 2)
                                              : 0);
                    if (upper >= 0 && upper < FD_SETSIZE) {
                        if (want & 1)
                            FD_SET(upper, rd);
                        if (want & 2)
                            FD_SET(upper, wr);
                        if (upper > *maximum)
                            *maximum = upper;
                    }
                    if (f->upper.pending && f->upper.pending(f->upper.context))
                        deadline = 0;
                }
                int fd = f->socket.fd;
                if (fd >= 0 && fd < FD_SETSIZE) {
                    bool read = !f->packet->tx.active, write = f->packet->ready;
                    if (read)
                        FD_SET(fd, rd);
                    if (write)
                        FD_SET(fd, wr);
                    if ((read || write) && fd > *maximum)
                        *maximum = fd;
                }
                continue;
            }
            if (!f->has_lane)
                continue;
            if (s->active && !p->flows.upper_control && f->lane.ack.pending &&
                f->lane.ack.since <= INT64_MAX - WN_DIRECT_ACK_DELAY_US)
                deadline = earlier(deadline, f->lane.ack.since + WN_DIRECT_ACK_DELAY_US);
            if (f->promoted) {
                int upper = f->upper.fd ? f->upper.fd(f->upper.context) : -1;
                struct wn_direct_buffer *tx = &f->sender.buffer, *rx = &f->receiver.buffer;
                bool reading = (!f->receiver.finished || rx->end < f->receiver.final) &&
                               rx->end - rx->start < p->flows.window &&
                               (rx->limit > rx->end || (rx->pool && rx->pool->available));
                bool writing =
                    tx->end > tx->start || (f->sender.finished && !f->upper_write_closed);
                unsigned want = (reading ? (f->upper_read_wait ? f->upper_read_wait : 1) : 0) |
                                (writing ? (f->upper_write_wait ? f->upper_write_wait : 2) : 0);
                if (upper >= 0 && upper < FD_SETSIZE) {
                    if (want & 1)
                        FD_SET(upper, rd);
                    if (want & 2)
                        FD_SET(upper, wr);
                    if (want && upper > *maximum)
                        *maximum = upper;
                }
                if (reading && f->upper.pending && f->upper.pending(f->upper.context))
                    deadline = 0;
            }
            int fd = f->socket.fd;
            if (fd < 0 || fd >= FD_SETSIZE)
                continue;
            struct wn_direct_buffer *rx = &f->receiver.buffer;
            bool read = !f->socket.read_eof && wn_direct_flows_send_capacity(&p->flows, f) > 0;
            bool write = !f->socket.write_shutdown && rx->end > rx->start;
            if (read)
                FD_SET(fd, rd);
            if (write)
                FD_SET(fd, wr);
            if ((read || write) && fd > *maximum)
                *maximum = fd;
        }
    }
    return deadline;
}
