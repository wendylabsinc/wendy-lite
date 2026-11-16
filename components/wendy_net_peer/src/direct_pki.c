#include "wendy_net_direct_pki.h"
#include <limits.h>

static int read_upper(void *arg, uint8_t *bytes, size_t size)
{
    struct wn_direct_pki *p = arg;
    if (p->retired || size > INT_MAX)
        return -1;
    return (int)wendy_pki_read(p->connection, bytes, size);
}
static int write_upper(void *arg, const uint8_t *bytes, size_t size)
{
    struct wn_direct_pki *p = arg;
    if (p->retired || size > INT_MAX)
        return -1;
    return (int)wendy_pki_write(p->connection, bytes, size);
}
static int shutdown_upper(void *arg)
{
    struct wn_direct_pki *p = arg;
    if (p->retired)
        return -1;
    int result = wendy_pki_shutdown_write(p->connection);
    if (!result)
        p->send_closed = true;
    return result;
}
static void close_upper(void *arg)
{
    struct wn_direct_pki *p = arg;
    if (p->retired)
        return;
    p->retired = true;
    p->retire(p->owner, p->send_closed);
}
static int fd_upper(void *arg)
{
    struct wn_direct_pki *p = arg;
    return !p->retired && p->fd ? p->fd(p->owner) : -1;
}
static bool pending_upper(void *arg)
{
    struct wn_direct_pki *p = arg;
    return !p->retired &&
           ((p->pending && p->pending(p->owner)) || wendy_pki_pending(p->connection));
}
struct wn_direct_upper wn_direct_pki_upper(struct wn_direct_pki *p)
{
    if (!p || !p->connection || !p->retire || p->retired)
        return (struct wn_direct_upper){0};
    return (struct wn_direct_upper){.context = p,
                                    .read = read_upper,
                                    .write = write_upper,
                                    .shutdown_write = shutdown_upper,
                                    .close = close_upper,
                                    .fd = fd_upper,
                                    .pending = pending_upper};
}
