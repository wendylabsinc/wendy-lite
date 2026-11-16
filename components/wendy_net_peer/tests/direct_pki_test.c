#include "wendy_net_direct_pki.h"
#include <assert.h>

/* PKI double: the test checks ownership/readiness, not TLS cryptography (which
 * is covered by the real MbedTLS/Go interop suite). */
struct wendy_pki_connection {
    unsigned calls;
    bool plaintext;
    int shutdown_result;
};
ssize_t wendy_pki_read(void *arg, void *bytes, size_t n)
{
    (void)bytes;
    (void)n;
    ((wendy_pki_connection *)arg)->calls++;
    return -2;
}
ssize_t wendy_pki_write(void *arg, const void *bytes, size_t n)
{
    (void)bytes;
    (void)n;
    ((wendy_pki_connection *)arg)->calls++;
    return -3;
}
int wendy_pki_shutdown_write(wendy_pki_connection *p)
{
    p->calls++;
    return p->shutdown_result;
}
bool wendy_pki_pending(wendy_pki_connection *p)
{
    p->calls++;
    return p->plaintext;
}
void wendy_pki_close(wendy_pki_connection *p)
{
    (void)p;
    assert(!"adapter bypassed owner cleanup worker");
}
struct owner {
    unsigned retired;
    bool encrypted, drain;
};
static void retire(void *arg, bool drain)
{
    struct owner *o = arg;
    o->retired++;
    o->drain = drain;
}
static bool pending(void *arg)
{
    return ((struct owner *)arg)->encrypted;
}
int main(void)
{
    wendy_pki_connection tls = {.shutdown_result = -3};
    struct owner owner = {0};
    struct wn_direct_pki adapter = {
        .connection = &tls, .owner = &owner, .retire = retire, .pending = pending};
    struct wn_direct_upper upper = wn_direct_pki_upper(&adapter);
    assert(upper.context == &adapter);
    assert(upper.fd(upper.context) == -1 && !upper.pending(upper.context));
    owner.encrypted = true;
    assert(upper.pending(upper.context));
    owner.encrypted = false;
    tls.plaintext = true;
    assert(upper.pending(upper.context));
    assert(upper.read(upper.context, NULL, 0) == -2 && upper.write(upper.context, NULL, 0) == -3);
    assert(upper.shutdown_write(upper.context) == -3);
    upper.close(upper.context);
    assert(owner.retired == 1 && adapter.retired && !owner.drain);
    /* Owner remains alive for deferred worker cleanup, but no more TLS access. */
    unsigned calls = tls.calls;
    upper.close(upper.context);
    assert(owner.retired == 1);
    assert(upper.read(upper.context, NULL, 0) == -1 && upper.write(upper.context, NULL, 0) == -1);
    assert(upper.shutdown_write(upper.context) == -1 && !upper.pending(upper.context));
    assert(upper.fd(upper.context) == -1 && tls.calls == calls);
    assert(!wn_direct_pki_upper(&adapter).context && !wn_direct_pki_upper(NULL).context);
    adapter.retired = false;
    tls.shutdown_result = 0;
    upper = wn_direct_pki_upper(&adapter);
    assert(!upper.shutdown_write(upper.context));
    upper.close(upper.context);
    assert(owner.retired == 2 && owner.drain); /* buffered close_notify must drain */
    adapter.retired = false;
    adapter.retire = NULL;
    assert(!wn_direct_pki_upper(&adapter).context);
    return 0;
}
