#include "app_relay.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct wendy_pki_connection {
    const char *input;
    size_t read;
    char output[64];
    size_t written;
    bool eof, closed;
    unsigned closes;
};
ssize_t wendy_pki_read(void *arg, void *bytes, size_t size)
{
    wendy_pki_connection *p = arg;
    size_t remaining = p->input ? strlen(p->input) - p->read : 0;
    if (!remaining)
        return p->eof ? 0 : -2;
    if (size > remaining)
        size = remaining;
    if (size > 3)
        size = 3;
    memcpy(bytes, p->input + p->read, size);
    p->read += size;
    return (ssize_t)size;
}
ssize_t wendy_pki_write(void *arg, const void *bytes, size_t size)
{
    wendy_pki_connection *p = arg;
    assert(!p->closed);
    if (size > 2)
        size = 2;
    assert(p->written + size < sizeof p->output);
    memcpy(p->output + p->written, bytes, size);
    p->written += size;
    return (ssize_t)size;
}
int wendy_pki_shutdown_write(wendy_pki_connection *p)
{
    assert(!p->closed);
    p->closes++;
    if (p->closes == 1)
        return -2;
    if (p->closes == 2)
        return -3;
    p->closed = true;
    return 0;
}
static void run(bool remote_first)
{
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    struct buffer buffers[2] = {0};
    bool local_half = false, tls_half = false;
    wendy_pki_connection tls = {0};
    if (remote_first) {
        tls.input = "request";
        tls.eof = true;
    } else {
        assert(send(fd[1], "request", 7, 0) == 7);
        assert(!shutdown(fd[1], SHUT_WR));
    }
    for (unsigned i = 0; i < 30; i++)
        assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, false) >= 0);
    char got[32] = {0};
    if (remote_first) {
        assert(local_half && !tls_half);
        assert(recv(fd[1], got, sizeof got, MSG_DONTWAIT) == 7 && !memcmp(got, "request", 7));
        assert(recv(fd[1], got, sizeof got, MSG_DONTWAIT) == 0);
        assert(send(fd[1], "response", 8, 0) == 8);
        assert(!shutdown(fd[1], SHUT_WR));
    } else {
        assert(tls_half && !local_half && tls.closes == 3 && !strcmp(tls.output, "request"));
        tls.input = "response";
        tls.eof = true;
    }
    /* Keep ciphertext pending after both plaintext halves close. */
    for (unsigned i = 0; i < 30; i++)
        assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, true) >= 0);
    assert(tls_half && local_half && tls.closes == 3);
    if (remote_first)
        assert(!strcmp(tls.output, "response"));
    else {
        assert(recv(fd[1], got, sizeof got, MSG_DONTWAIT) == 8 && !memcmp(got, "response", 8));
        assert(recv(fd[1], got, sizeof got, MSG_DONTWAIT) == 0);
    }
    assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, false) == -1);
    close(fd[0]);
    close(fd[1]);
}
static void close_notify_drain(void)
{
    int fd[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
    assert(!shutdown(fd[1], SHUT_WR));
    struct buffer buffers[2] = {0};
    bool local_half = false, tls_half = false;
    wendy_pki_connection tls = {.eof = true, .closes = 2};
    /* The pre-call output snapshot is empty; shutdown queues a new record. */
    assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, false) == 1);
    assert(local_half && tls_half);
    assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, true) >= 0);
    assert(wn_app_relay_step(&tls, fd[0], buffers, &local_half, &tls_half, false) == -1);
    close(fd[0]);
    close(fd[1]);
}
int main(void)
{
    run(false);
    run(true);
    close_notify_drain();
    return 0;
}
