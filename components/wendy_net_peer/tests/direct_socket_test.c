#include "wendy_net_direct_socket.h"
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void)
{
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    struct wn_direct_socket io;
    assert(!wn_direct_socket_init(&io, pair[0]));
    struct wn_direct_slot chunks[2], rx_chunks[1];
    struct wn_direct_pool pool, rx_pool;
    assert(!wn_direct_pool_init_dynamic(&pool, chunks, 2, malloc, free));
    assert(!wn_direct_pool_init_dynamic(&rx_pool, rx_chunks, 1, malloc, free));
    struct wn_direct_sender tx = {0};
    struct wn_direct_receiver rx = {0};
    wn_direct_buffer_init(&tx.buffer, &pool);
    wn_direct_buffer_init(&rx.buffer, &rx_pool);
    assert(!wn_direct_reserve(&rx.buffer, 256));
    uint8_t payload[513], scratch[513];
    memset(payload, 0x5a, sizeof payload);
    assert(send(pair[1], payload, sizeof payload, 0) == sizeof payload);
    assert(wn_direct_socket_read(&io, &tx, 512) == 1);
    assert(wn_direct_socket_read(&io, &tx, 512) == 1);
    assert(tx.buffer.end == 512 && !pool.available);
    // Suspension preserves the local socket; exhausted credit leaves its next
    // byte in the socket instead of consuming into an unaccounted staging buffer.
    assert(!wn_direct_socket_read(&io, &tx, 512));
    assert(tx.buffer.end == 512);
    tx.remote_limit = 1024;
    size_t n;
    assert(!wn_direct_send_offer(&tx, 0, scratch, 512, &n) && n == 512);
    assert(!wn_direct_send_state(&tx, 256, 1024));
    assert(wn_direct_socket_read(&io, &tx, 512) == 1);
    assert(tx.buffer.end == 513);
    assert(!wn_direct_send_offer(&tx, 256, scratch, sizeof scratch, &n) && n == 257);
    assert(!memcmp(scratch, payload + 256, n));
    assert(!shutdown(pair[1], SHUT_WR));
    assert(wn_direct_socket_read(&io, &tx, 512) == 1);
    assert(io.read_eof && tx.finished && tx.final == 513);
    // A FIN promise cannot close the local write side before all bytes arrive.
    assert(!wn_direct_receive_finish(&rx, 3));
    assert(!wn_direct_socket_write(&io, &rx));
    assert(!wn_direct_receive(&rx, "abc", 3));
    // Fill the local socket's send queue: failed/nonblocking writes must not
    // release acknowledged receive ownership before the application accepts it.
    size_t queued = 0;
    ssize_t sent;
    while ((sent = send(pair[0], payload, sizeof payload, MSG_DONTWAIT)) > 0)
        queued += (size_t)sent;
    while ((sent = send(pair[0], payload, 1, MSG_DONTWAIT)) > 0)
        queued += (size_t)sent;
    assert(sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    assert(!wn_direct_socket_write(&io, &rx));
    assert(rx.buffer.start == 0);
    while (queued) {
        ssize_t got = recv(pair[1], scratch, queued < sizeof scratch ? queued : sizeof scratch, 0);
        assert(got > 0);
        queued -= (size_t)got;
    }
    assert(wn_direct_socket_write(&io, &rx) == 1);
    assert(recv(pair[1], scratch, sizeof scratch, 0) == 3 && !memcmp(scratch, "abc", 3));
    assert(wn_direct_socket_write(&io, &rx) == 1);
    assert(io.write_shutdown);
    assert(recv(pair[1], scratch, sizeof scratch, 0) == 0);
    wn_direct_close(&tx.buffer);
    wn_direct_close(&rx.buffer);
    assert(pool.available == 2 && rx_pool.available == 1);
    close(pair[0]);
    close(pair[1]);
    return 0;
}
