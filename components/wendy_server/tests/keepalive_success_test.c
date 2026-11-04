#include "wendy_server_keepalive.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

/* A WendyCom mTLS link must close itself 45 s after its peer goes silent,
 * probing every 15 s, even when the device has nothing to send. */
int main(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof address;
    assert(!bind(listener, (struct sockaddr *)&address, sizeof address));
    assert(!listen(listener, 1));
    assert(!getsockname(listener, (struct sockaddr *)&address, &length));
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0 && !connect(client, (struct sockaddr *)&address, sizeof address));
    int fd = accept(listener, NULL, NULL);
    assert(fd >= 0);

    assert(!wendy_server_enable_keepalive(fd));

    int enabled = 0, idle = 0, interval = 0, probes = 0;
    socklen_t size = sizeof enabled;
    assert(!getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, &size) && enabled);
#ifdef TCP_KEEPIDLE
    assert(!getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, &size));
#else
    assert(!getsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, &size));
#endif
    assert(!getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, &size));
    assert(!getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, &size));
    assert(idle == 15 && interval == 15 && probes == 2);
    assert(idle + interval * probes == 45);

    /* A descriptor that is not a socket reports failure instead of crashing. */
    assert(wendy_server_enable_keepalive(-1) == -1);

    close(fd);
    close(client);
    close(listener);
    puts("keepalive_success_test: ok");
    return 0;
}
