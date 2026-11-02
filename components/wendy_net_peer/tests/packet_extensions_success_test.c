/* Optional datagram kinds preserve an in-progress version1 IPv6 packet. */
#include "wendy_net_peer_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    /* A future datagram kind between fragments cannot corrupt reassembly. */
    uint8_t packet[WN_MTU] = {0x60}, fragment[WN_DATAGRAM_MAX];
    wn_put16(packet + 4, WN_MTU - 40);
    struct wn_assembler assembler = {0};
    size_t n = wn_fragment(fragment, packet, sizeof packet, 7, 0);
    assert(n && !wn_assemble(&assembler, fragment, n, 1));
    struct wn_assembler saved = assembler;
    uint8_t future[] = {3, 0x01};
    assert(!wn_assemble(&assembler, future, sizeof future, 2));
    assert(!memcmp(&saved, &assembler, sizeof saved));
    n = wn_fragment(fragment, packet, sizeof packet, 7, 1091);
    assert(n && wn_assemble(&assembler, fragment, n, 3) == WN_MTU);
    assert(!memcmp(packet, assembler.packet, sizeof packet));
    assert(wn_assemble(&assembler, (uint8_t[]){1}, 1, 4) < 0);
    puts("future datagrams skipped; partial packet retained and malformed known kind rejected");
    return 0;
}
