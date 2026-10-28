/* Ordinary busy streams: one borrowed handshake never stalls another flow. */
#include "wendy_net_actor.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    struct wna_session handshake={.phase=WNA_PREPARE,.deadline=1000};
    struct wna_session established={.phase=WNA_READY,.deadline=10000};
    struct wna_channel traffic={0};
    assert(wna_next(&handshake,1,false,true)==WNA_CRYPTO_PREPARE);
    wna_lend(&handshake);
    assert(wna_next(&handshake,2,true,true)==WNA_NONE);
    /* A ready unrelated connection can consume and produce bytes while the
     * first connection is exclusively lent to the lower-priority worker. */
    memcpy(traffic.input.bytes,"sensor",6);traffic.input.size=6;
    char bytes[WNA_IO_BYTES];assert(wna_read(&traffic,bytes,sizeof bytes)==6);
    assert(!memcmp(bytes,"sensor",6));
    assert(wna_write(&traffic,bytes,6)==6);
    assert(established.phase==WNA_READY);
    wna_completed(&handshake,0);
    assert(wna_next(&handshake,3,false,true)==WNA_CRYPTO_STEP);
    wna_lend(&handshake);wna_completed(&handshake,-2);
    assert(wna_next(&handshake,4,false,true)==WNA_IO_READ);
    assert(wna_next(&handshake,5,true,true)==WNA_CRYPTO_STEP);
    memset(bytes,7,sizeof bytes);
    assert(wna_write(&traffic,bytes,sizeof bytes)==WNA_IO_BYTES-6);
    assert(wna_write(&traffic,bytes,1)==-3);
    assert(traffic.output.size==WNA_IO_BYTES);
    wna_buffer_consume(&traffic.output,123);
    assert(wna_write(&traffic,bytes,123)==123 && traffic.output.size==WNA_IO_BYTES);
    wna_lend(&handshake);handshake.cancel=true;
    assert(wna_next(&handshake,1001,true,true)==WNA_NONE);
    wna_completed(&handshake,1);
    assert(wna_next(&handshake,1002,true,true)==WNA_CLOSE);
    struct wna_session guest={.phase=WNA_HANDSHAKE,.deadline=5000};
    wna_lend(&guest);
    assert(!wna_yield_guest_setup(&guest,false,true,false,true)); /* PSRAM policy. */
    assert(!wna_yield_guest_setup(&guest,true,false,false,true)); /* Incoming guest. */
    assert(!wna_yield_guest_setup(&guest,true,true,true,true)); /* Established I/O. */
    assert(!wna_yield_guest_setup(&guest,true,true,false,false)); /* Other owner. */
    assert(wna_yield_guest_setup(&guest,true,true,false,true));
    assert(guest.cancel && guest.lent && guest.phase==WNA_HANDSHAKE);
    assert(wna_next(&guest,1003,true,true)==WNA_NONE); /* Never touch the loan. */
    wna_completed(&guest,0);
    assert(!guest.lent && guest.cancel && guest.phase==WNA_READY);
    assert(wna_next(&guest,1004,true,true)==WNA_CLOSE);
    assert(!wna_yield_guest_setup(&established,true,true,true,true));
    puts("Independent I/O, bounded buffers, wait-for-input and acknowledged cancellation pass");
}
