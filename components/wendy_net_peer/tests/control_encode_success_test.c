/* Ordinary gossip framing round trips, including complete and final chunks. */
#include "wendy_net_control.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void roundtrip(const struct wg_message *message)
{
    char text[WN_CONTROL_MAX+1];uint8_t decoded[WG_CHUNK];
    struct wg_message read;
    int n=wn_gossip_write(message,text,sizeof text);
    assert(n>0 && (size_t)n<=WN_CONTROL_MAX);
    assert(!wn_gossip_read(text,(size_t)n,&read,decoded));
    assert(read.op==message->op && read.id.type==message->id.type);
    assert(!memcmp(read.id.hash,message->id.hash,32));
    assert(read.request==message->request && read.offset==message->offset);
    assert(read.total==message->total && read.size==message->size);
    if(read.size)assert(!memcmp(read.data,message->data,read.size));
}
int main(void)
{
    /* A future peer's optional operation has its own body schema. Skip it
     * without attempting to decode that schema as today's DATA format. */
    uint8_t future[256];struct wn_writer writer={.data=future,.capacity=sizeof future,.maximum=sizeof future};
    wn_map(&writer,2);wn_key(&writer,"kind");wn_text(&writer,"gossip");wn_key(&writer,"gossip");
    wn_map(&writer,2);wn_key(&writer,"op");wn_text(&writer,"future-cache-hint");wn_text(&writer,"details");
    wn_map(&writer,1);wn_text(&writer,"mode");wn_text(&writer,"compact");int future_size=wn_finish(&writer);assert(future_size>0);
    struct wg_message skipped;uint8_t scratch[WG_CHUNK];
    assert(wn_gossip_read(future,(size_t)future_size,&skipped,scratch)==1);
    uint8_t bytes[WG_CHUNK];
    for(unsigned i=0;i<sizeof bytes;i++)bytes[i]=(uint8_t)(i*31+7);
    for(unsigned type=1;type<=3;type++){
        struct wg_message m={.id.type=type};
        memset(m.id.hash,0x42,32);
        roundtrip(&m);
        m.op=WG_GONE;roundtrip(&m);
        m.op=WG_WANT;m.request=42;roundtrip(&m);
        m.op=WG_UNAVAILABLE;roundtrip(&m);
        m.op=WG_DATA;m.data=bytes;m.total=m.size=WG_CHUNK;roundtrip(&m);
        m.total=WG_CHUNK+1;roundtrip(&m);
        m.offset=WG_CHUNK;m.size=1;roundtrip(&m);
    }
    puts("Normal gossip encoding round trips passed");
    return 0;
}
