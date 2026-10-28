#include "../src/time_control.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void emit_frame(const void *data,size_t size)
{uint8_t header[4];wn_put32(header,(uint32_t)size);assert(fwrite(header,1,4,stdout)==4 && fwrite(data,1,size,stdout)==size);}
int main(int argc,char **argv)
{
    bool emit=argc==2 && !strcmp(argv[1],"--wire");
    uint8_t query[93];for(size_t i=0;i<sizeof query;i++)query[i]=(uint8_t)i;
    struct wnt_job *client=wnt_new(42,query,sizeof query,30000);assert(client);
    char wire[1600];int size=wnt_request_write(client,wire,sizeof wire);assert(size>0);
    if(emit)emit_frame(wire,(size_t)size);
    struct wn_doc doc;assert(!wn_doc_parse(&doc,wire,(size_t)size));
    int at=wn_doc_member(&doc,0,"time");assert(at>=0);
    struct wnt_job *server=wnt_request_read(&doc,(unsigned)at,30000);assert(server);
    assert(server->query_size==sizeof query && !memcmp(server->query,query,sizeof query));
    server->size=17*1024+41;server->reply=malloc(server->size);assert(server->reply);
    for(size_t i=0;i<server->size;i++)server->reply[i]=(uint8_t)(i*31+7);
    server->result=0;
    while(!atomic_load(&client->done)){
        size=wnt_reply_write(server,wire,sizeof wire);assert(size>0);
        if(emit)emit_frame(wire,(size_t)size);
        assert(!wn_doc_parse(&doc,wire,(size_t)size));at=wn_doc_member(&doc,0,"time");
        assert(!wnt_reply_read(client,&doc,(unsigned)at));
        size_t piece=server->size-server->offset;if(piece>1024)piece=1024;server->offset+=piece;
        if(!atomic_load(&client->done)){
            size=wnt_request_write(client,wire,sizeof wire);assert(size>0);
            if(emit)emit_frame(wire,(size_t)size);
            assert(!wn_doc_parse(&doc,wire,(size_t)size));at=wn_doc_member(&doc,0,"time");
            assert(wn_doc_equal(&doc,wn_doc_member(&doc,(unsigned)at,"op"),"next"));
            uint64_t offset;assert(!wn_doc_u64(&doc,wn_doc_member(&doc,(unsigned)at,"offset"),&offset));
            assert(offset==server->offset);
        }
    }
    assert(!client->result && client->size==server->size && !memcmp(client->reply,server->reply,server->size));
    wnt_retain(server);wnt_release(server);wnt_release(server);wnt_release(client);
    if(!emit)puts("normal 17449-byte timestamp reply pulled intact over bounded control frames");
    return 0;
}
