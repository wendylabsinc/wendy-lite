/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_control.h"
#include "../src/certificate_wire.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "catalog"))
    {
        for (unsigned i = 0; i < 2; i++)
        {
            char out[160];
            int n=wn_catalog_marker_write(i!=0,out,sizeof out);assert(n>0);
            uint8_t header[4];wn_put32(header,(uint32_t)n);
            assert(fwrite(header,1,4,stdout)==4 && fwrite(out,1,(size_t)n,stdout)==(size_t)n);
        }
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "wire"))
    {
        char line[WN_CONTROL_MAX+1];size_t n=fread(line,1,sizeof line,stdin);
        assert(feof(stdin));
        struct wg_message m;
        uint8_t data[WG_CHUNK];
        char out[WN_CONTROL_MAX + 1];
        assert(n > 0 && !wn_gossip_read(line, n, &m, data));
        int written=wn_gossip_write(&m,out,sizeof out);assert(written>0);
        assert(fwrite(out,1,(size_t)written,stdout)==(size_t)written);
        return 0;
    }
    if(argc==2 && !strcmp(argv[1],"certificate")){
        char input[WN_CONTROL_MAX+1],out[WN_CONTROL_MAX+1];size_t size=fread(input,1,sizeof input,stdin);
        assert(feof(stdin));struct wn_doc d;assert(!wn_doc_parse(&d,input,size));
        int envelope=wn_doc_member(&d,0,"certificate"),at,n=-1;assert(envelope>=0);
        if((at=wn_doc_member(&d,(unsigned)envelope,"chain"))>=0){
            struct wncf_chain chain;assert(!wncf_chain_read(&d,(unsigned)at,"2558fd76-afc7-466e-9613-6b715296a526",&chain));
            n=wncf_chain_write(&chain,out,sizeof out);
        }else if((at=wn_doc_member(&d,(unsigned)envelope,"request"))>=0){
            struct wncf_request request;assert(!wncf_request_read(&d,(unsigned)at,&request));n=wncf_request_write(&request,out,sizeof out);
        }else if((at=wn_doc_member(&d,(unsigned)envelope,"chunk"))>=0){
            struct wncf_chunk chunk;uint8_t bytes[WNCF_CHUNK];assert(!wncf_chunk_read(&d,(unsigned)at,&chunk,bytes));
            n=wncf_chunk_write(&chunk,bytes,out,sizeof out);
        }
        assert(n>0 && fwrite(out,1,(size_t)n,stdout)==(size_t)n);return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "hash"))
    {
        uint8_t data[WG_OBJECT_MAX + 1], hash[32];
        size_t n = fread(data, 1, sizeof data, stdin);
        assert(feof(stdin) && !wn_gossip_identify(NULL, 1, data, n, hash));
        for (unsigned i = 0; i < 32; i++)
            printf("%02x", hash[i]);
        putchar('\n');
        return 0;
    }
    assert(argc == 1);
    const char *self = "00000000-0000-4000-8000-000000000001";
    const char *peer = "00000000-0000-4000-8000-000000000002";
    char out[WN_CONTROL_MAX + 1];
    uint8_t data[WG_CHUNK], decoded[WG_CHUNK];
    int n = wn_router_hello_write(peer, self, out, sizeof out);
    assert(n > 0 && !wn_router_hello_check(out, n, self, peer));
    assert(wn_hello_check(out, n, self, peer) < 0);
    assert(wn_router_hello_check(out, n, peer, self) < 0);
    n = wn_hello_write(peer, self, out, sizeof out);
    assert(n > 0 && wn_router_hello_check(out, n, self, peer) < 0);
    for (unsigned i = 0; i < WG_CHUNK; i++)
        data[i] = (uint8_t)i;
    for (unsigned op = 0; op < 4; op++)
    {
        struct wg_message m = {.op = (enum wg_op)op, .id.type = 1};
        memset(m.id.hash, 0x9f, 32);
        if (op != WG_HAVE)
            m.request = UINT64_MAX;
        if (op == WG_DATA)
        {
            m.data = data;
            m.size = WG_CHUNK;
            m.offset = WG_CHUNK;
            m.total = WG_OBJECT_MAX;
        }
        n = wn_gossip_write(&m, out, sizeof out);
        assert(n > 0);
        struct wg_message parsed;
        assert(!wn_gossip_read(out, n, &parsed, decoded));
        assert(parsed.op == m.op && parsed.request == m.request &&
               parsed.offset == m.offset && parsed.total == m.total &&
               parsed.size == m.size && !memcmp(parsed.id.hash, m.id.hash, 32));
        if (m.size)
            assert(!memcmp(parsed.data, data, m.size));
        assert(wn_gossip_write(&m, out, 20) < 0);
        m.id.type = 2;
        assert(wn_gossip_write(&m, out, sizeof out) < 0);
    }
    const char *invalid[] = {
        "{\"kind\":\"gossip\",\"gossip\":{\"v\":1,\"op\":\"have\",\"type\":1}}",
        "{\"kind\":\"gossip\",\"gossip\":{\"v\":1,\"op\":\"want\",\"type\":1,"
        "\"digest\":\"n5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn58=\"}}",
        "{\"kind\":\"gossip\",\"gossip\":{\"v\":1,\"op\":\"have\",\"type\":1,"
        "\"digest\":\"n5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn58=\","
        "\"offset\":4294967296}}",
        "{\"kind\":\"gossip\",\"gossip\":{\"v\":1,\"v\":1,\"op\":\"have\","
        "\"type\":1,\"digest\":\"n5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn58="
        "\"}}"};
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; i++)
    {
        struct wg_message parsed;
        assert(wn_gossip_read(invalid[i], strlen(invalid[i]), &parsed,
                              decoded) < 0);
    }
    puts("native router hello and bounded manifest gossip JSON pass");
    return 0;
}
