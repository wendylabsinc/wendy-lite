#include "wendy_net_binary.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void message(struct wn_writer *writer)
{
    const unsigned char bytes[] = {0, 0x7f, 0xff};
    wn_map(writer, 3);
    wn_key(writer, "data"); wn_bytes(writer, bytes, sizeof bytes);
    wn_key(writer, "kind"); wn_text(writer, "hello");
    wn_key(writer, "v"); wn_uint(writer, 2);
}
int main(void)
{
    const unsigned char expected[] = {
        0xa3, 0x61, 'd', 0x43, 0, 0x7f, 0xff,
        0x61, 'k', 0x65, 'h', 'e', 'l', 'l', 'o', 0x61, 'v', 2
    };
    struct wn_writer measured = {.maximum = 256};
    message(&measured);
    assert(wn_finish(&measured) == sizeof expected);
    unsigned char buffer[128];
    struct wn_writer writer = {.data=buffer,.capacity=sizeof buffer,.maximum=256};
    message(&writer);
    assert(wn_finish(&writer) == sizeof expected);
    assert(!memcmp(buffer,expected,sizeof expected) && !buffer[sizeof expected]);

    writer = (struct wn_writer){.data=buffer,.capacity=sizeof expected,.maximum=256};
    message(&writer);
    assert(wn_finish(&writer) == sizeof expected); /* Exact-sized output. */
    writer = (struct wn_writer){.data=buffer,.capacity=sizeof expected-1,.maximum=256};
    message(&writer);
    assert(wn_finish(&writer) == -1); /* Caller retries after sizing. */
    writer = (struct wn_writer){.maximum=sizeof expected-1};
    message(&writer);
    assert(wn_finish(&writer) == -1);

    const unsigned char integers[] = {
        0x87, 0x17, 0x18, 0x18, 0x18, 0xff, 0x19, 1, 0,
        0x1a, 0, 1, 0, 0, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0, 0xf5
    };
    writer = (struct wn_writer){.data=buffer,.capacity=sizeof buffer,.maximum=sizeof buffer};
    wn_array(&writer,7);
    wn_uint(&writer,23); wn_uint(&writer,24); wn_uint(&writer,255);
    wn_uint(&writer,256); wn_uint(&writer,65536); wn_uint(&writer,UINT64_C(4294967296));
    wn_bool(&writer,true);
    assert(wn_finish(&writer) == sizeof integers && !memcmp(buffer,integers,sizeof integers));
    assert(!strcmp(wn_key_name("operatorCertificate"),"O"));
    assert(!strcmp(wn_key_name("futureField"),"futureField"));
    assert(!strcmp(wn_key_name("v"),"v"));
    puts("CBOR writer: exact wire bytes, shortest integers and bounded sizing passed");
    return 0;
}
