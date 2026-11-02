/* Ordinary gossip framing round trips, including complete and final chunks. */
#include "wendy_net_control.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void roundtrip(const struct wg_message *message)
{
    char text[WN_CONTROL_MAX + 1];
    uint8_t decoded[WG_CHUNK];
    struct wg_message read;
    int n = wn_gossip_write(message, text, sizeof text);
    assert(n > 0 && (size_t)n <= WN_CONTROL_MAX);
    assert(!wn_gossip_read(text, (size_t)n, &read, decoded));
    assert(read.op == message->op && read.id.type == message->id.type);
    assert(!memcmp(read.id.hash, message->id.hash, 32));
    assert(read.request == message->request && read.offset == message->offset);
    assert(read.total == message->total && read.size == message->size);
    if (read.size)
        assert(!memcmp(read.data, message->data, read.size));
}
/* Each discriminator owns the fields below it, including their CBOR types. */
static void discriminator_extensions(void)
{
    uint8_t wire[256], scratch[WG_CHUNK];
    for (unsigned mode = 0; mode < 8; mode++) {
        struct wn_writer w = {.data = wire, .capacity = sizeof wire, .maximum = sizeof wire};
        wn_map(&w, 2);
        wn_key(&w, "kind");
        wn_text(&w, "gossip");
        wn_key(&w, "gossip");
        wn_map(&w, 4);
        wn_key(&w, "v");
        if (mode == 4)
            wn_text(&w, "not-an-integer");
        else
            wn_uint(&w, mode == 1 ? 2 : 1);
        wn_key(&w, "type");
        if (mode == 1 || mode == 5)
            wn_map(&w, 0); /* A future version may replace the type schema. */
        else
            wn_uint(&w, mode == 0 ? 3 : 1);
        wn_key(&w, "op");
        if (mode == 2)
            wn_text(&w, "");
        else if (mode == 3)
            wn_uint(&w, 7);
        else if (mode == 6)
            wn_text(&w, "have"); /* Known operation with an incompatible body. */
        else if (mode == 7)
            wn_text(&w, "future-operation");
        else
            wn_map(&w, 0);
        wn_key(&w, "data");
        wn_map(&w, 1);
        wn_key(&w, "future-body");
        wn_uint(&w, 42);
        int size = wn_finish(&w);
        assert(size > 0);
        struct wg_message out;
        memset(&out, 0x5a, sizeof out);
        struct wg_message saved = out;
        int expected = mode < 2 || mode == 7 ? 1 : -1;
        assert(wn_gossip_read(wire, (size_t)size, &out, scratch) == expected);
        assert(!memcmp(&saved, &out, sizeof out));
        assert(wn_gossip_read_view(wire, (size_t)size, &out) == expected);
        assert(!memcmp(&saved, &out, sizeof out));
        /* The following current message still decodes normally. */
        struct wg_message known = {.id.type = 1, .op = WG_HAVE};
        memset(known.id.hash, 0x42, sizeof known.id.hash);
        roundtrip(&known);
    }
    /* Required selectors remain mandatory for the version that defines them. */
    const uint8_t missing_version[] = {0xa2, 0x61, 'k',  0x66, 'g',  'o',  's', 's',
                                       'i',  'p',  0x61, 'g',  0xa1, 0x61, 't', 0x01};
    const uint8_t missing_type[] = {0xa2, 0x61, 'k',  0x66, 'g',  'o',  's', 's',
                                    'i',  'p',  0x61, 'g',  0xa1, 0x61, 'v', 0x01};
    struct wg_message out;
    assert(wn_gossip_read(missing_version, sizeof missing_version, &out, scratch) < 0);
    assert(wn_gossip_read(missing_type, sizeof missing_type, &out, scratch) < 0);
}
int main(void)
{
    discriminator_extensions();
    /* A future peer's optional operation has its own body schema. Skip it
     * without attempting to decode that schema as today's DATA format. */
    uint8_t future[256];
    struct wn_writer writer = {.data = future, .capacity = sizeof future, .maximum = sizeof future};
    wn_map(&writer, 2);
    wn_key(&writer, "kind");
    wn_text(&writer, "gossip");
    wn_key(&writer, "gossip");
    wn_map(&writer, 4);
    wn_key(&writer, "v");
    wn_uint(&writer, 1);
    wn_key(&writer, "type");
    wn_uint(&writer, 1);
    wn_key(&writer, "op");
    wn_text(&writer, "future-cache-hint");
    wn_text(&writer, "x");
    wn_map(&writer, 1);
    wn_text(&writer, "m");
    wn_text(&writer, "compact");
    int future_size = wn_finish(&writer);
    assert(future_size > 0);
    struct wg_message skipped;
    uint8_t scratch[WG_CHUNK];
    assert(wn_gossip_read(future, (size_t)future_size, &skipped, scratch) == 1);
    uint8_t bytes[WG_CHUNK];
    for (unsigned i = 0; i < sizeof bytes; i++)
        bytes[i] = (uint8_t)(i * 31 + 7);
    for (unsigned type = 1; type <= 1; type++) {
        struct wg_message m = {.id.type = type};
        memset(m.id.hash, 0x42, 32);
        roundtrip(&m);
        m.op = WG_GONE;
        roundtrip(&m);
        m.op = WG_WANT;
        m.request = 42;
        roundtrip(&m);
        m.op = WG_UNAVAILABLE;
        roundtrip(&m);
        m.op = WG_DATA;
        m.data = bytes;
        m.total = m.size = WG_CHUNK;
        roundtrip(&m);
        m.total = WG_CHUNK + 1;
        roundtrip(&m);
        m.offset = WG_CHUNK;
        m.size = 1;
        roundtrip(&m);
    }
    puts("Normal gossip encoding round trips passed");
    return 0;
}
