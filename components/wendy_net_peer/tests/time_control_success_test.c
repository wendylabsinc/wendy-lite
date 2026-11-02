#include "../src/time_control.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void emit_frame(const void *data, size_t size)
{
    uint8_t header[4];
    wn_put32(header, (uint32_t)size);
    assert(fwrite(header, 1, 4, stdout) == 4 && fwrite(data, 1, size, stdout) == size);
}
int main(int argc, char **argv)
{
    bool emit = argc == 2 && !strcmp(argv[1], "--wire");
    uint8_t query[93];
    for (size_t i = 0; i < sizeof query; i++)
        query[i] = (uint8_t)i;
    struct wnt_job *client = wnt_new(42, query, sizeof query, 30000);
    assert(client);
    char wire[1600];
    int size = wnt_request_write(client, wire, sizeof wire);
    assert(size > 0);
    if (emit)
        emit_frame(wire, (size_t)size);
    struct wn_doc doc;
    assert(!wn_doc_parse(&doc, wire, (size_t)size));
    int at = wn_doc_member(&doc, 0, "time");
    assert(at >= 0 && wnt_version_supported(&doc, (unsigned)at));
    uint64_t version;
    assert(!wn_doc_u64(&doc, wn_doc_member(&doc, (unsigned)at, "v"), &version) && version == 1);
    struct wnt_job *server = wnt_request_read(&doc, (unsigned)at, 30000);
    assert(server);
    assert(server->query_size == sizeof query && !memcmp(server->query, query, sizeof query));
    server->size = 17 * 1024 + 41;
    server->reply = malloc(server->size);
    assert(server->reply);
    for (size_t i = 0; i < server->size; i++)
        server->reply[i] = (uint8_t)(i * 31 + 7);
    server->result = 0;
    /* A future operation without today's id/total/data is ignored, preserving
     * the active request. Known malformed replies still fail validation. */
    struct wn_writer future = {
        .data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
    wn_map(&future, 1);
    wn_key(&future, "op");
    wn_text(&future, "future-progress");
    size = wn_finish(&future);
    assert(size > 0 && !wn_doc_parse(&doc, wire, (size_t)size));
    assert(!wnt_reply_read(client, &doc, 0));
    assert(!atomic_load(&client->done) && !client->reply && !client->offset);
    future = (struct wn_writer){
        .data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
    wn_map(&future, 2);
    wn_key(&future, "op");
    wn_text(&future, "reply");
    wn_key(&future, "id");
    wn_uint(&future, client->id);
    size = wn_finish(&future);
    assert(size > 0 && !wn_doc_parse(&doc, wire, (size_t)size));
    assert(wnt_reply_read(client, &doc, 0) < 0);
    assert(!atomic_load(&client->done) && !client->reply && !client->offset);
    /* Unsupported versions are independent of today's operation schema. */
    future = (struct wn_writer){
        .data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
    wn_map(&future, 2);
    wn_key(&future, "op");
    wn_map(&future, 1);
    wn_key(&future, "future-shape");
    wn_uint(&future, 7);
    wn_key(&future, "v");
    wn_uint(&future, 2);
    size = wn_finish(&future);
    assert(size > 0 && !wn_doc_parse(&doc, wire, (size_t)size));
    assert(!wnt_version_supported(&doc, 0));
    assert(!wnt_reply_read(client, &doc, 0));
    assert(!wnt_request_read(&doc, 0, 30000));
    assert(!atomic_load(&client->done) && !client->reply && !client->offset);
    /* Old senders omit v or leave its scalar zero; both retain version1. */
    for (unsigned legacy = 0; legacy < 3; legacy++) {
        future = (struct wn_writer){
            .data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
        wn_map(&future, legacy ? 4 : 3);
        if (legacy) {
            wn_key(&future, "v");
            wn_uint(&future, legacy - 1);
        }
        wn_key(&future, "op");
        wn_text(&future, "request");
        wn_key(&future, "id");
        wn_uint(&future, 42);
        wn_key(&future, "data");
        wn_bytes(&future, query, sizeof query);
        size = wn_finish(&future);
        assert(size > 0 && !wn_doc_parse(&doc, wire, (size_t)size));
        assert(wnt_version_supported(&doc, 0));
        struct wnt_job *old = wnt_request_read(&doc, 0, 30000);
        assert(old && old->id == 42 && old->query_size == sizeof query &&
               !memcmp(old->query, query, sizeof query));
        wnt_release(old);
    }
    while (!atomic_load(&client->done)) {
        size = wnt_reply_write(server, wire, sizeof wire);
        assert(size > 0);
        if (emit)
            emit_frame(wire, (size_t)size);
        assert(!wn_doc_parse(&doc, wire, (size_t)size));
        at = wn_doc_member(&doc, 0, "time");
        assert(!wnt_reply_read(client, &doc, (unsigned)at));
        size_t piece = server->size - server->offset;
        if (piece > 1024)
            piece = 1024;
        server->offset += piece;
        if (!atomic_load(&client->done)) {
            size = wnt_request_write(client, wire, sizeof wire);
            assert(size > 0);
            if (emit)
                emit_frame(wire, (size_t)size);
            assert(!wn_doc_parse(&doc, wire, (size_t)size));
            at = wn_doc_member(&doc, 0, "time");
            assert(wn_doc_equal(&doc, wn_doc_member(&doc, (unsigned)at, "op"), "next"));
            uint64_t offset;
            assert(!wn_doc_u64(&doc, wn_doc_member(&doc, (unsigned)at, "offset"), &offset));
            assert(offset == server->offset);
        }
    }
    assert(!client->result && client->size == server->size &&
           !memcmp(client->reply, server->reply, server->size));
    wnt_retain(server);
    wnt_release(server);
    wnt_release(server);
    wnt_release(client);
    if (!emit)
        puts("normal 17449-byte timestamp reply pulled intact over bounded control frames");
    return 0;
}
