/* Matching native service metadata, local guest JSON and inherited leases. */
#include "wendy_net_service_protocol.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int service(struct wn_writer *w, unsigned id)
{
    char name[32];
    snprintf(name, sizeof name, "room.%u", id);
    wn_map(w, 7);
    wn_key(w, "a");
    wn_text(w, "app.test");
    wn_key(w, "m");
    wn_text(w, "default.lan");
    wn_key(w, "s");
    wn_text(w, name);
    wn_key(w, "n");
    wn_text(w, "Room");
    wn_key(w, "t");
    wn_text(w, "_sensor._tcp");
    wn_key(w, "p");
    wn_uint(w, 7000 + id);
    wn_key(w, "x");
    wn_array(w, 1);
    wn_text(w, "unit=celsius");
    return 0;
}
static int services(unsigned count, bool repeat, char *out, size_t cap)
{
    struct wn_writer w = {.data = (uint8_t *)out, .capacity = cap, .maximum = WN_MANIFEST_BODY_MAX};
    wn_map(&w, 1);
    wn_key(&w, "services");
    wn_array(&w, count);
    for (unsigned i = 0; i < count; i++)
        service(&w, repeat ? 0 : i);
    return wn_finish(&w);
}
static void optional_service_rows(void)
{
    char wire[2048];
    struct wn_writer w = {.data = (uint8_t *)wire, .capacity = sizeof wire, .maximum = sizeof wire};
    wn_map(&w, 1);
    wn_text(&w, "s");
    wn_array(&w, 3);
    service(&w, 0);
    for (unsigned i = 0; i < 2; i++) {
        wn_map(&w, i ? 4 : 5);
        wn_text(&w, "m");
        wn_text(&w, "default");
        wn_text(&w, "a");
        wn_text(&w, i ? "wendy.mesh.system" : "app.test");
        wn_text(&w, "s");
        wn_text(&w, i ? "future-gateway" : "future-stream");
        if (!i) {
            wn_text(&w, "t");
            wn_text(&w, "_sensor._sctp");
        }
        wn_text(&w, "p");
        wn_map(&w, 0); /* Opaque future payload shape. */
    }
    int n = wn_finish(&w);
    struct wn_doc d, child;
    assert(n > 0 && !wn_doc_parse_array_view(&d, wire, (size_t)n, sizeof wire, "s"));
    assert(!wns_manifest_services_validate(&d, 0));
    int array = wn_doc_member(&d, 0, "s");
    size_t cursor = 0;
    struct wns_record record;
    assert(wn_doc_array_next(&d, array, &cursor, &child) == 1 &&
           !wns_manifest_service_read(&child, &record));
    for (unsigned i = 0; i < 2; i++)
        assert(wn_doc_array_next(&d, array, &cursor, &child) == 1 &&
               wns_manifest_service_read(&child, &record) == WNS_UNSUPPORTED);
    assert(!wn_doc_array_next(&d, array, &cursor, &child));
}
int main(void)
{
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    assert(wendy_net_runtime_memory_open());
#endif
    optional_service_rows();
    const char json[] =
        "{\"serviceId\":\"room.temperature\",\"type\":\"_sensor._tcp\",\"instance\":\"Room\",\"port\":7000,\"txt\":[\"unit=celsius\"]}";
    char *binary = NULL;
    size_t bytes = 0;
    assert(!wns_spec_from_json(json, sizeof json - 1, &binary, &bytes));
    struct wns_record record;
    assert(!wns_spec_read(binary, bytes, &record));
    assert(!strcmp(record.service, "room.temperature") && record.port == 7000);
    char txt[256];
    assert(wns_record_txt(&record, 0, txt, sizeof txt) == 12 && !strcmp(txt, "unit=celsius"));
    /* Optional future CBOR fields do not change this service's known view. */
    char extended[2048];
    assert(bytes > 0 && (uint8_t)binary[0] == 0xa5 && bytes < sizeof extended);
    memcpy(extended, binary, bytes);
    extended[0] = (char)0xa6;
    struct wn_writer extension = {.data = (uint8_t *)extended,
                                  .capacity = sizeof extended,
                                  .maximum = sizeof extended,
                                  .size = bytes};
    wn_text(&extension, "z");
    wn_array(&extension, 2);
    wn_bool(&extension, true);
    wn_map(&extension, 1);
    wn_text(&extension, "future");
    wn_uint(&extension, 9);
    int extended_size = wn_finish(&extension);
    assert(extended_size > 0 && !wns_spec_read(extended, (size_t)extended_size, &record));
    assert(!strcmp(record.service, "room.temperature") && record.port == 7000 &&
           record.txt_count == 1);
    free(binary);
    assert(wns_label_valid("room.temperature") && wns_label_valid("room_1"));
    assert(wns_type_valid("_-sensor._udp") && wns_type_valid("_sensor._tcp"));
    assert(!wns_label_valid("Room") && !wns_type_valid("_Sensor._tcp"));
    assert(wns_app_id_valid("APP_1.example") && !wns_app_id_valid(".."));
    char wire[WN_MANIFEST_BODY_MAX];
    struct wn_doc doc;
    for (unsigned count = 0; count <= 256; count = count ? count * 2 : 1) {
        int n = services(count, false, wire, sizeof wire);
        assert(n > 0);
        assert(!wn_doc_parse_array_view(&doc, wire, (size_t)n, sizeof wire, "services"));
        assert(!wns_manifest_services_validate(&doc, 0));
        if (count == 256)
            break;
    }
    int n = services(2, true, wire, sizeof wire);
    assert(n > 0);
    assert(!wn_doc_parse_array_view(&doc, wire, (size_t)n, sizeof wire, "services"));
    assert(wns_manifest_services_validate(&doc, 0) < 0);
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_runtime_memory_close();
    assert(wendy_net_runtime_memory_drained());
#endif
    puts(
        "Shared service schema: local text API, compact CBOR, 256 entries and exact identity uniqueness");
}
