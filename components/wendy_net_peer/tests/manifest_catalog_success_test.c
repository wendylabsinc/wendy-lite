/* Normal complete-manifest service publication, replacement and guest browse. */
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned changes;
static void changed(void *context)
{
    (void)context;
    changes++;
}
static uint64_t next_hop(void *context, const uint8_t device[16], uint64_t exclude)
{
    (void)context;
    (void)device;
    (void)exclude;
    return 1;
}
static struct wnsc_node *open_node(const char *device)
{
    struct wnsc_config config = {.tenant = "11111111-1111-4111-8111-111111111111",
                                 .device = device,
                                 .services_changed = changed,
                                 .next_hop = next_hop};
    struct wnsc_node *node = NULL;
    assert(!wnsc_open(&node, &config));
    return node;
}
static char *body(struct wnsc_node *node, uint64_t revision, int64_t issued)
{
    int size = wnsc_services_write(node, NULL, 0);
    assert(size > 0);
    char *array = malloc((size_t)size + 1);
    assert(array);
    assert(wnsc_services_write(node, array, (size_t)size + 1) == size);
    struct wn_origin origin = {.router_id = 42, .seqno = 7};
    int bytes =
        wn_manifest_services_write(node->self, &origin, revision, issued, issued + 900000, 5054,
                                   43022, "Test ESP", true, array, (size_t)size, NULL, 0);
    assert(bytes > 0);
    char *out = malloc((size_t)bytes + 1);
    assert(out);
    assert(wn_manifest_services_write(node->self, &origin, revision, issued, issued + 900000, 5054,
                                      43022, "Test ESP", true, array, (size_t)size, out,
                                      (size_t)bytes + 1) == bytes);
    free(array);
    return out;
}
static void import(struct wnsc_node *to, struct wnsc_node *from, const char *bytes,
                   uint64_t revision, int64_t issued, int64_t deadline_us, bool withdraw)
{
    /* Measure this manifest again; binary CBOR is not NUL-delimited text. */
    int size = wnsc_services_write(from, NULL, 0);
    char *array = malloc((size_t)size + 1);
    assert(array);
    assert(wnsc_services_write(from, array, (size_t)size + 1) == size);
    struct wn_origin origin = {42, 7};
    int count =
        wn_manifest_services_write(from->self, &origin, revision, issued, issued + 900000, 5054,
                                   43022, "Test ESP", true, array, (size_t)size, NULL, 0);
    free(array);
    struct wn_doc *doc = malloc(sizeof *doc);
    assert(doc);
    assert(!wn_doc_parse_array_view(doc, bytes, (size_t)count, WN_MANIFEST_BODY_MAX, "services"));
    assert(!wns_manifest_services_validate(doc, 0));
    assert(
        !wnsc_manifest_services(to, doc, 0, from->self, revision, issued, issued + 900000, deadline_us, withdraw));
    free(doc);
}
int main(void)
{
    struct wnsc_node *origin = open_node("22222222-2222-4222-8222-222222222222");
    struct wnsc_node *viewer = open_node("33333333-3333-4333-8333-333333333333");
    struct wns_record *r = calloc(1, sizeof *r);
    assert(r);
    strcpy(r->app, WNS_GUEST_APP_ID);
    strcpy(r->service, "temperature");
    strcpy(r->type, "_sensorlink._tcp");
    strcpy(r->instance, "Room");
    r->port = 28080;
    r->issued = 1700000000000;
    r->expires = r->issued + 900000;
    const char *txt[] = {"format=f32le", "channel=42"};
    r->txt_count = 2;
    assert(!wnsc_publish(origin, r, txt, r->issued, 0));
    assert(changes == 1);
    assert(!wnsc_publish(origin, r, txt, r->issued + 30000, 30000));
    assert(changes == 1);
    strcpy(r->service, "humidity");
    r->port = 28081;
    assert(!wnsc_publish(origin, r, txt, r->issued + 60000, 60000));
    assert(changes == 2);
    char *wire = body(origin, 7, r->issued);
    import(viewer, origin, wire, 7, r->issued, 900001000, false);
    free(wire);
    assert(viewer->records.count == 2);
    wnsc_prune(origin, 900001001);
    for (struct wns_entry *own = origin->records.entries; own; own = own->next)
        assert(own->wire);
    for (struct wns_entry *e = viewer->records.entries; e; e = e->next) {
        assert(e->generation == 7 && e->expires == r->expires);
    }
    struct wns_record *projected = malloc(sizeof *projected);
    assert(projected);
    assert(!wnsc_entry_record(viewer, viewer->records.entries, r->issued, projected));
    assert(projected->issued == r->issued);
    free(projected);
    char browse[4096];
    int n = wnsc_browse(viewer, "_sensorlink._tcp", 1001, browse, sizeof browse);
    assert(n > 0 && (size_t)n < sizeof browse && strstr(browse, "Room") &&
           strstr(browse, "format=f32le"));
    wnsc_prune(viewer, 900001000);
    assert(!viewer->records.count);
    r->withdraw = true;
    assert(!wnsc_publish(origin, r, NULL, r->issued + 1, 1));
    wire = body(origin, 8, r->issued + 1000);
    import(viewer, origin, wire, 8, r->issued + 1000, 1000001000, false);
    free(wire);
    assert(viewer->records.count == 1);
    struct wns_entry *e = viewer->records.entries;
    assert(!strcmp(wns_entry_service(e), "temperature") && e->generation == 8 &&
           e->expires == r->expires + 1000);
    /* Receipt time is independent of the signed wall timestamps. A delayed
     * duplicate projection cannot renew the first local deadline. */
    assert(e->deadline_us == 1000001000);
    wire = body(origin, 8, r->issued + 1000);
    import(viewer, origin, wire, 8, r->issued + 1000, 2000001000, false);
    free(wire);
    assert(viewer->records.entries->deadline_us == 1000001000);
    assert(wnsc_browse_endpoints(viewer, "_sensorlink._tcp", 1000000999, browse,
                                sizeof browse) > 2);
    assert(wnsc_browse_endpoints(viewer, "_sensorlink._tcp", 1000001000, browse,
                                sizeof browse) == 2);
    wnsc_prune(viewer, 1000001000);
    assert(!viewer->records.count && !viewer->records.bytes && !viewer->records.entries);

    /* Supersession replaces the old receipt and omission set immediately;
     * a complete withdrawal clears every derived summary at acceptance. */
    wire = body(origin, 9, r->issued + 1000);
    import(viewer, origin, wire, 9, r->issued + 1000, 2100000000, false);
    free(wire);
    assert(viewer->records.entries->deadline_us == 2100000000);
    wire = body(origin, 10, r->issued + 1000);
    import(viewer, origin, wire, 10, r->issued + 1000, 2100000000, true);
    free(wire);
    assert(!viewer->records.count && !viewer->records.bytes);

    /* Idle short-lived foreign publications must release every full summary
     * and wire allocation on each expiry, rather than linger until a cert's
     * much later date. Higher revisions can populate a fresh local lifetime. */
    for (unsigned cycle = 0; cycle < 300; cycle++) {
        int64_t now = INT64_C(2000000000) + (int64_t)cycle * 2000;
        wire = body(origin, 11 + cycle, r->issued + 1000);
        import(viewer, origin, wire, 11 + cycle, r->issued + 1000, now + 1000, false);
        free(wire);
        assert(viewer->records.count == 1 && viewer->records.bytes > 0);
        assert(wnsc_browse(viewer, "_sensorlink._tcp", now + 999, browse, sizeof browse) > 2);
        wnsc_prune(viewer, now + 999);
        assert(viewer->records.count == 1);
        wnsc_prune(viewer, now + 1000);
        assert(!viewer->records.count && !viewer->records.bytes && !viewer->records.entries);
    }

    /* Signed own publication lifetime expires while local listener intent is
     * retained for a future publication. Repeated commit cannot reset it. */
    wnsc_manifest_committed(origin, 400, r->issued, r->expires, 3000000000);
    wnsc_manifest_committed(origin, 400, r->issued, r->expires, 4000000000);
    assert(origin->records.entries->deadline_us == 3000000000);
    assert(wnsc_browse(origin, "_sensorlink._tcp", 2999999999, browse, sizeof browse) > 2);
    assert(wnsc_browse(origin, "_sensorlink._tcp", 3000000000, browse, sizeof browse) == 2);
    wnsc_prune(origin, 3000000000);
    assert(origin->records.count == 1 && origin->records.entries->wire);
    wnsc_manifest_committed(origin, 401, r->issued, r->expires, 4000000000);
    assert(wnsc_browse(origin, "_sensorlink._tcp", 3000000000, browse, sizeof browse) > 2);
    /* A trust-policy transition revokes only the selected foreign owner,
     * releasing its complete projection immediately before the local TTL.
     * Other foreign claims and local intent retain their bytes and lifetime. */
    struct wnsc_node *second = open_node("44444444-4444-4444-8444-444444444444");
    r->withdraw = false;
    assert(!wnsc_publish(second, r, txt, r->issued, 0));
    assert(!wnsc_publish(viewer, r, txt, r->issued, 0));
    wnsc_manifest_committed(viewer, 500, r->issued, r->expires, 6000000000);
    wire = body(origin, 500, r->issued);
    import(viewer, origin, wire, 500, r->issued, 6000000000, false);
    free(wire);
    wire = body(second, 500, r->issued);
    import(viewer, second, wire, 500, r->issued, 6000000000, false);
    free(wire);
    assert(viewer->records.count == 3);
    struct wns_entry *revoked = wns_store_find(&viewer->records, origin->self,
                                               WNS_GUEST_APP_ID, "temperature");
    struct wns_entry *retained = wns_store_find(&viewer->records, second->self,
                                                WNS_GUEST_APP_ID, "humidity");
    struct wns_entry *local = wns_store_find(&viewer->records, viewer->self,
                                             WNS_GUEST_APP_ID, "humidity");
    assert(revoked && retained && local && local->own);
    size_t revoked_bytes = sizeof *revoked + strlen(revoked->key) +
                           strlen(wns_entry_service(revoked)) +
                           strlen(wns_entry_type(revoked)) + 3 + revoked->wire_size;
    size_t before_revoke = viewer->records.bytes;
    wnsc_revoke_owner(viewer, origin->self);
    assert(viewer->records.count == 2 && viewer->records.bytes == before_revoke - revoked_bytes);
    assert(!wns_store_find(&viewer->records, origin->self, WNS_GUEST_APP_ID, "temperature"));
    assert(wns_store_find(&viewer->records, second->self, WNS_GUEST_APP_ID, "humidity") == retained);
    assert(wns_store_find(&viewer->records, viewer->self, WNS_GUEST_APP_ID, "humidity") == local);
    assert(retained->wire && local->wire && retained->deadline_us == 6000000000);
    size_t retained_bytes = viewer->records.bytes;
    wnsc_revoke_owner(viewer, origin->self);
    wnsc_revoke_owner(viewer, viewer->self);
    wnsc_revoke_owner(viewer, NULL);
    wnsc_revoke_owner(NULL, origin->self);
    assert(viewer->records.count == 2 && viewer->records.bytes == retained_bytes);
    wnsc_close(second);
    free(r);
    wnsc_close(origin);
    wnsc_close(viewer);
    puts(
        "complete manifest: two services, common lease, idempotent source, omission and guest browse PASS");
    return 0;
}
