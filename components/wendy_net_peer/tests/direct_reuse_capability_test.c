#include "wendy_net_control.h"
#include "wendy_net_direct_wire.h"
#include <assert.h>

int main(void)
{
    uint32_t old = UINT32_C(1) | WN_DIRECT_CAP_TLS;
    uint32_t reuse = WN_DIRECT_CAP_VERSION | WN_DIRECT_CAP_TLS;
    assert(wn_direct_capability_negotiate(reuse, reuse) == reuse);
    assert(!wn_direct_capability_negotiate(reuse, old));
    assert(!wn_direct_capability_negotiate(old, reuse));
    assert(wn_direct_selected_transport(reuse) == reuse);
    bool deferred;
    assert(wn_direct_carrier_negotiate(reuse, 0, reuse, 0, &deferred) == reuse && !deferred);
    assert(wn_direct_carrier_negotiate(0, reuse, reuse, 0, &deferred) == reuse && deferred);
    assert(wn_direct_carrier_negotiate(reuse, 0, 0, reuse, &deferred) == reuse && deferred);
    assert(wn_direct_carrier_negotiate(0, reuse, 0, reuse, &deferred) == reuse && deferred);
    assert(!wn_direct_carrier_negotiate(reuse, 0, old, 0, &deferred) && !deferred);
    const char *a = "24fb93e3-4d53-47fa-ba6a-3e2747045496",
               *b = "7cd512eb-eb0c-4f68-b752-148e804e3d11";
    char wire[512];
    uint32_t selected = 0;
    int n = wn_router_hello_write_deferred(a, b, wire, sizeof wire, 0, reuse);
    assert(n > 0);
    assert(!wn_router_hello_check_deferred(wire, (size_t)n, b, a, reuse, 0, &selected, &deferred));
    assert(selected == reuse && deferred);
    assert(!wn_router_hello_check_direct(wire, (size_t)n, b, a, 0, &selected) && !selected);
    n = wn_operator_ready_write_deferred(wire, sizeof wire, reuse, true);
    assert(n > 0);
    struct wn_doc doc;
    uint64_t value = 0;
    assert(!wn_doc_parse(&doc, wire, (size_t)n));
    assert(wn_doc_member(&doc, 0, "direct") < 0);
    assert(!wn_doc_u64(&doc, wn_doc_member(&doc, 0, "directDeferred"), &value) && value == reuse);
    return 0;
}
