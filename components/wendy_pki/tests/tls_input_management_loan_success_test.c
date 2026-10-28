/* Ordinary baseline TLS borrowing one idle mesh-owned input allocation. */
#include "wendy_pki_tls_input.h"
#include "wendy_net_memory.h"
#include <assert.h>
#include <string.h>
int main(void)
{
    wendy_net_memory_t mesh=WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&mesh,65536,false));
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&mesh,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_snapshot_t state;wendy_net_memory_snapshot(&mesh,&state);
    assert(state.current_bytes==wendy_net_memory_charge(PKI_TLS_INPUT_RESERVE));
    assert(state.allocation_count==1);
    size_t capacity=99;
    assert(!wendy_pki_input_workspace_borrow(&capacity) && !capacity); /* DER remains exact-owner. */
    unsigned char *management=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(management);
    memset(management,42,1024);
    assert(!wendy_pki_input_workspace_cached_bytes());
    /* Other baseline TLS allocations have no mesh owner. */
    void *other=wendy_net_memory_scoped_calloc(1,1024);assert(other);
    wendy_net_memory_snapshot(&mesh,&state);
    assert(state.current_bytes==wendy_net_memory_charge(PKI_TLS_INPUT_RESERVE) && state.allocation_count==1);
    wendy_pki_input_workspace_active(false);wendy_net_memory_close(&mesh);
    assert(!wendy_net_memory_drained(&mesh)); /* Management loan still owns mesh bytes. */
    pki_tls_input_return(management,PKI_TLS_INPUT_RESERVE);
    assert(wendy_net_memory_drained(&mesh));
    wendy_net_memory_snapshot(&mesh,&state);assert(!state.current_bytes && !state.allocation_count);
    wendy_net_memory_scoped_free(other);
    assert(!wendy_pki_input_workspace_cached_bytes());

    /* Management begins while mesh is off. Enabling during its handshake
     * must not reserve another input buffer, or adopt uncharged baseline RAM. */
    management=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(management);
    wendy_net_memory_t restarted=WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&restarted,65536,false));
    previous=wendy_net_memory_scope_enter(&restarted,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    wendy_pki_input_workspace_active(true);
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_snapshot(&restarted,&state);
    assert(!state.current_bytes && !state.allocation_count);
    assert(!wendy_pki_input_workspace_cached_bytes());
    pki_tls_input_return(management,PKI_TLS_INPUT_RESERVE);
    assert(!wendy_pki_input_workspace_cached_bytes());
    wendy_net_memory_snapshot(&restarted,&state);
    assert(!state.current_bytes && !state.allocation_count);
    /* Only the actor refills, charging the reserve to its real owner. */
    previous=wendy_net_memory_scope_enter(&restarted,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    wendy_net_memory_scope_leave(previous);
    wendy_net_memory_snapshot(&restarted,&state);
    assert(state.current_bytes==wendy_net_memory_charge(PKI_TLS_INPUT_RESERVE));
    assert(state.allocation_count==1);
    management=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(management);
    wendy_pki_input_workspace_active(false);wendy_net_memory_close(&restarted);
    assert(!wendy_net_memory_drained(&restarted));
    pki_tls_input_return(management,PKI_TLS_INPUT_RESERVE);
    assert(wendy_net_memory_drained(&restarted));
    assert(!wendy_pki_input_workspace_cached_bytes());
    return 0;
}
