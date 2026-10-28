/* An old TLS loan can finish while a new service epoch is already active. */
#include "wendy_pki_tls_input.h"
#include "wendy_net_memory.h"
#include <assert.h>
int main(void)
{
    wendy_net_memory_t first=WENDY_NET_MEMORY_INITIALIZER;
    wendy_net_memory_t second=WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&first,65536,false));
    assert(wendy_net_memory_open(&second,65536,false));
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&first,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    unsigned char *loan=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(loan);
    wendy_pki_input_workspace_active(false);wendy_net_memory_scope_leave(previous);
    wendy_net_memory_close(&first);assert(!wendy_net_memory_drained(&first));
    previous=wendy_net_memory_scope_enter(&second,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true); /* Waits for the outstanding old loan. */
    wendy_net_memory_scope_leave(previous);
    pki_tls_input_return(loan,PKI_TLS_INPUT_RESERVE);
    assert(wendy_net_memory_drained(&first));
    assert(!wendy_pki_input_workspace_cached_bytes());
    previous=wendy_net_memory_scope_enter(&second,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
    pki_tls_input_discard_cached();wendy_net_memory_scope_leave(previous);
    /* An unrelated baseline caller cannot refill a service owner's workspace. */
    wendy_pki_input_workspace_active(true);
    assert(!wendy_pki_input_workspace_cached_bytes());
    previous=wendy_net_memory_scope_enter(&second,WENDY_NET_MEMORY_INTERNAL);
    wendy_pki_input_workspace_active(true);
    size_t capacity=0;loan=wendy_pki_input_workspace_borrow(&capacity);
    assert(loan && capacity==PKI_TLS_INPUT_RESERVE);
    wendy_pki_input_workspace_release(loan);
    wendy_pki_input_workspace_active(false);wendy_net_memory_scope_leave(previous);
    wendy_net_memory_close(&second);assert(wendy_net_memory_drained(&second));
    return 0;
}
