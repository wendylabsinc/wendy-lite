/* Real production TLS with a native-mesh owner that follows the connection
 * after setup returns to the ordinary shared management/com caller scope. */
#include "wendy_pki_internal.h"
#include <mbedtls/platform.h>
#include <assert.h>
#include <stdio.h>

static wendy_net_memory_t mesh_memory=WENDY_NET_MEMORY_INITIALIZER;
static bool baseline_lan,record_operation;
static unsigned record_allocations,connections;
static void *scoped_library_calloc(size_t count,size_t bytes)
{
    if(record_operation){
        assert(wendy_net_memory_scope_current().owner==(baseline_lan ? NULL:&mesh_memory));
        record_allocations++;
    }
    return wendy_net_memory_scoped_calloc(count,bytes);
}
static int scoped_accept_owned(int *fd,struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,const char *tenant,const char *device,
    wendy_pki_connection **out,int64_t deadline)
{
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(
        baseline_lan ? NULL:&mesh_memory,WENDY_NET_MEMORY_INTERNAL);
    int result=pki_tls_accept_owned(fd,owned,roots,tenant,device,out,deadline);
    wendy_net_memory_scope_leave(previous);
    if(!result){
        assert((*out)->allocation_scope.owner==(baseline_lan ? NULL:&mesh_memory));
        connections++;
    }
    return result;
}
static int scoped_accept_owned_stream(const struct wendy_pki_stream *stream,
    struct pki_tls_owned_identity *owned,struct wendy_conf_span roots,
    const char *tenant,const char *device,wendy_pki_connection **out,int64_t deadline)
{
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(
        baseline_lan ? NULL:&mesh_memory,WENDY_NET_MEMORY_INTERNAL);
    int result=pki_tls_accept_owned_stream(stream,owned,roots,tenant,device,out,deadline);
    wendy_net_memory_scope_leave(previous);
    if(!result){
        assert((*out)->allocation_scope.owner==(baseline_lan ? NULL:&mesh_memory));
        connections++;
    }
    return result;
}
static ssize_t scoped_read(void *connection,void *bytes,size_t size)
{
    wendy_net_memory_scope_t caller=wendy_net_memory_scope_current();
    assert(!caller.owner);
    record_operation=true;
    ssize_t result=wendy_pki_read(connection,bytes,size);
    record_operation=false;
    assert(wendy_net_memory_scope_current().owner==caller.owner);
    return result;
}
static ssize_t scoped_write(void *connection,const void *bytes,size_t size)
{
    wendy_net_memory_scope_t caller=wendy_net_memory_scope_current();
    assert(!caller.owner);
    record_operation=true;
    ssize_t result=wendy_pki_write(connection,bytes,size);
    record_operation=false;
    assert(wendy_net_memory_scope_current().owner==caller.owner);
    return result;
}
static void scoped_close(wendy_pki_connection *connection)
{
    wendy_net_memory_scope_t caller=wendy_net_memory_scope_current();
    assert(!caller.owner);
    wendy_pki_close(connection);
    assert(wendy_net_memory_scope_current().owner==caller.owner);
}

#define pki_tls_accept_owned scoped_accept_owned
#define pki_tls_accept_owned_stream scoped_accept_owned_stream
#define wendy_pki_read scoped_read
#define wendy_pki_write scoped_write
#define wendy_pki_close scoped_close
#define main normal_tls_adapter_main
#include "tls_test.c"
#undef main
#undef pki_tls_accept_owned
#undef pki_tls_accept_owned_stream
#undef wendy_pki_read
#undef wendy_pki_write
#undef wendy_pki_close

int main(int argc,char **argv)
{
    assert(getenv("WENDY_TLS_NORMAL_ONLY") && getenv("WENDY_TLS_OWNED_STREAM"));
    baseline_lan=getenv("WENDY_TLS_SCOPE_LAN_BASELINE")!=NULL;
    assert(wendy_net_memory_open(&mesh_memory,1024*1024,false));
    assert(!mbedtls_platform_set_calloc_free(scoped_library_calloc,wendy_net_memory_scoped_free));
    int result=normal_tls_adapter_main(argc,argv);
    assert(!result && connections && record_allocations);
    wendy_net_memory_snapshot_t state;wendy_net_memory_snapshot(&mesh_memory,&state);
    assert(!state.current_bytes && !state.allocation_count && !state.reservation_count);
    if(baseline_lan)assert(!state.high_water_bytes);
    else assert(state.high_water_bytes);
    wendy_net_memory_close(&mesh_memory);
    assert(wendy_net_memory_drained(&mesh_memory));
    fprintf(stderr,"normal native management scope: mesh=%u connections=%u record_allocations=%u peak=%zu drained=1\n",
        !baseline_lan,connections,record_allocations,state.high_water_bytes);
    return result;
}
