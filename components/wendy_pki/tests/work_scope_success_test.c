/* Normal mesh/management submissions retain their initiating allocation owner. */
#include "wendy_pki_work.h"
#include "wendy_net_memory.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>

struct request {
    wendy_net_memory_t *expected;
    wendy_net_memory_placement_t placement;
    void *buffer;
    atomic_bool complete;
};
static atomic_bool stopping;
static void allocate(void *context)
{
    struct request *request=context;
    wendy_net_memory_scope_t scope=wendy_net_memory_scope_current();
    assert(scope.owner==request->expected && scope.placement==request->placement);
    request->buffer=wendy_net_memory_scoped_calloc(1,256);
    assert(request->buffer);
    memset(request->buffer,42,256);
    atomic_store(&request->complete,true);
}
static void *worker(void *unused)
{
    (void)unused;
    while(!atomic_load(&stopping)){
        if(!wendy_pki_work_poll())sched_yield();
        assert(!wendy_net_memory_scope_current().owner);
    }
    return NULL;
}
int main(void)
{
    wendy_net_memory_t mesh=WENDY_NET_MEMORY_INITIALIZER;
    assert(wendy_net_memory_open(&mesh,8192,true));
    wendy_pki_work_enable();
    pthread_t thread;assert(!pthread_create(&thread,NULL,worker,NULL));
    for(unsigned i=0;i<100;i++){
        struct request request={.expected=i%2 ? &mesh:NULL,
            .placement=i%2 ? WENDY_NET_MEMORY_EXTERNAL:WENDY_NET_MEMORY_INTERNAL};
        wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(request.expected,request.placement);
        while(!wendy_pki_work_submit(allocate,&request))sched_yield();
        wendy_net_memory_scope_leave(previous);
        while(!atomic_load(&request.complete))sched_yield();
        wendy_net_memory_snapshot_t state;wendy_net_memory_snapshot(&mesh,&state);
        assert(state.allocation_count==(request.expected ? 1:0));
        assert(((unsigned char *)request.buffer)[255]==42);
        wendy_net_memory_scoped_free(request.buffer);
        assert(wendy_net_memory_drained(&mesh));
    }
    atomic_store(&stopping,true);assert(!pthread_join(thread,NULL));
    /* I/O provider is a different polling context with the same ownership rule. */
    struct request io={.expected=&mesh,.placement=WENDY_NET_MEMORY_EXTERNAL};
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&mesh,io.placement);
    assert(wendy_pki_io_work_submit(allocate,&io));
    wendy_net_memory_scope_leave(previous);
    assert(wendy_pki_io_work_poll() && atomic_load(&io.complete));
    assert(!wendy_net_memory_scope_current().owner);
    assert(!wendy_net_memory_drained(&mesh));
    wendy_net_memory_scoped_free(io.buffer);
    struct request synchronous={.expected=&mesh,.placement=WENDY_NET_MEMORY_INTERNAL};
    previous=wendy_net_memory_scope_enter(&mesh,synchronous.placement);
    assert(!wendy_pki_work_run(allocate,&synchronous));
    wendy_net_memory_scope_leave(previous);
    assert(atomic_load(&synchronous.complete));
    wendy_net_memory_scoped_free(synchronous.buffer);
    assert(wendy_net_memory_drained(&mesh));
    wendy_net_memory_close(&mesh);
    return 0;
}
