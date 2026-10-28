/* Ordinary physical setup arriving during a mesh handshake. Admission must
 * precede the expensive preparation boundary and survive ownership transfer. */
#include "wendy_pki_native_prepare.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
static atomic_bool resetting;
static atomic_uint input_allocations,trust_snapshots;
static pthread_mutex_t identity=PTHREAD_MUTEX_INITIALIZER;
int64_t esp_timer_get_time(void)
{struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
bool wendy_pki_reset_in_progress(void){return atomic_load(&resetting);}
struct physical {char preparation,connection;atomic_bool started;bool admitted;};
static void *physical_prepare(void *context)
{
    struct physical *p=context;pthread_mutex_lock(&identity);atomic_store(&p->started,true);
    p->admitted=pki_native_prepare_with_identity(&p->preparation,&identity,esp_timer_get_time()+1000000);
    if(!p->admitted){pthread_mutex_unlock(&identity);return NULL;}
    /* This is the production orchestration's post-claim allocation boundary;
     * snapshot/input/key code cannot be entered while admission is pending. */
    atomic_fetch_add(&trust_snapshots,1);
    void *trust=wendy_net_memory_scoped_calloc(1,7456);assert(trust);
    atomic_fetch_add(&input_allocations,1);
    void *input=wendy_net_memory_scoped_calloc(1,26624);assert(input);
    assert(wendy_pki_handshake_transfer(&p->preparation,&p->connection));
    wendy_pki_handshake_release(&p->preparation);
    assert(wendy_pki_handshake_busy()); /* obsolete stack cookie cannot unlock c */
    char next;
    assert(!wendy_pki_handshake_claim(&next));
    wendy_net_memory_scoped_free(input);wendy_net_memory_scoped_free(trust);
    wendy_pki_handshake_release(&p->connection);
    assert(wendy_pki_handshake_claim(&next));
    wendy_pki_handshake_release(&p->connection);
    assert(wendy_pki_handshake_busy()); /* established old c cannot unlock next */
    wendy_pki_handshake_release(&next);pthread_mutex_unlock(&identity);return NULL;
}
static void worker_attempt(void *context)
{
    bool *ran=context;char owner;
    assert(wendy_pki_work_is_current());
    assert(!pki_native_prepare_claim(&owner,esp_timer_get_time()+1000000));
    pthread_mutex_lock(&identity);
    assert(!pki_native_prepare_with_identity(&owner,&identity,esp_timer_get_time()+1000000));
    pthread_mutex_unlock(&identity);*ran=true;
}
int main(void)
{
    assert(wendy_net_runtime_memory_open());
    wendy_net_memory_scope_t old=wendy_net_runtime_scope_enter();
    void *mesh_input=wendy_net_memory_scoped_calloc(1,26624);assert(mesh_input);
    wendy_net_memory_scope_leave(old);
    char mesh_owner;assert(wendy_pki_handshake_claim(&mesh_owner));
    struct physical physical={0};pthread_t thread;
    assert(!pthread_create(&thread,NULL,physical_prepare,&physical));
    while(!atomic_load(&physical.started))sched_yield();
    const struct timespec wait={.tv_nsec=20000000};nanosleep(&wait,NULL);
    assert(!atomic_load(&input_allocations) && !atomic_load(&trust_snapshots));
    /* The actor's pending PREPARE can acquire identity while physical waits. */
    assert(!pthread_mutex_trylock(&identity));
    wendy_pki_handshake_release(&mesh_owner);
    nanosleep(&wait,NULL); /* let physical encounter the held identity mutex */
    /* Simulate ordinary Cloud/identity work retaining this mutex and needing
     * workspace itself. Physical may only trylock, then must release its lease;
     * it cannot hold workspace while awaiting our identity lock. */
    int64_t claim_deadline=esp_timer_get_time()+1000000;
    while(!wendy_pki_handshake_claim(&mesh_owner) && esp_timer_get_time()<claim_deadline)pki_native_prepare_yield();
    assert(wendy_pki_handshake_claim(&mesh_owner));
    pthread_mutex_unlock(&identity);
    wendy_net_memory_snapshot_t before;wendy_net_runtime_memory_snapshot(&before);
    assert(before.current_bytes>=26624 && before.allocation_count==1);
    /* Mesh OFF can release its loan while this baseline caller remains queued.
     * The physical session never inherits a closed mesh allocation owner. */
    wendy_net_runtime_memory_close();wendy_net_memory_scoped_free(mesh_input);
    assert(wendy_net_runtime_memory_drained());wendy_pki_handshake_release(&mesh_owner);
    assert(!pthread_join(thread,NULL));assert(physical.admitted);
    assert(atomic_load(&input_allocations)==1 && atomic_load(&trust_snapshots)==1);
    assert(!wendy_pki_handshake_busy() && wendy_net_runtime_memory_drained());
    assert(wendy_pki_handshake_claim(&mesh_owner));physical=(struct physical){0};
    assert(!pthread_create(&thread,NULL,physical_prepare,&physical));
    while(!atomic_load(&physical.started))sched_yield();
    atomic_store(&resetting,true);
    assert(!pthread_join(thread,NULL));assert(!physical.admitted);
    assert(atomic_load(&input_allocations)==1 && atomic_load(&trust_snapshots)==1);
    assert(wendy_pki_handshake_busy());wendy_pki_handshake_release(&mesh_owner);atomic_store(&resetting,false);
    char expired;assert(!pki_native_prepare_claim(&expired,esp_timer_get_time()));
    bool ran=false;wendy_pki_work_enable();assert(wendy_pki_work_submit(worker_attempt,&ran));
    assert(wendy_pki_work_poll() && ran && !wendy_pki_work_is_current());
    assert(!wendy_pki_handshake_busy());
    puts("native physical preparation: no second input/snapshot before lease, transfer, lock ordering, reset, worker refusal and OFF drain PASS");
}
