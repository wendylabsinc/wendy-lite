/* Ordinary job submission/completion and reuse, with a caller retaining its
 * request until the existing TLS worker completes it. No radio or PKI input. */
#include "wendy_pki_work.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>

struct request {unsigned value;atomic_bool complete;};
static atomic_bool stopping;
static void finish(void *context)
{
    struct request *request=context;
    request->value+=7;
    atomic_store(&request->complete,true);
}
static void *worker(void *unused)
{
    (void)unused;
    while(!atomic_load(&stopping)){
        if(!wendy_pki_work_poll())sched_yield();
    }
    return NULL;
}
int main(void)
{
    unsigned outgoing,native;
    assert(wendy_pki_handshake_claim(&outgoing));
    assert(wendy_pki_handshake_owned(&outgoing));
    assert(!wendy_pki_handshake_owned(&native));
    assert(!wendy_pki_handshake_claim(&native));
    wendy_pki_handshake_release(&outgoing);
    assert(!wendy_pki_handshake_owned(&outgoing));
    assert(wendy_pki_handshake_claim(&native));
    wendy_pki_handshake_release(&native);
    wendy_pki_work_enable();assert(wendy_pki_work_available());
    pthread_t thread;assert(!pthread_create(&thread,NULL,worker,NULL));
    for(unsigned i=0;i<1000;i++){
        struct request request={.value=i};
        while(!wendy_pki_work_submit(finish,&request))sched_yield();
        while(!atomic_load(&request.complete))sched_yield();
        assert(request.value==i+7);
    }
    atomic_store(&stopping,true);assert(!pthread_join(thread,NULL));
    return 0;
}
