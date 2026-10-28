/* Ordinary delayed completion across OFF: its observed fd must stay live
 * until it publishes, while subsequent producers observe the detached state. */
#include "wake_lifetime.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

struct fixture {
    struct wnad_wake_lifetime wake;
    atomic_bool borrowed,proceed;
};
static void *publish(void *context)
{
    struct fixture *f=context;
    int fd=wnad_wake_borrow(&f->wake);
    assert(fd>=0);
    atomic_store(&f->borrowed,true);
    while(!atomic_load(&f->proceed))sched_yield();
    const uint8_t byte=42;
    assert(write(fd,&byte,1)==1);
    wnad_wake_return(&f->wake);
    return NULL;
}
int main(void)
{
    int pipefd[2];assert(pipe(pipefd)==0);
    struct fixture f={.wake={.descriptor=pipefd[1]}};
    pthread_t thread;assert(!pthread_create(&thread,NULL,publish,&f));
    while(!atomic_load(&f.borrowed))sched_yield();
    int retired=wnad_wake_detach(&f.wake);
    assert(retired==pipefd[1]);
    assert(!wnad_wake_drained(&f.wake));
    /* A normal late producer cannot obtain the retiring descriptor. */
    assert(wnad_wake_borrow(&f.wake)==-1);
    wnad_wake_return(&f.wake);
    assert(!wnad_wake_drained(&f.wake));
    atomic_store(&f.proceed,true);
    assert(!pthread_join(thread,NULL));
    assert(wnad_wake_drained(&f.wake));
    assert(close(retired)==0);
    uint8_t byte=0;assert(read(pipefd[0],&byte,1)==1 && byte==42);
    assert(read(pipefd[0],&byte,1)==0);assert(!close(pipefd[0]));
    /* A restarted owner is independent of the old completion. */
    assert(!pipe(pipefd));atomic_store(&f.wake.descriptor,pipefd[1]);
    int fd=wnad_wake_borrow(&f.wake);assert(fd==pipefd[1]);
    byte=7;assert(write(fd,&byte,1)==1);wnad_wake_return(&f.wake);
    assert(wnad_wake_detach(&f.wake)==pipefd[1]);assert(wnad_wake_drained(&f.wake));
    assert(!close(pipefd[1]));assert(read(pipefd[0],&byte,1)==1 && byte==7);
    assert(!close(pipefd[0]));puts("wake lifetime positive PASS");
    return 0;
}
