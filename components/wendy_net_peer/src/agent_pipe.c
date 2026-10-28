#include "agent_pipe.h"
#include <assert.h>
#include <string.h>
void wnap_init(struct wnap_ring *ring,uint8_t *bytes,unsigned capacity)
{
    assert(ring && bytes && capacity && capacity<=65535);
    ring->bytes=bytes;ring->capacity=capacity;
    atomic_init(&ring->produced,0);atomic_init(&ring->consumed,0);
}
size_t wnap_available(const struct wnap_ring *ring)
{
    unsigned consumed=atomic_load_explicit(&ring->consumed,memory_order_relaxed);
    unsigned produced=atomic_load_explicit(&ring->produced,memory_order_acquire);
    return (produced+ring->capacity+1-consumed)%(ring->capacity+1);
}
size_t wnap_space(const struct wnap_ring *ring)
{
    unsigned produced=atomic_load_explicit(&ring->produced,memory_order_relaxed);
    unsigned consumed=atomic_load_explicit(&ring->consumed,memory_order_acquire);
    return ring->capacity-(produced+ring->capacity+1-consumed)%(ring->capacity+1);
}
size_t wnap_read_span(struct wnap_ring *ring,const uint8_t **bytes)
{
    size_t count=wnap_available(ring);unsigned at=atomic_load_explicit(&ring->consumed,memory_order_relaxed);
    if(count>ring->capacity+1-at)count=ring->capacity+1-at;
    *bytes=ring->bytes+at;return count;
}
size_t wnap_write_span(struct wnap_ring *ring,uint8_t **bytes)
{
    size_t count=wnap_space(ring);unsigned at=atomic_load_explicit(&ring->produced,memory_order_relaxed);
    if(count>ring->capacity+1-at)count=ring->capacity+1-at;
    *bytes=ring->bytes+at;return count;
}
void wnap_consume(struct wnap_ring *ring,size_t count)
{
    assert(count<=wnap_available(ring));
    unsigned at=atomic_load_explicit(&ring->consumed,memory_order_relaxed);
    atomic_store_explicit(&ring->consumed,(at+(unsigned)count)%(ring->capacity+1),memory_order_release);
}
void wnap_produce(struct wnap_ring *ring,size_t count)
{
    assert(count<=wnap_space(ring));
    unsigned at=atomic_load_explicit(&ring->produced,memory_order_relaxed);
    atomic_store_explicit(&ring->produced,(at+(unsigned)count)%(ring->capacity+1),memory_order_release);
}
size_t wnap_read(struct wnap_ring *ring,void *bytes,size_t size)
{
    size_t used=0;
    while(used<size){const uint8_t *span;size_t count=wnap_read_span(ring,&span);
        if(!count)break;
        if(count>size-used)count=size-used;
        memcpy((uint8_t *)bytes+used,span,count);wnap_consume(ring,count);used+=count;}
    return used;
}
size_t wnap_write(struct wnap_ring *ring,const void *bytes,size_t size)
{
    size_t used=0;
    while(used<size){uint8_t *span;size_t count=wnap_write_span(ring,&span);
        if(!count)break;
        if(count>size-used)count=size-used;
        memcpy(span,(const uint8_t *)bytes+used,count);wnap_produce(ring,count);used+=count;}
    return used;
}
