#include "wendy_net_packet_queue.h"
#include "wendy_net_alloc.h"
#include "wendy_net_peer_protocol.h"
#include <stdlib.h>
#include <string.h>
struct wnpq_packet {struct wnpq_packet *next;size_t size;unsigned char bytes[];};
void wnpq_init(struct wnpq *q,size_t limit,void *(*allocate)(size_t),void (*release)(void *))
{*q=(struct wnpq){.limit=limit,.allocate=allocate ? allocate:wendy_net_malloc,.release=release ? release:wendy_net_free};}
int wnpq_push(struct wnpq *q,const void *bytes,size_t size)
{
    if(!bytes || size<40 || size>WN_MTU)return -1;
    if(q->count>=q->limit)return 1;
    struct wnpq_packet *p=q->allocate(sizeof *p+size);
    if(!p)return 1;
    p->next=NULL;p->size=size;memcpy(p->bytes,bytes,size);
    if(q->tail)q->tail->next=p;else q->head=p;
    q->tail=p;q->count++;return 0;
}
void *wnpq_front(struct wnpq *q,size_t *size)
{
    struct wnpq_packet *p=q->head;
    *size=p ? p->size:0;return p ? p->bytes:NULL;
}
void wnpq_drop(struct wnpq *q)
{
    struct wnpq_packet *p=q->head;if(!p)return;
    q->head=p->next;if(!q->head)q->tail=NULL;q->count--;
    q->release(p);
}
int wnpq_pop(struct wnpq *q,void *out,size_t *size)
{
    void *bytes=wnpq_front(q,size);if(!bytes)return 0;
    memcpy(out,bytes,*size);wnpq_drop(q);return 1;
}
void wnpq_reset(struct wnpq *q)
{
    while(q->head){struct wnpq_packet *p=q->head;q->head=p->next;q->release(p);}
    q->tail=NULL;q->count=0;
}
