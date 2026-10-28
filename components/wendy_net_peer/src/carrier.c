/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_net_carrier.h"
#include "wendy_net_alloc.h"
#include "wendy_net_peer_protocol.h"
#include <stdlib.h>
#include <string.h>

struct wnc_frame
{
    struct wnc_frame *next,*previous,*class_next;
    size_t size, offset;
    int64_t started, progress;
    bool begun,priority;
    uint8_t category;
    uint8_t data[];
};
_Static_assert(WNC_CLASS_RESERVE>=sizeof(struct wnc_frame)+5+WN_DATAGRAM_MAX,
    "routing reserve must admit a maximum datagram");
_Static_assert(WNC_CLASS_RESERVE>=WN_MTU+2*(sizeof(struct wnc_frame)+5+9),
    "IP reserve must admit one complete two-fragment packet");
#define CPROBE_ADD(c,key,n) ((void)0)
#define probe_enqueue(c,f,n) ((void)0)
#define probe_dequeue(c,f,n) ((void)0)
#define probe_start(c,f,n) ((void)0)
int wnc_init(struct wnc_carrier *c, const struct wnc_io *io, void *small,
             size_t size, size_t limit, size_t control_limit)
{
    if (!c || !io || !io->read || !io->write || !small ||
        size < WN_DATAGRAM_MAX || limit < 2048 || limit > 65536 ||
        !control_limit || control_limit > 65536)
        return WNC_INVALID;
    memset(c, 0, sizeof *c);
    c->io = *io;
    c->small = small;
    c->small_size = size;
    c->limit = limit;
    c->control_limit = control_limit;
    c->stall_timeout_us=INT64_C(5000000);
    c->frame_timeout_us=INT64_C(30000000);
    return 0;
}
int wnc_fair_scheduler(struct wnc_carrier *c,unsigned frames)
{
    if(!c || !c->io.write || c->head || c->queued || !frames || frames>32 ||
       c->limit<3U*WNC_CLASS_RESERVE)return WNC_INVALID;
    c->fair=true;c->routing_limit=frames;return 0;
}
/* All bookkeeping is actor-owned. The three class queues and one global
 * ownership chain make enqueue/selection/removal O(1); no payload moves. */
static void choose_frame(struct wnc_carrier *c)
{
    if(!c->fair || !c->head || c->head->begun)return;
    unsigned k=WNC_CLASSES;
    if(!c->last_routing && c->class_head[WNC_ROUTE])k=WNC_ROUTE;
    else if(!c->last_metadata && c->class_head[WNC_METADATA])k=WNC_METADATA;
    else if(c->class_head[WNC_IP])k=WNC_IP;
    else if(c->class_head[WNC_METADATA])k=WNC_METADATA;
    else if(c->class_head[WNC_ROUTE])k=WNC_ROUTE;
    if(k==WNC_CLASSES)return;
    struct wnc_frame *f=c->class_head[k];
    if(f==c->head)return;
    f->previous->next=f->next;
    if(f->next)f->next->previous=f->previous;else c->tail=f->previous;
    f->previous=NULL;f->next=c->head;c->head->previous=f;c->head=f;
}
static void class_drop(struct wnc_carrier *c,const struct wnc_frame *f,size_t bytes)
{
    if(!c->fair)return;
    unsigned k=f->category;c->class_bytes[k]-=bytes;c->class_frames[k]--;
}
static void reset_rx(struct wnc_carrier *c)
{
    if (c->body != c->small)
        wendy_net_free(c->body);
    c->body = NULL;
    c->body_have = c->body_size = c->header_have = 0;
    c->rx_started = c->rx_progress = 0;c->rx_paused=false;
}
void wnc_deinit(struct wnc_carrier *c)
{
    if (!c)
        return;
    while (c->head)
    {
        struct wnc_frame *next = c->head->next;
        wendy_net_free(c->head);
        c->head = next;
    }
    reset_rx(c);
    memset(c, 0, sizeof *c);
}
static int enqueue(struct wnc_carrier *c,const void *data,size_t size,
                   bool control,bool priority)
{
    if (!c || !c->io.write || !data || !size ||
        size > (control ? c->control_limit : WN_DATAGRAM_MAX))
        return WNC_INVALID;
    size_t prefix = control ? 9 : 5,
           allocation = sizeof(struct wnc_frame) + prefix + size;
    unsigned category=control ? WNC_METADATA:priority ? WNC_ROUTE:WNC_IP;
    size_t bound=c->limit;
    if(c->fair){
        if(category==WNC_ROUTE && c->class_frames[WNC_ROUTE]>=c->routing_limit)return WNC_LIMIT;
        size_t reserve=0;
        for(unsigned k=0;k<WNC_CLASSES;k++)
            if(k!=category && c->class_bytes[k]<WNC_CLASS_RESERVE)
                reserve+=WNC_CLASS_RESERVE-c->class_bytes[k];
        if(reserve>bound)return WNC_INVALID;
        bound-=reserve;
    }else if(!control && !priority){
        if(c->priority_reserve>bound)return WNC_INVALID;
        bound-=c->priority_reserve;
    }
    if (c->queued > bound || allocation > bound - c->queued)
        return WNC_LIMIT;
    struct wnc_frame *f = wendy_net_calloc(1, allocation);
    if (!f)
        return WNC_NOMEM;
    f->size = prefix + size;
    f->priority=priority;f->category=(uint8_t)category;
    f->data[0] = control ? 1 : 2;
    wn_put32(f->data + 1, (uint32_t)(size + (control ? 4 : 0)));
    if (control)
        wn_put32(f->data + 5, (uint32_t)size);
    memcpy(f->data + prefix, data, size);
    if(c->fair){
        f->previous=c->tail;
        if(c->tail)c->tail->next=f;else c->head=f;
        c->tail=f;
        if(c->class_tail[category])c->class_tail[category]->class_next=f;
        else c->class_head[category]=f;
        c->class_tail[category]=f;c->class_bytes[category]+=allocation;c->class_frames[category]++;
    }else if(priority){
        struct wnc_frame **at=&c->head;
        if(*at && (*at)->begun)at=&(*at)->next;
        while(*at && (*at)->priority)at=&(*at)->next;
        f->next=*at;*at=f;
        if(!f->next)c->tail=f;
    }else{
        if(c->tail)c->tail->next=f;else c->head=f;
        c->tail=f;
    }
    c->queued += allocation;probe_enqueue(c,f,allocation);
    return 0;
}
int wnc_enqueue(struct wnc_carrier *c,const void *data,size_t size,bool control)
{return enqueue(c,data,size,control,false);}
int wnc_enqueue_priority(struct wnc_carrier *c,const void *data,size_t size,bool control)
{return enqueue(c,data,size,control,true);}
int wnc_enqueue_packet(struct wnc_carrier *c, const void *packet, size_t size,
                       uint32_t id)
{
    if (!c || !packet || size < 40 || size > WN_MTU)
        return WNC_INVALID;
    struct wnc_frame *tail = c->tail;
    struct wnc_frame *class_tail=c->class_tail[WNC_IP];
    size_t queued = c->queued;
    uint8_t fragment[WN_DATAGRAM_MAX];
    int result = 0;
    for (size_t offset = 0; offset < size; offset += WN_DATAGRAM_MAX - 9)
    {
        size_t length = wn_fragment(fragment, packet, size, id, offset);
        result = length ? wnc_enqueue(c, fragment, length, false) : WNC_INVALID;
        if (result)
            break;
    }
    if (!result)
        return 0;
    struct wnc_frame *frame = tail ? tail->next : c->head;
    if(c->fair){
        c->class_tail[WNC_IP]=class_tail;
        if(class_tail)class_tail->class_next=NULL;else c->class_head[WNC_IP]=NULL;
    }
    if (tail)
        tail->next = NULL;
    else
        c->head = NULL;
    while (frame)
    {
        struct wnc_frame *next = frame->next;
        class_drop(c,frame,sizeof *frame+frame->size);
        probe_dequeue(c,frame,sizeof *frame+frame->size);
        wendy_net_free(frame);
        frame = next;
    }
    c->tail = tail;
    c->queued = queued;
    return result;
}
static bool expired(const struct wnc_carrier *c,int64_t now, int64_t started, int64_t progress)
{
    return now < progress || now < started ||
           now - progress >= c->stall_timeout_us ||
           now - started >= c->frame_timeout_us;
}
bool wnc_timeout_snapshot(const struct wnc_carrier *c,int64_t now,struct wnc_timeout *out)
{
    if(!c || !out)return false;
    const struct wnc_frame *f=c->head;
    if(f && f->begun && expired(c,now,f->started,f->progress)){
        *out=(struct wnc_timeout){true,f->offset,f->size,now-f->progress,now-f->started};return true;
    }
    if(c->header_have && expired(c,now,c->rx_started,c->rx_progress)){
        *out=(struct wnc_timeout){false,c->header_have+c->body_have,5+c->body_size,
            now-c->rx_progress,now-c->rx_started};return true;
    }
    return false;
}
static int pump_write(struct wnc_carrier *c, int64_t now)
{
    choose_frame(c);
    struct wnc_frame *f = c->head;
    if (!f)
        return 0;
    if (!f->begun)
    {
        f->begun = true;
        f->started = f->progress = now;probe_start(c,f,(unsigned)now);
    }
    if (expired(c,now, f->started, f->progress))
        return WNC_TIMEOUT;
    size_t left = f->size - f->offset;
    ssize_t n = c->io.write(c->io.context, f->data + f->offset, left);
    if (n == -2 || n == -3)
        return 0;
    if (n <= 0 || (size_t)n > left)
        return WNC_IO;
    CPROBE_ADD(c,tx_bytes,n);
    f->offset += (size_t)n;
    f->progress = now;
    if (f->offset == f->size)
    {
        c->head = f->next;
        if (!c->head)c->tail = NULL;
        else if(c->fair)c->head->previous=NULL;
        if(c->fair){
            unsigned k=f->category;
            c->class_head[k]=f->class_next;
            if(!c->class_head[k])c->class_tail[k]=NULL;
            class_drop(c,f,sizeof *f+f->size);
            c->last_routing=k==WNC_ROUTE;
            if(k!=WNC_ROUTE)c->last_metadata=k==WNC_METADATA;
        }
        c->queued -= sizeof *f + f->size;
        probe_dequeue(c,f,sizeof *f+f->size);CPROBE_ADD(c,tx_frames,1);
        wendy_net_free(f);
    }
    return 1;
}
static int deliver_frame(struct wnc_carrier *c,wnc_receive receive,void *ctx)
{
    bool control=c->header[0]==1;
    if(control && wn_get32(c->body)!=c->body_size-4)return WNC_INVALID;
    int r=receive(ctx,c->body+(control ? 4:0),c->body_size-(control ? 4:0),control);
    if(r>0){c->rx_paused=true;return 0;}
    if(r<0)return WNC_INVALID;
    CPROBE_ADD(c,rx_frames,1);reset_rx(c);return 1;
}
static int pump_read(struct wnc_carrier *c, int64_t now, wnc_receive receive,
                     void *ctx)
{
    if(c->rx_paused)return deliver_frame(c,receive,ctx);
    if (c->header_have && expired(c,now, c->rx_started, c->rx_progress))
        return WNC_TIMEOUT;
    uint8_t *out = c->header_have < 5 ? c->header + c->header_have
                                      : c->body + c->body_have;
    size_t left =
        c->header_have < 5 ? 5 - c->header_have : c->body_size - c->body_have;
    ssize_t n = c->io.read(c->io.context, out, left);
    if (n == -2 || n == -3)
        return 0;
    if (!n)
        return WNC_CLOSED;
    if (n < 0 || (size_t)n > left)
        return WNC_IO;
    CPROBE_ADD(c,rx_bytes,n);
    if (!c->header_have)
        c->rx_started = now;
    c->rx_progress = now;
    if (c->header_have < 5)
    {
        c->header_have += (unsigned)n;
        if (c->header_have == 5)
        {
            size_t size = wn_get32(c->header + 1);
            if ((c->header[0] == 1 &&
                 (size < 5 || size > c->control_limit + 4)) ||
                (c->header[0] == 2 && (!size || size > WN_DATAGRAM_MAX)) ||
                (c->header[0] != 1 && c->header[0] != 2))
                return WNC_INVALID;
            c->body_size = size;
            c->body = size <= c->small_size ? c->small : wendy_net_malloc(size);
            if (!c->body)
                return WNC_NOMEM;
        }
        return 1;
    }
    c->body_have += (size_t)n;
    if(c->body_have==c->body_size)return deliver_frame(c,receive,ctx);
    return 1;
}
int wnc_pump(struct wnc_carrier *c, int64_t now, wnc_receive receive, void *ctx)
{
    if (!c || !c->io.read || !c->io.write || !receive || now < 0)
        return WNC_INVALID;
    int written = pump_write(c, now);
    if (written < 0)
        return written;
    int read = pump_read(c, now, receive, ctx);
    return read < 0 ? read : (read || written);
}
