#include "wendy_net_actor.h"
#include <string.h>
#include <assert.h>
size_t wna_buffer_space(struct wna_buffer *b)
{
    if(b->offset && b->size){memmove(b->bytes,b->bytes+b->offset,b->size);b->offset=0;}
    if(!b->size)b->offset=0;
    return sizeof b->bytes-b->size;
}
void wna_buffer_consume(struct wna_buffer *b,size_t n)
{assert(n<=b->size);b->offset+=n;b->size-=n;if(!b->size)b->offset=0;}
ssize_t wna_read(void *context,void *bytes,size_t count)
{
    struct wna_channel *c=context;
    if(c->failed)return -1;
    if(!c->input.size)return c->eof ? 0:-2;
    if(count>c->input.size)count=c->input.size;
    memcpy(bytes,c->input.bytes+c->input.offset,count);wna_buffer_consume(&c->input,count);return (ssize_t)count;
}
ssize_t wna_write(void *context,const void *bytes,size_t count)
{
    struct wna_channel *c=context;
    if(c->failed || c->eof)return -1;
    size_t room=wna_buffer_space(&c->output);if(!room)return -3;
    if(count>room)count=room;
    memcpy(c->output.bytes+c->output.size,bytes,count);c->output.size+=count;return (ssize_t)count;
}
enum wna_effect wna_next(struct wna_session *s,uint64_t now,bool input,bool output_space)
{
    if(s->lent)return WNA_NONE;
    if(s->cancel || now>=s->deadline || s->phase==WNA_FAILED){s->phase=WNA_CLOSED;return WNA_CLOSE;}
    if(now<s->retry_at)return WNA_NONE;
    if(s->phase==WNA_PREPARE)return WNA_CRYPTO_PREPARE;
    if(s->phase!=WNA_HANDSHAKE)return WNA_NONE;
    if(s->need==-2 && !input)return WNA_IO_READ;
    if(s->need==-3 && !output_space)return WNA_IO_WRITE;
    return WNA_CRYPTO_STEP;
}
void wna_lend(struct wna_session *s)
{assert(!s->lent && (s->phase==WNA_PREPARE || s->phase==WNA_HANDSHAKE));s->lent=true;}
void wna_completed(struct wna_session *s,int result)
{
    assert(s->lent);s->lent=false;s->need=result;
    if(result==-1)s->phase=WNA_FAILED;
    else if(s->phase==WNA_PREPARE){if(!result)s->phase=WNA_HANDSHAKE;}
    else if(!result)s->phase=WNA_READY;
}
bool wna_yield_guest_setup(struct wna_session *s,bool constrained,bool outbound,
                          bool established,bool owns_workspace)
{
    if(!constrained || !outbound || established || !owns_workspace || s->cancel ||
       (s->phase!=WNA_PREPARE && s->phase!=WNA_HANDSHAKE))return false;
    s->cancel=true;return true;
}
