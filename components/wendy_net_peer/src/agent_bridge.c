#include "agent_bridge.h"
#include "wendy_net_alloc.h"
#include "actor_driver.h"
#include <stddef.h>
#include <stdatomic.h>
#include <assert.h>

struct wnab_bridge {
    atomic_uint references;
    atomic_bool closing,input_eof;
    struct wcom_operation add,close;
    struct wnab_bridge *com_next; /* Accessed only by the com application task. */
    int link;
    bool close_queued;
    atomic_uint barrier_token;
    void (*barrier_done)(uint32_t);
    enum wcom_link_permission permission;
    wendy_net_memory_scope_t scope;
    struct wnap_ring incoming,outgoing;
    uint8_t bytes[];
};
static atomic_uint live;
static struct wnab_bridge *com_links,*creating;
static void retain(struct wnab_bridge *b){atomic_fetch_add(&b->references,1);}
static void release(struct wnab_bridge *b)
{
    if(atomic_fetch_sub_explicit(&b->references,1,memory_order_acq_rel)!=1)return;
    /* The actor cannot retire its wake fd while any bridge is still live.
     * No wake or stale numeric fd use occurs after this final live decrement. */
    wnad_wake();
    wendy_net_free(b);
    atomic_fetch_sub_explicit(&live,1,memory_order_release);
}
static ssize_t read_plain(void *context,void *bytes,size_t size)
{
    struct wnab_bridge *b=context;
    if(atomic_load(&b->closing))return 0;
    size_t n=wnap_read(&b->incoming,bytes,size);
    if(n){wnad_wake();return (ssize_t)n;}
    return atomic_load(&b->input_eof) ? 0:WCOM_STREAM_ERR_WANT_READ;
}
static ssize_t write_plain(void *context,const void *bytes,size_t size)
{
    struct wnab_bridge *b=context;
    if(atomic_load(&b->closing))return WCOM_STREAM_ERR_UNKNOWN;
    size_t n=wnap_write(&b->outgoing,bytes,size);
    if(n){wnad_wake();return (ssize_t)n;}
    return WCOM_STREAM_ERR_WANT_WRITE;
}
static int wake_fd(void *context){(void)context;return wcom_core_wakeup_fd();}
static bool can_read(void *context)
{
    struct wnab_bridge *b=context;
    return atomic_load(&b->closing) || atomic_load(&b->input_eof) || wnap_available(&b->incoming);
}
static bool can_write(void *context)
{
    struct wnab_bridge *b=context;
    return !atomic_load(&b->closing) && wnap_space(&b->outgoing);
}
static void *allocate_buffer(void *context,size_t size)
{
    struct wnab_bridge *b=context;
    if(atomic_load(&b->closing))return NULL;
    wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(b->scope.owner,b->scope.placement);
    void *buffer=wendy_net_memory_scoped_calloc(1,size);
    wendy_net_memory_scope_leave(previous);return buffer;
}
static void free_buffer(void *context,void *buffer)
{(void)context;wendy_net_memory_scoped_free(buffer);}
static void reply_barrier(void *context,uint32_t token,void (*done)(uint32_t))
{
    struct wnab_bridge *b=context;
    /* One settings change globally may await a receipt. The release publishes
     * the immutable callback before the actor sees its token. */
    assert(!atomic_load(&b->barrier_token));
    b->barrier_done=done;
    atomic_store_explicit(&b->barrier_token,token,memory_order_release);wnad_wake();
}
void wnab_output_drained(struct wnab_bridge *b)
{
    uint32_t token=atomic_load_explicit(&b->barrier_token,memory_order_acquire);
    if(token){
        void (*done)(uint32_t)=b->barrier_done;
        atomic_store_explicit(&b->barrier_token,0,memory_order_release);done(token);
    }
}
static const struct wcom_stream_ops operations={.read=read_plain,.write=write_plain,
    .wakeup_fd=wake_fd,.can_read=can_read,.can_write=can_write,
    .allocate_buffer=allocate_buffer,.free_buffer=free_buffer,.reply_barrier=reply_barrier};
static void interrupted(int link,enum wcom_interruption_reason reason)
{
    (void)reason;
    struct wnab_bridge **at=&com_links;
    while(*at && (*at)->link!=link && !(*at==creating && (*at)->link<0))at=&(*at)->com_next;
    if(!*at)return;
    struct wnab_bridge *b=*at;*at=b->com_next;
    /* UNDEFINED handlers release the captured allocator before this link lease
     * is dropped. The actor's separate lease covers pending TLS output. */
    wcom_remove_link(link);b->link=-1;atomic_store(&b->closing,true);
    wnad_wake();release(b);
}
static void add_link(struct wcom_operation *operation)
{
    struct wnab_bridge *b=(void *)((char *)operation-offsetof(struct wnab_bridge,add));
    if(!atomic_load(&b->closing)){
        retain(b); /* Persistent com link lease, before CONNECTED handlers run. */
        b->com_next=com_links;com_links=b;creating=b;
        int link=wcom_add_routed_stream_link_with_permission(&operations,b,interrupted,b->permission);
        creating=NULL;
        if(link<0){
            com_links=b->com_next;atomic_store(&b->closing,true);release(b);
        }else if(!atomic_load(&b->closing))b->link=link;
        /* A CONNECTED handler may close synchronously (ordinary admission or
         * protocol-buffer failure). interrupted() already removed that lease. */
    }
    wnad_wake();release(b); /* Queued add operation lease. */
}
static void close_link(struct wcom_operation *operation)
{
    struct wnab_bridge *b=(void *)((char *)operation-offsetof(struct wnab_bridge,close));
    if(b->link>=0)wcom_close(b->link); /* interruption releases the link lease */
    release(b); /* Queued close operation lease. */
}
struct wnab_bridge *wnab_open(enum wcom_link_permission permission,unsigned capacity)
{
    if(!capacity || capacity>65535 || wcom_core_wakeup_fd()<0 ||
       (permission!=WCOM_LINK_PERMISSION_FULL && permission!=WCOM_LINK_PERMISSION_SENSOR_ONLY))return NULL;
    struct wnab_bridge *b=wendy_net_calloc(1,sizeof *b+2*((size_t)capacity+1));
    if(!b)return NULL;
    atomic_init(&b->references,2); /* Actor + queued add operation. */
    atomic_init(&b->closing,false);atomic_init(&b->input_eof,false);atomic_init(&b->barrier_token,0);
    b->link=-1;b->permission=permission;b->scope=wendy_net_memory_scope_current();
    wnap_init(&b->incoming,b->bytes,capacity);
    wnap_init(&b->outgoing,b->bytes+capacity+1,capacity);
    b->add.func=add_link;b->close.func=close_link;
    atomic_fetch_add(&live,1);wcom_core_exec(&b->add);return b;
}
struct wnap_ring *wnab_incoming(struct wnab_bridge *b){return &b->incoming;}
struct wnap_ring *wnab_outgoing(struct wnab_bridge *b){return &b->outgoing;}
void wnab_notify(struct wnab_bridge *b){(void)b;wcom_core_wake();}
void wnab_input_eof(struct wnab_bridge *b){atomic_store(&b->input_eof,true);wcom_core_wake();}
bool wnab_closed(struct wnab_bridge *b){return atomic_load(&b->closing);}
void wnab_close(struct wnab_bridge *b)
{
    if(b->close_queued)return;
    b->close_queued=true;atomic_store(&b->closing,true);
    retain(b);wcom_core_exec(&b->close);wcom_core_wake();
}
bool wnab_retired(struct wnab_bridge *b)
{
    return b->close_queued && atomic_load_explicit(&b->references,memory_order_acquire)==1;
}
void wnab_release(struct wnab_bridge *b)
{assert(wnab_retired(b));release(b);}
unsigned wnab_live(void){return atomic_load_explicit(&live,memory_order_acquire);}
