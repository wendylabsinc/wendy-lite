/* A normal 64-origin startup inventory through one available send slot/pass. */
#define main shared_router_fixture_main
#include "router_node_success_test.c"
#undef main
struct inventory_observer {unsigned slots,seen[67];};
static int inventory_send(void *context,const void *wire,size_t size,bool control)
{
    struct inventory_observer *o=context;assert(control);
    if(!o->slots)return WNC_LIMIT;
    struct wg_message message;uint8_t data[WG_CHUNK];
    assert(!wn_gossip_read(wire,size,&message,data) && message.op==WG_HAVE && message.id.type==1);
    assert(message.id.hash[0]<67);o->seen[message.id.hash[0]]++;o->slots--;return 0;
}
int main(void)
{
    struct wnrs_node node={.own_cached=true,.own_artifact={.type=1}};
    struct inventory_observer seen={0};struct wnrs session={.node=&node,.send=inventory_send,.context=&seen};
    for(unsigned id=1;id<=64;id++){
        struct wnd_entry *entry=calloc(1,sizeof *entry);assert(entry);
        entry->device[15]=(uint8_t)id;entry->gossip_hash[0]=(uint8_t)id;entry->gossip_cached=true;
        entry->next=node.core.directory.entries;node.core.directory.entries=entry;
    }
    queue_inventory(&session);unsigned passes=0;
    while(session.need_inventory){assert(++passes<=66);seen.slots=1;assert(inventory(&session)>=0);}
    for(unsigned id=0;id<=64;id++)assert(seen.seen[id]==1);
    /* A lower UUID changes while a sweep is paused. Finish the current tail
     * before replaying once, so continual additions cannot reset progress. */
    queue_inventory(&session);passes=0;
    while(session.need_inventory){
        assert(++passes<=132);seen.slots=1;assert(inventory(&session)>=0);
        if(passes==32){
            struct wnd_entry *first=node.core.directory.entries;while(first->device[15]!=1)first=first->next;
            first->gossip_hash[0]=65;queue_inventory(&session);
        }
        if(passes==66)assert(seen.seen[64]>=2);
    }
    assert(seen.seen[65]==1 && seen.seen[64]==3);
    wnd_deinit(&node.core.directory);
    puts("64-origin backpressured inventory resumes fairly; later low-UUID update receives another sweep PASS");
}
