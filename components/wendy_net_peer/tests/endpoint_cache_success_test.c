/* Ordinary verified endpoint turnover, independent of retained keys/blobs. */
#include "wendy_net_directory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct wne_entry *find(struct wne_cache *c,unsigned id)
{for(struct wne_entry *e=c->entries;e;e=e->next)if(e->device[15]==id)return e;return NULL;}
int main(void)
{
    struct wne_cache c={0};struct wnd_manifest m={.revision=1,.tls_app_port=43022,.agent_port=5054,.agent_mtls=true};
    uint8_t hash[32]={1};uint16_t port=0;
    assert(!c.entries && !c.count);
    for(unsigned i=1;i<=64;i++){
        m.device[15]=(uint8_t)i;
        assert(!wne_update(&c,&m,hash,10000,1));assert(c.count==i);
    }
    struct wne_entry *entry=find(&c,32);assert(entry);
    m.device[15]=32;m.revision=2;m.tls_app_port=44000;hash[0]=2;
    assert(!wne_update(&c,&m,hash,12000,2));assert(find(&c,32)==entry && c.count==64);
    assert(wne_endpoint(&c,m.device,false,3,&port) && port==44000);
    assert(wne_endpoint(&c,m.device,true,3,&port) && port==5054);
    /* A duplicate must not extend the signed projection's existing lease. */
    assert(!wne_update(&c,&m,hash,20000,3) && entry->deadline_us==12000);
    m.revision=3;m.withdraw=true;hash[0]=3;
    assert(!wne_update(&c,&m,hash,13000,4));assert(find(&c,32)==entry);
    assert(!wne_endpoint(&c,m.device,false,5,&port));
    m.device[15]=65;m.revision=1;m.withdraw=false;hash[0]=1;
    struct wne_entry *old=find(&c,1);assert(old);
    assert(!wne_update(&c,&m,hash,14000,5));assert(c.count==64 && !find(&c,1) && find(&c,65)==old);
    /* Reap on update, including still-unexpired withdrawals only when due. */
    m.device[15]=66;assert(!wne_update(&c,&m,hash,16000,11000));assert(c.count==3 && !find(&c,2));
    assert(find(&c,32)==entry);
    wne_reap(&c,13000);assert(c.count==2 && !find(&c,32));
    wne_reap(&c,16000);assert(!c.entries && !c.count);
    m.device[15]=1;assert(!wne_update(&c,&m,hash,20000,17000));wne_clear(&c);
    assert(!c.entries && !c.count);
    printf("Dynamic endpoint cache:64 cap, in-place update, FIFO reuse, lease reaping; entry=%zu bytes\n",sizeof(struct wne_entry));
}
