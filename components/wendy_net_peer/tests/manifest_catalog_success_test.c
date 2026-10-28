/* Normal complete-manifest service publication, replacement and guest browse. */
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned changes;
static void changed(void *context){(void)context;changes++;}
static uint64_t next_hop(void *context,const uint8_t device[16],uint64_t exclude)
{(void)context;(void)device;(void)exclude;return 1;}
static struct wnsc_node *open_node(const char *device)
{
    struct wnsc_config config={.tenant="11111111-1111-4111-8111-111111111111",.device=device,
        .services_changed=changed,.next_hop=next_hop};
    struct wnsc_node *node=NULL;assert(!wnsc_open(&node,&config));return node;
}
static char *body(struct wnsc_node *node,uint64_t revision,int64_t issued)
{
    int size=wnsc_services_write(node,NULL,0);assert(size>0);
    char *array=malloc((size_t)size+1);assert(array);
    assert(wnsc_services_write(node,array,(size_t)size+1)==size);
    struct wn_origin origin={.router_id=42,.seqno=7};
    int bytes=wn_manifest_services_write(node->self,&origin,revision,issued,issued+900000,
        5054,43022,"Test ESP",true,array,(size_t)size,NULL,0);assert(bytes>0);
    char *out=malloc((size_t)bytes+1);assert(out);
    assert(wn_manifest_services_write(node->self,&origin,revision,issued,issued+900000,
        5054,43022,"Test ESP",true,array,(size_t)size,out,(size_t)bytes+1)==bytes);
    free(array);return out;
}
static void import(struct wnsc_node *to,struct wnsc_node *from,const char *bytes,uint64_t revision,int64_t issued)
{
    /* Measure this manifest again; binary CBOR is not NUL-delimited text. */
    int size=wnsc_services_write(from,NULL,0);char *array=malloc((size_t)size+1);assert(array);
    assert(wnsc_services_write(from,array,(size_t)size+1)==size);
    struct wn_origin origin={42,7};
    int count=wn_manifest_services_write(from->self,&origin,revision,issued,issued+900000,
        5054,43022,"Test ESP",true,array,(size_t)size,NULL,0);free(array);
    struct wn_doc *doc=malloc(sizeof *doc);assert(doc);
    assert(!wn_doc_parse_array_view(doc,bytes,(size_t)count,WN_MANIFEST_BODY_MAX,"services"));
    assert(!wns_manifest_services_validate(doc,0));
    assert(!wnsc_manifest_services(to,doc,0,from->self,revision,issued,issued+900000,false));
    free(doc);
}
int main(void)
{
    struct wnsc_node *origin=open_node("22222222-2222-4222-8222-222222222222");
    struct wnsc_node *viewer=open_node("33333333-3333-4333-8333-333333333333");
    struct wns_record *r=calloc(1,sizeof *r);assert(r);
    strcpy(r->app,WNS_GUEST_APP_ID);strcpy(r->service,"temperature");
    strcpy(r->type,"_sensorlink._tcp");strcpy(r->instance,"Room");r->port=28080;
    r->issued=1700000000000;r->expires=r->issued+900000;
    const char *txt[]={"format=f32le","channel=42"};r->txt_count=2;
    assert(!wnsc_publish(origin,r,txt,r->issued,0));assert(changes==1);
    assert(!wnsc_publish(origin,r,txt,r->issued+30000,30000));assert(changes==1);
    strcpy(r->service,"humidity");r->port=28081;
    assert(!wnsc_publish(origin,r,txt,r->issued+60000,60000));assert(changes==2);
    char *wire=body(origin,7,r->issued);import(viewer,origin,wire,7,r->issued);free(wire);
    assert(viewer->records.count==2);
    wnsc_prune(origin,r->expires+1);
    for(struct wns_entry *own=origin->records.entries;own;own=own->next)assert(own->wire);
    for(struct wns_entry *e=viewer->records.entries;e;e=e->next){assert(e->generation==7 && e->expires==r->expires);}
    struct wns_record *projected=malloc(sizeof *projected);assert(projected);
    assert(!wnsc_entry_record(viewer,viewer->records.entries,r->issued,projected));
    assert(projected->issued==r->issued);free(projected);
    char browse[4096];int n=wnsc_browse(viewer,"_sensorlink._tcp",r->issued+1,browse,sizeof browse);
    assert(n>0 && (size_t)n<sizeof browse && strstr(browse,"Room") && strstr(browse,"format=f32le"));
    wnsc_prune(viewer,r->expires+1);assert(!viewer->records.count);
    r->withdraw=true;assert(!wnsc_publish(origin,r,NULL,r->issued+1,1));
    wire=body(origin,8,r->issued+1000);import(viewer,origin,wire,8,r->issued+1000);free(wire);
    assert(viewer->records.count==1);
    struct wns_entry *e=viewer->records.entries;
    assert(!strcmp(wns_entry_service(e),"temperature") && e->generation==8 && e->expires==r->expires+1000);
    free(r);wnsc_close(origin);wnsc_close(viewer);
    puts("complete manifest: two services, common lease, idempotent source, omission and guest browse PASS");return 0;
}
