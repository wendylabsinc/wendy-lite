/* SPDX-License-Identifier: Apache-2.0 */
#include "catalog_internal.h"
#include "wendy_net_alloc.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>
int wnsc_open(struct wnsc_node **out,const struct wnsc_config *config)
{
 *out=NULL;size_t bytes=config->catalog_bytes ? config->catalog_bytes:32768;
 size_t records=config->catalog_records ? config->catalog_records:64;
 if(bytes<4096 || bytes>512*1024 || !records || records>512)return -1;
 struct wnsc_node *node=wendy_net_calloc(1,sizeof *node);if(!node)return 1;
 node->config=*config;wns_store_init(&node->records,records,bytes);
 if(wn_uuid_parse(config->device,node->self) || wn_principal(config->tenant,config->device,node->principal)<0){wnsc_close(node);return -1;}
 *out=node;return 0;
}
void wnsc_close(struct wnsc_node *node){if(node){wns_store_clear(&node->records);wendy_net_free(node);}}
int wnsc_publish(struct wnsc_node *node,struct wns_record *record,const char *const *txt,int64_t wall,uint64_t now)
{
 (void)wall;(void)now;if(!node || !record)return -1;
 strcpy(record->mesh,"default");strcpy(record->principal,node->principal);memcpy(record->device,node->self,16);
 return wnsc_manifest_publish(node,record,txt);
}
size_t wnsc_memory(const struct wnsc_node *node){return node ? sizeof *node+node->records.bytes:0;}
bool wnsc_ready(const struct wnsc_node *node,const uint8_t device[16])
{
 return node && device && (!memcmp(node->self,device,16) || node->config.next_hop(node->config.context,device,0)!=0);
}
void wnsc_prune(struct wnsc_node *node,int64_t wall){if(node)wns_store_prune(&node->records,wall);}
void wnsc_browse_demand(struct wnsc_node *node,uint64_t now){(void)node;(void)now;}
int wnsc_browse(struct wnsc_node *node,const char *type,int64_t wall,char *out,size_t cap)
{
    if(!node || !type || !*type)return -1;
    struct wns_record *record=wendy_net_malloc(sizeof *record);if(!record)return -1;
    size_t required=1;unsigned count=0;
    if(out && cap)out[0]='[';
    for(const struct wns_entry *e=node->records.entries;e;e=e->next){
        if(!e->wire || e->withdraw || e->unavailable || e->expires<=wall || !wnsc_ready(node,e->device))continue;
        if(wnsc_entry_record(node,e,wall,record) ||
           record->gateway || strcmp(record->type,type))continue;
        char device[37],prefix[180];wn_uuid_format(e->device,device);
        int n=snprintf(prefix,sizeof prefix,"%s{\"device\":\"%s\",\"host\":\"device-%s.mesh.wendy.internal\",\"record\":",
            count ? ",":"",device,device);
        if(n<0 || (size_t)n>=sizeof prefix){wendy_net_free(record);return -1;}
        int json_size=wns_record_json(record,NULL,0);
        if(json_size<0){wendy_net_free(record);return -1;}
        size_t item=(size_t)n+(size_t)json_size+1;
        if(out && required<cap && item<cap-required){
            memcpy(out+required,prefix,(size_t)n);
            if(wns_record_json(record,out+required+(size_t)n,cap-required-(size_t)n)!=json_size){wendy_net_free(record);return -1;}
            out[required+(size_t)n+(size_t)json_size]='}';
        }
        required+=item;count++;
    }
    if(out && required+1<cap){out[required]=']';out[required+1]=0;}
    wendy_net_free(record);return required<INT32_MAX ? (int)(required+1):-1;
}

int wnsc_browse_endpoints(struct wnsc_node *node,const char *type,int64_t wall,char *out,size_t cap)
{
    if(!node || !type || !*type)return -1;
    size_t required=1;unsigned count=0;
    if(out && cap){out[0]='[';if(cap>1)out[1]=0;}
    for(const struct wns_entry *e=node->records.entries;e;e=e->next){
        if(!e->summary_verified || e->withdraw || e->unavailable || e->gateway ||
           e->expires<=wall || strcmp(wns_entry_type(e),type) || !wnsc_ready(node,e->device))continue;
        char device[37];wn_uuid_format(e->device,device);
        /* These identifiers/type have already passed their restricted ASCII
         * grammars; the summary introduces no new unescaped user text. */
        int n=snprintf(out && required<cap ? out+required:NULL,
            out && required<cap ? cap-required:0,
            "%s{\"device\":\"%s\",\"host\":\"device-%s.mesh.wendy.internal\","
            "\"appId\":\"%s\",\"serviceId\":\"%s\",\"type\":\"%s\",\"port\":%u,"
            "\"generation\":%llu,\"expires\":%lld,\"detailsAvailable\":%s}",
            count ? ",":"",device,device,e->key,wns_entry_service(e),wns_entry_type(e),
            (unsigned)e->port,(unsigned long long)e->generation,(long long)e->expires,e->wire ? "true":"false");
        if(n<0)return -1;
        required+=(size_t)n;count++;
    }
    if(out && required+1<cap){out[required]=']';out[required+1]=0;}
    return required<INT32_MAX ? (int)(required+1):-1;
}
