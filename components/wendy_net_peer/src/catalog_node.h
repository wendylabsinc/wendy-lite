/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_service_store.h"
struct wnsc_node;
struct wnsc_config {
 void *context;
 const char *tenant,*device;
 /* Derived browse metadata only. Full signed bytes use the router FIFO. */
 size_t catalog_bytes,catalog_records;
 void (*services_changed)(void *);
 int64_t (*expires)(void *);
 uint64_t (*next_hop)(void *,const uint8_t device[16],uint64_t exclude);
};
int wnsc_open(struct wnsc_node **,const struct wnsc_config *);
void wnsc_close(struct wnsc_node *);
int wnsc_publish(struct wnsc_node *,struct wns_record *,const char *const *,int64_t,uint64_t);
size_t wnsc_memory(const struct wnsc_node *);
void wnsc_prune(struct wnsc_node *,int64_t);
int wnsc_browse(struct wnsc_node *,const char *,int64_t,char *,size_t);
int wnsc_browse_endpoints(struct wnsc_node *,const char *,int64_t,char *,size_t);
#define WNS_GUEST_APP_ID "sh.wendy.lite.app"
typedef int (*wnsc_listener_owner)(void *,uint16_t,bool);
struct wnsc_registry;
int wnsc_guest_publish(struct wnsc_node *,const void *,size_t,wnsc_listener_owner,void *,int64_t,uint64_t);
int wnsc_guest_withdraw(struct wnsc_node *,const char *,int64_t,uint64_t);
int wnsc_guest_register(struct wnsc_registry **,const void *,size_t,wnsc_listener_owner,void *);
int wnsc_guest_tick(struct wnsc_registry **,struct wnsc_node *,wnsc_listener_owner,void *,int64_t,uint64_t);
int wnsc_guest_unregister(struct wnsc_registry **,struct wnsc_node *,const char *,int64_t,uint64_t);
void wnsc_guest_clear(struct wnsc_registry **);
bool wnsc_ready(const struct wnsc_node *,const uint8_t device[16]);
void wnsc_browse_demand(struct wnsc_node *,uint64_t);
int wnsc_services_write(const struct wnsc_node *,char *,size_t);
int wnsc_manifest_services(struct wnsc_node *,const struct wn_doc *,unsigned,const uint8_t[16],uint64_t,int64_t,int64_t,bool);
int wnsc_manifest_publish(struct wnsc_node *,struct wns_record *,const char *const *);
int wnsc_entry_record(const struct wnsc_node *,const struct wns_entry *,int64_t,struct wns_record *);
void wnsc_manifest_committed(struct wnsc_node *,uint64_t,int64_t,int64_t);
