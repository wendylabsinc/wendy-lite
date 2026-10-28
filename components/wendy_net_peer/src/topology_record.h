#pragma once
#include <stddef.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"

#define WNT_TOPOLOGY_PRINCIPAL_MAX 1024
#define WNT_TOPOLOGY_DEVICE 1
#define WNT_TOPOLOGY_OPERATOR 2

/* Actor-turn borrowed metadata. The principal is never retained by a scan;
 * only the one selected exported row gets an immutable charged copy. */
struct wnt_record_view {
    WendyComNetTopologyRecord record;
    const char *principal;
    size_t principal_size;
};
/* page starts empty. Success transfers one immutable selected row into it. */
int wnt_record_copy(WendyComNetTopologyPage *,const struct wnt_record_view *);
/* Safe after both synchronous encoding passes, or on query timeout/stop. */
void wnt_page_release(WendyComNetTopologyPage *);

struct wnrs_node;
/* Actor-only extension point for later typed operator authority. Category2
 * receives a route in view.record (including its exact IPv6 address/origin);
 * fill its owner only. Category3 selects the indexed live announcement.
 * Return1 row/owner,0 absent,-1 unavailable. Views borrow only this actor turn;
 * this hook never allocates. LUI's base implementation returns0. */
int wnrs_topology_operator_row(struct wnrs_node *,unsigned category,unsigned index,
    int64_t now,struct wnt_record_view *);
