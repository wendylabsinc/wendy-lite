#pragma once
#include <stdatomic.h>
#include "wendy_com_msg.pb.h"
#include "topology_record.h"
/* state_lock serializes the mailbox and fields; references alone protect the
 * allocation after a caller times out. There is never a caller-owned buffer. */
struct topology_query {
    atomic_uint references;
    bool processing,complete;
    int result;
    WendyComNetTopologyParams params;
    WendyComNetTopologyPage page;
};
static inline void wnqt_release(struct topology_query *q,void (*release)(void *))
{if(atomic_fetch_sub(&q->references,1)==1){wnt_page_release(&q->page);release(q);}}
static inline struct topology_query *wnqt_take(struct topology_query **mailbox)
{struct topology_query *q=*mailbox;if(q)q->processing=true;return q;}
static inline void wnqt_cancel(struct topology_query **mailbox,struct topology_query *q,void (*release)(void *))
{if(*mailbox==q && !q->processing){*mailbox=NULL;wnqt_release(q,release);}}
static inline void wnqt_finish(struct topology_query **mailbox,struct topology_query *q,int result,void (*release)(void *))
{if(*mailbox==q)*mailbox=NULL;q->result=result;q->complete=true;wnqt_release(q,release);}
/* Actor shutdown runs between projection turns, never beneath a borrowed view. */
static inline void wnqt_abort(struct topology_query **mailbox,void (*release)(void *))
{struct topology_query *q=*mailbox;if(q){*mailbox=NULL;q->result=-1;q->complete=true;wnqt_release(q,release);}}
