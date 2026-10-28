/* Normal caller timeout/completion ordering, using the production mailbox. */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/topology_query.h"
static unsigned live,freed;
static void release(void *p){assert(live);live--;freed++;free(p);}
static struct topology_query *create(void){struct topology_query *q=calloc(1,sizeof *q);assert(q);atomic_init(&q->references,2);live++;return q;}
int main(void){
 struct topology_query *mailbox=NULL;
 /* OFF has no actor/mailbox and owns no heap. */
 assert(!wnqt_take(&mailbox) && !live);
 struct topology_query *q=create();mailbox=q;
 /* A timeout before actor pickup removes its lease immediately. */
 wnqt_cancel(&mailbox,q,release);assert(!mailbox && live==1);
 wnqt_release(q,release);assert(!live && freed==1);
 /* Caller cancellation after actor pickup cannot release the actor's DTO. */
 q=create();mailbox=q;assert(wnqt_take(&mailbox)==q);
 wnqt_cancel(&mailbox,q,release);wnqt_release(q,release);assert(live==1);
 q->page.generation=42;wnqt_finish(&mailbox,q,0,release);assert(!mailbox && !live && freed==2);
 /* Normal completion retains only the caller lease until it copies out. */
 q=create();mailbox=q;assert(wnqt_take(&mailbox)==q);
 q->page.generation=43;wnqt_finish(&mailbox,q,0,release);
 assert(!mailbox && q->complete && !q->result && q->page.generation==43 && live==1);
 wnqt_release(q,release);assert(!live && freed==3);
 printf("PASS bounded topology mailbox: query=%zu, timeout/cancel/complete release all leases\n",sizeof *q);
 return 0;
}
