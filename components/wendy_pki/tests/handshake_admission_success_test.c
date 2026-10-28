/* Normal PSRAM retained-context policy, independent from serialized CPU jobs. */
#include "wendy_pki_work.h"
#include "wendy_net_alloc.h"
#include "wendy_net_actor.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct lane {struct wna_session state;struct wna_channel channel;int result;void *input;unsigned jobs;};
static unsigned active_cpu,max_cpu;
static void prepare(void *context)
{
    struct lane *l=context;assert(wendy_pki_work_is_current());
    active_cpu++;if(active_cpu>max_cpu)max_cpu=active_cpu;assert(active_cpu==1);
    if(l->state.phase==WNA_PREPARE){l->input=wendy_net_memory_scoped_calloc(1,26624);assert(l->input);l->result=0;}
    else l->result=l->channel.input.size ? 0:-2;
    l->jobs++;active_cpu--;
}
static void submit(struct lane *l)
{assert(wendy_pki_work_submit(prepare,l));wna_lend(&l->state);}
static void collect(struct lane *l)
{assert(wendy_pki_work_poll());wna_completed(&l->state,l->result);}
int main(void)
{
    wendy_net_memory_t *memory=wendy_net_runtime_memory_ledger();
    assert(wendy_net_memory_open(memory,2*1024*1024,true));
    wendy_pki_work_enable();assert(wendy_pki_handshake_mesh_limit()==2);
    wendy_net_memory_scope_t baseline=wendy_net_runtime_scope_enter();
    struct lane a={.state={.phase=WNA_PREPARE,.deadline=1000000}},b=a,c=a;
    assert(wendy_pki_handshake_claim(&a) && wendy_pki_handshake_claim(&a));
    assert(wendy_pki_handshake_claim(&b));assert(!wendy_pki_handshake_claim(&c));
    assert(!wendy_pki_handshake_available() && wendy_pki_handshake_busy());
    submit(&a);assert(!wendy_pki_work_submit(prepare,&b));collect(&a);
    submit(&b);collect(&b);
    assert(a.input!=b.input && a.jobs==1 && b.jobs==1 && max_cpu==1);
    wendy_net_memory_snapshot_t retained;wendy_net_memory_snapshot(memory,&retained);
    assert(retained.external_bytes>=2*26624 && retained.internal_bytes==0);
    /* Both independent contexts wait for network input while unrelated
     * established/control BIO bytes continue at actor priority. */
    submit(&a);collect(&a);submit(&b);collect(&b);
    assert(wna_next(&a.state,1,false,true)==WNA_IO_READ && wna_next(&b.state,1,false,true)==WNA_IO_READ);
    struct wna_channel established={0};const char control[]="HAVE/WANT";
    assert(wna_write(&established,control,sizeof control)==sizeof control);
    assert(established.output.size==sizeof control && !memcmp(established.output.bytes,control,sizeof control));
    /* Actual physical admission is available despite two live mesh owners.
     * Transfer preserves its reserved slot and stale releases cannot unlock it. */
    wendy_net_memory_scope_leave(baseline);
    assert(wendy_pki_handshake_available());char physical_cookie,physical_tls;
    assert(wendy_pki_handshake_claim(&physical_cookie));
    assert(wendy_pki_handshake_transfer(&physical_cookie,&physical_tls));
    wendy_pki_handshake_release(&physical_cookie);assert(!wendy_pki_handshake_available());
    baseline=wendy_net_runtime_scope_enter();assert(!wendy_pki_handshake_available());
    /* An ordinary completed peer releases only itself. */
    a.channel.input.size=1;submit(&a);collect(&a);assert(a.state.phase==WNA_READY);
    wendy_pki_handshake_release(&a);assert(wendy_pki_handshake_claim(&c));
    wendy_pki_handshake_release(&a);assert(!wendy_pki_handshake_available());
    /* OFF waits for an actual loan completion before retiring its context. */
    submit(&b);b.state.cancel=true;wendy_net_memory_close(memory);
    assert(b.state.lent && !wendy_net_memory_drained(memory));collect(&b);
    assert(wna_next(&b.state,2,false,true)==WNA_CLOSE);
    wendy_net_memory_scoped_free(a.input);wendy_net_memory_scoped_free(b.input);
    wendy_pki_handshake_release(&b);wendy_pki_handshake_release(&c);
    assert(wendy_pki_handshake_busy());wendy_net_memory_scope_leave(baseline);
    wendy_pki_handshake_release(&physical_tls);
    assert(!wendy_pki_handshake_busy() && wendy_net_memory_drained(memory));
    /* The same implementation retains the existing one-slot SRAM policy. */
    assert(wendy_net_memory_open(memory,1024*1024,false));assert(wendy_pki_handshake_mesh_limit()==1);
    baseline=wendy_net_runtime_scope_enter();assert(wendy_pki_handshake_claim(&a));
    assert(!wendy_pki_handshake_claim(&b));wendy_net_memory_scope_leave(baseline);
    assert(!wendy_pki_handshake_available());wendy_pki_handshake_release(&a);
    assert(wendy_pki_handshake_available() && wendy_pki_handshake_claim(&physical_tls));
    wendy_pki_handshake_release(&physical_tls);wendy_net_memory_close(memory);
    assert(!wendy_pki_handshake_busy() && wendy_net_memory_drained(memory));
    printf("PSRAM:2 independent context/BIO admissions + reserved physical, serialized CPU max=%u; SRAM1 and OFF drain PASS; retained input charge=%zu\n",max_cpu,retained.current_bytes);
    return 0;
}
