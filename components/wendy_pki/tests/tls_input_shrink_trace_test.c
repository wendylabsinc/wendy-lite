/* Matched positive TLS input-allocation trace. No allocation is rejected or
 * resized by this observer; the production optional policy does all work. */
#include "wendy_pki_internal.h"
#include <assert.h>
#include <stdio.h>
struct input_block {void *pointer;size_t size;};
static struct input_block blocks[16];
static size_t live_input,peak_input,first_idle_peak,intermediate_bytes,wrap_peak;
static unsigned intermediate,small,wrap_calls;
static bool wrap_phase,read_phase,close_phase;
static wendy_pki_connection *observed;
static void *trace_calloc(size_t count,size_t bytes)
{
    void *p=wendy_net_memory_scoped_calloc(count,bytes);size_t size=count*bytes;
    bool input=size==26624 || ((wrap_phase || close_phase || read_phase) && size>=2048 && size<=65536);
    if(p && input){
        unsigned i=0;while(i<16 && blocks[i].pointer)i++;assert(i<16);
        blocks[i]=(struct input_block){p,size};live_input+=size;if(live_input>peak_input)peak_input=live_input;
        if((wrap_phase || close_phase) && size>16384 && size<26624){intermediate++;intermediate_bytes=size;}
        if(size==2048 && read_phase){
            if(!small){
                first_idle_peak=observed->ssl.MBEDTLS_PRIVATE(in_buf_len)+2048;
                for(unsigned j=0;j<16;j++)
                    if(blocks[j].size==26624 && blocks[j].pointer!=observed->ssl.MBEDTLS_PRIVATE(in_buf))first_idle_peak+=26624;
            }
            small++;
        }
    }
    return p;
}
static void trace_free(void *pointer)
{
    for(unsigned i=0;i<16;i++)if(pointer && blocks[i].pointer==pointer){live_input-=blocks[i].size;blocks[i]=(struct input_block){0};break;}
    wendy_net_memory_scoped_free(pointer);
}
static int trace_begin(const struct wendy_pki_stream *io,const char *tenant,const char *device,
    struct pki_tls_owned_identity *own,struct wendy_conf_span roots,wendy_pki_connection **out)
{
    int result=pki_tls_agent_begin(io,tenant,device,own,roots,out);
    if(!result){observed=*out;assert(observed->ssl.MBEDTLS_PRIVATE(in_buf_len)==26624);}
    return result;
}
static int trace_advance(wendy_pki_connection *c)
{
    assert(c==observed);wrap_phase=c->ssl.MBEDTLS_PRIVATE(state)==MBEDTLS_SSL_HANDSHAKE_WRAPUP;
    if(wrap_phase)wrap_calls++;
    int result=pki_tls_agent_advance(c);
    if(wrap_phase)wrap_peak=peak_input;
    wrap_phase=false;return result;
}
static ssize_t trace_read(void *context,void *data,size_t size)
{read_phase=context==observed;ssize_t n=wendy_pki_read(context,data,size);read_phase=false;return n;}
static void trace_close(wendy_pki_connection *c)
{close_phase=c && c==observed;wendy_pki_close(c);close_phase=false;if(c==observed)observed=NULL;}
#define pki_tls_agent_begin trace_begin
#define pki_tls_agent_advance trace_advance
#define wendy_pki_read trace_read
#define wendy_pki_close trace_close
#define main normal_tls_adapter_main
#include "tls_test.c"
#undef main
#undef pki_tls_agent_begin
#undef pki_tls_agent_advance
#undef wendy_pki_read
#undef wendy_pki_close
int main(int argc,char **argv)
{
    if(argc!=5 || strncmp(argv[4],"owned-lan-",10)){
        unsetenv("WENDY_TLS_DEFER_INPUT_SHRINK");unsetenv("WENDY_TLS_INPUT_WORKSPACE");return normal_tls_adapter_main(argc,argv);
    }
    assert(!mbedtls_platform_set_calloc_free(trace_calloc,trace_free));
    bool deferred=getenv("WENDY_TLS_DEFER_INPUT_SHRINK")!=NULL;
    int result=normal_tls_adapter_main(argc,argv);
    assert(!result && wrap_calls && !observed && !live_input);
    size_t initial_peak=small ? first_idle_peak:wrap_peak;
    if(deferred)assert(!intermediate && initial_peak<=26624+2048);
    else assert(intermediate && initial_peak>=26624+intermediate_bytes);
    if(!getenv("WENDY_TLS_CLOSE_WITHOUT_APP"))assert(small);
    fprintf(stderr,"input shrink: deferred=%u wrap=%u intermediate=%u small=%u normal_input=%zu wrap_first_idle_peak=%zu tracked_large_allocation_peak=%zu closed=1 PASS\n",
        deferred,wrap_calls,intermediate,small,intermediate_bytes,initial_peak,peak_input);
    return 0;
}
